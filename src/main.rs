#![feature(slice_as_array)]

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::time::Duration;
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;

pub struct Block {
    data: Vec<u8>,
    nonce: Vec<u8>,
}

pub fn encrypt(data: &[u8], password: &str) -> Block {
    let hash = Sha256::digest(password.as_bytes());
    let password_byte = hash.as_array().unwrap();
    let key: &Key<Aes256Gcm> = password_byte.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted_data = match cipher.encrypt(&nonce, data) {
        Ok(encrypted) => Block {
            data: encrypted,
            nonce: nonce.to_vec(),
        },
        Err(_) => panic!("could not encrypt"),
    };

    encrypted_data
}

pub fn decrypt(encrypted_text: &Block, password: &str) -> Vec<u8> {
    let hash = Sha256::digest(password.as_bytes());
    let password_byte = hash.as_array().unwrap();
    let key: &Key<Aes256Gcm> = password_byte.into();
    let nonce = Nonce::from_slice(&encrypted_text.nonce);
    let cipher = Aes256Gcm::new(&key);

    cipher
        .decrypt(nonce, encrypted_text.data.as_slice())
        .unwrap_or_else(|_| {
            println!("Failed to decrypt");
            vec![]
        })
}

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
            Ok(MyBehaviour { gossipsub, mdns })
        })?
        .build();
    let mut stdin = io::BufReader::new(io::stdin()).lines();
    println!("Enter the topic you want to join:");
    let topic_name = stdin.next_line().await?.unwrap();
    let topic = gossipsub::IdentTopic::new(topic_name);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on("/ip6/::/udp/0/quic-v1".parse()?)?;

    println!("Enter the password to use for AES-GCM encryption:");
    let password = stdin.next_line().await?.unwrap();

    println!("Enter messages via STDIN and they will be sent to connected peers using Gossipsub");

    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                let encrypted_block = encrypt(line.as_bytes(), &password);

                let mut message = encrypted_block.nonce.clone();
                message.extend_from_slice(&encrypted_block.data);

                if let Err(e) = swarm
                    .behaviour_mut().gossipsub
                    .publish(topic.clone(), &*message) {
                    println!("Publish error: {e:?}");
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discovered a new peer: {peer_id}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => {
                    let (nonce, ciphertext) = message.data.split_at(12);
                    let encrypted_block = Block {
                        data: ciphertext.to_vec(),
                        nonce: nonce.to_vec(),
                    };

                    let plaintext = decrypt(&encrypted_block, &password);
                    if !plaintext.is_empty(){
                         println!(
                            "Got message: '{}' with id: {id} from peer: {peer_id}",
                            String::from_utf8_lossy(&plaintext),
                        );
                    }
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                _ => {}
            }
        }
    }
}
