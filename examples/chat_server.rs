// DISCLAIMER: THIS CODE WAS BUILT IN A RUSH TO TEST THE PROTOTYPE
// THIS DOES NOT REPRESENT THE QUALITY OF MY CODE OR THE EISENBAHN PROJECT

use std::{net::SocketAddr, time::Duration};

use ahash::HashMap;
use ed25519_dalek::SigningKey;
use eisenbahn::{
    common::{constants::Channel, socket::NetworkConditions},
    server::{
        auth::{AuthenticationResult, Authenticator, NoneAuthenticator},
        builder::{Received, ServerBuilder, ToSend},
        send_queue::SendError,
    },
};
use rand::{rngs::SmallRng, Rng, SeedableRng};

struct MockNoneAuthenticator;

impl NoneAuthenticator for MockNoneAuthenticator {
    fn authenticate(&mut self, player_name: &str) -> AuthenticationResult {
        AuthenticationResult::Success { payload: vec![] }
    }
}

struct TerribleNetworkConditions {
    rng: SmallRng,
}

impl TerribleNetworkConditions {
    fn new() -> Self {
        Self {
            rng: SmallRng::from_entropy(),
        }
    }
}

impl NetworkConditions for TerribleNetworkConditions {
    fn simulate_packet_loss(&mut self, _packet_size: usize) -> bool {
        // 4% packet loss
        self.rng.gen_bool(0.04)
        //false
    }

    fn simulate_packet_latency(&mut self, _packet_size: usize) -> std::time::Duration {
        // 80-120ms latency
        std::time::Duration::from_millis(self.rng.gen_range(80..120))
        //Duration::ZERO
    }
}

fn main() {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let server_address: SocketAddr = "0.0.0.0:44444".parse().unwrap();
    let server = ServerBuilder::new(
        server_address,
        Authenticator::None(Box::new(MockNoneAuthenticator)),
        signing_key,
        [0; 16],
    )
    .with_network_conditions(Box::new(TerribleNetworkConditions::new()))
    .run()
    .unwrap();

    let mut chatters = HashMap::default();

    'outer: loop {
        match server.blocking_recv().unwrap() {
            (addr, Received::Connected { player_name }) => {
                for (_addr, _) in chatters.iter() {
                    if *_addr == addr {
                        continue;
                    }
                    match server.send(
                        *_addr,
                        ToSend::Message {
                            channel: Channel::Reliable0,
                            data: format!("{} has joined the chat", player_name)
                                .as_bytes()
                                .to_vec(),
                        },
                    ) {
                        Ok(_) => {}
                        Err(SendError::ServerShutdown) => break 'outer,
                        _ => {}
                    }
                }
                chatters.insert(addr, player_name);
            }
            (addr, Received::Message { data }) => {
                let message = String::from_utf8(data.clone()).unwrap();
                for (_addr, _) in chatters.iter() {
                    if *_addr == addr {
                        continue;
                    }
                    match server.send(
                        *_addr,
                        ToSend::Message {
                            channel: Channel::Reliable0,
                            data: data.clone(),
                        },
                    ) {
                        Ok(_) => {}
                        Err(SendError::ServerShutdown) => break 'outer,
                        _ => {}
                    }
                }
                println!("{}: {}", chatters.get(&addr).unwrap(), message);
            }
            (addr, Received::Disconnected { reason, data }) => {
                println!(
                    "{} has disconnected, because: {:?}: {}",
                    chatters.get(&addr).unwrap(),
                    reason,
                    String::from_utf8(data).unwrap()
                );
                chatters.remove(&addr);
            }
        }
    }
}
