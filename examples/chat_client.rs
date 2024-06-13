// DISCLAIMER: THIS CODE WAS BUILT IN A RUSH TO TEST THE PROTOTYPE
// THIS DOES NOT REPRESENT THE QUALITY OF MY CODE OR THE EISENBAHN PROJECT

use std::net::SocketAddr;

use clap::Parser;
use eisenbahn::{
    client::{builder::ClientBuilder, Received, ToSend},
    common::{constants::Channel, encryption::auth::AuthenticationNone, socket::NetworkConditions},
};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use text_io::read;

#[derive(Parser)]
struct Args {
    ip: SocketAddr,
    username: String,
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
        // 25% packet loss
        self.rng.gen_bool(0.25)
    }

    fn simulate_packet_latency(&mut self, _packet_size: usize) -> std::time::Duration {
        // 80-120ms latency
        std::time::Duration::from_millis(self.rng.gen_range(80..120))
    }
}

pub fn main() {
    let args = Args::parse();
    let client = ClientBuilder::new()
        .with_none_authentication(Some(AuthenticationNone::new(args.username)))
        .with_network_conditions(Box::new(TerribleNetworkConditions::new()))
        .connect(args.ip, None)
        .unwrap();

    // Receive messages in a separate thread, because stdin reading is blocking
    let _client = client.clone();
    std::thread::spawn(move || {
        let client = _client;
        loop {
            match client.blocking_recv() {
                Ok(Received::Message { data }) => {
                    let message = String::from_utf8(data).unwrap();
                    println!("{}", message);
                }
                Ok(Received::Disconnect { reason, data }) => {
                    let message = String::from_utf8(data).unwrap();
                    println!("Disconnected: {}, reason: {:?}", message, reason);
                    break;
                }
                Err(e) => {
                    println!("Failed to receive message: {:?}", e);
                    break;
                }
            }
        }
        std::process::exit(0);
    });

    // We do a polling approach here, but for a chat application, it's better to use a blocking approach
    loop {
        let msg: String = read!("{}\n");
        if msg.starts_with("/quit") {
            let data = msg.strip_prefix("/quit").unwrap();
            let data = data.trim();
            match client.send(ToSend::Disconnect {
                data: data.as_bytes().to_vec(),
            }) {
                Ok(_) => {}
                Err(e) => {
                    println!("Failed to send disconnect: {:?}", e);
                    break;
                }
            }
        } else {
            match client.send(ToSend::Message {
                channel: Channel::Reliable0,
                data: msg.as_bytes().to_vec(),
            }) {
                Ok(_) => {}
                Err(e) => {
                    println!("Failed to send message: {:?}", e);
                    break;
                }
            }
        }
    }
}
