// DISCLAIMER: THIS CODE WAS BUILT IN A RUSH TO TEST THE PROTOTYPE
// THIS DOES NOT REPRESENT THE QUALITY OF MY CODE OR THE EISENBAHN PROJECT

use clap::Parser;
use eisenbahn::{
    client::{builder::ClientBuilder, Received, ToSend},
    common::{constants::Channel, encryption::auth::AuthenticationNone},
};
use text_io::read;

#[derive(Parser)]
struct Args {
    username: String,
}

pub fn main() {
    let args = Args::parse();
    let client = ClientBuilder::new()
        .with_none_authentication(Some(AuthenticationNone::new(args.username)))
        .connect("127.0.0.1:44444".parse().unwrap(), None)
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
