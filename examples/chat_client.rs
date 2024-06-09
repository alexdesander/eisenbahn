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

    let _client = client.clone();
    std::thread::spawn(move || loop {
        match _client.blocking_recv().unwrap() {
            Received::Message { data } => {
                let message = String::from_utf8(data).unwrap();
                println!("{}", message);
            }
            Received::Disconnect { reason, data } => {
                let message = String::from_utf8(data).unwrap();
                println!("Disconnected: {}, reason: {:?}", message, reason);
                break;
            }
        }
    });

    loop {
        let line: String = read!("{}\n");
        match client.blocking_send(ToSend::Message {
            channel: Channel::Reliable0,
            data: line.as_bytes().to_vec(),
        }) {
            Ok(_) => {}
            Err(_) => {
                println!("Failed to send message");
                break;
            }
        }
    }
}
