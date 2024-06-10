#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use ed25519_dalek::SigningKey;
    use rand::{rngs::SmallRng, Rng, SeedableRng};

    use crate::{
        client::builder::ClientBuilder,
        common::{constants::Channel, encryption::auth::AuthenticationNone},
        server::{
            auth::{AuthenticationResult, Authenticator, NoneAuthenticator},
            builder::ServerBuilder,
        },
    };

    struct MockNoneAuthenticator;

    impl NoneAuthenticator for MockNoneAuthenticator {
        fn authenticate(&mut self, player_name: &str) -> crate::server::auth::AuthenticationResult {
            AuthenticationResult::Success { payload: vec![] }
        }
    }

    #[test]
    fn server_to_client() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let server_address: SocketAddr = "127.0.0.1:44454".parse().unwrap();
        let server = ServerBuilder::new(
            server_address,
            Authenticator::None(Box::new(MockNoneAuthenticator)),
            signing_key,
            [0; 16],
        )
        .run()
        .unwrap();
        let client = ClientBuilder::new()
            .with_preferred_ciphers_auto(false)
            .with_none_authentication(Some(AuthenticationNone::new("hi".to_string())))
            .connect(server_address, None)
            .unwrap();
        let client_address;
        loop {
            let Ok(Some(msg)) = server.recv() else {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            };
            match msg {
                (addr, crate::server::builder::Received::Connected { player_name }) => {
                    client_address = addr;
                    break;
                }
                _ => unreachable!(),
            };
        }

        let mut rng = SmallRng::from_entropy();
        let mut msgs = Vec::new();
        for _ in 0..200 {
            msgs.push(vec![rng.gen::<u8>(); rng.gen_range(1..3000)]);
        }

        let mut received = Vec::new();
        for msg in msgs.iter() {
            server
                .send(
                    client_address,
                    crate::server::builder::ToSend::Message {
                        channel: Channel::Reliable0,
                        data: msg.clone(),
                    },
                )
                .unwrap();
            if rng.gen_bool(0.3) {
                while let Ok(Some(msg)) = client.recv() {
                    match msg {
                        crate::client::Received::Message { data } => {
                            received.push(data);
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        loop {
            if msgs.len() == received.len() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            while let Ok(Some(msg)) = client.recv() {
                match msg {
                    crate::client::Received::Message { data } => {
                        received.push(data);
                    }
                    _ => unreachable!(),
                }
            }
        }

        assert_eq!(msgs, received);
    }

    #[test]
    fn client_to_server() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let server_address: SocketAddr = "127.0.0.1:44444".parse().unwrap();
        let server = ServerBuilder::new(
            server_address,
            Authenticator::None(Box::new(MockNoneAuthenticator)),
            signing_key,
            [0; 16],
        )
        .run()
        .unwrap();
        let client = ClientBuilder::new()
            .with_preferred_ciphers_auto(false)
            .with_none_authentication(Some(AuthenticationNone::new("hi".to_string())))
            .connect(server_address, None)
            .unwrap();
        let client_address;
        loop {
            let Ok(Some(msg)) = server.recv() else {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            };
            match msg {
                (addr, crate::server::builder::Received::Connected { player_name }) => {
                    client_address = addr;
                    break;
                }
                _ => unreachable!(),
            };
        }

        let mut rng = SmallRng::from_entropy();
        let mut msgs = Vec::new();
        for _ in 0..200 {
            msgs.push(vec![rng.gen::<u8>(); rng.gen_range(1..3000)]);
        }

        let mut received = Vec::new();
        for msg in msgs.iter() {
            client
                .send(crate::client::ToSend::Message {
                    channel: Channel::Reliable0,
                    data: msg.clone(),
                })
                .unwrap();
            if rng.gen_bool(0.3) {
                while let Ok(Some(msg)) = client.recv() {
                    match msg {
                        crate::client::Received::Message { data } => {
                            received.push(data);
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        loop {
            if msgs.len() == received.len() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            while let Ok(Some(msg)) = server.recv() {
                match msg {
                    (_, crate::server::builder::Received::Message { data }) => {
                        received.push(data);
                    }
                    _ => unreachable!(),
                }
            }
        }

        assert_eq!(msgs, received);
    }
}
