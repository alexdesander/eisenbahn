use std::{
    io::{self, Read, Write},
    net::{SocketAddr, UdpSocket},
    rc::Rc,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crossbeam_channel::{TryRecvError, TrySendError};
use ed25519_dalek::{ed25519::signature::Signer, VerifyingKey};
use mio::{Poll, Waker};
use rand::{thread_rng, Rng};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::common::{
    constants::*,
    encryption::{
        auth::{
            AuthenticationCA, AuthenticationKey, AuthenticationKind, AuthenticationNone,
            AuthenticationPassword,
        },
        sym::SymCipherAlgorithm,
        Encryption,
    },
};

use super::{ClientCmd, ClientState, Received, ToSend, WAKE_TOKEN};

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Handshake timed out")]
    TimedOut,
    #[error("Client version is incompatible with server version")]
    VersionIncompatibility {
        min_supported_version: (u32, u32, u32),
        max_supported_version: (u32, u32, u32),
    },
    #[error("Server public key does not match the trusted server key")]
    KeyMismatch { received_key: VerifyingKey },
    #[error("Server sent an invalid signature")]
    SignatureIncorrect,
    #[error("Server chose None cipher but it is not allowed")]
    NoneCipherNotAllowed,
    #[error("The key exchange was not contributory")]
    KeyExchangeWasNotContributory,
    #[error("The authentication methos is not supported by the client (no auth info provided to the client))")]
    AuthenticationNotSupported(AuthenticationKind),
    #[error("The server denied the connection")]
    ConnectionDenied { info: Vec<u8> },
    #[error("Decryption error")]
    DecryptionError,
}

/// Holds all the information needed to connect to a server
/// Acts as a connection builder
pub struct ClientBuilder {
    bind_address: SocketAddr,
    /// From most preferred to least preferred
    preferred_ciphers: Vec<SymCipherAlgorithm>,
    allow_none_cipher: bool,
    version: (u32, u32, u32),
    handshake_timeout: Duration,
    none_authentication: Option<AuthenticationNone>,
    key_authentication: Option<AuthenticationKey>,
    password_authentication: Option<AuthenticationPassword>,
    ca_authentication: Option<AuthenticationCA>,
    send_queue_max_pending_messages: usize,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            bind_address: "0.0.0.0:0".parse().unwrap(),
            preferred_ciphers: vec![
                SymCipherAlgorithm::ChaCha20Poly1305,
                SymCipherAlgorithm::ChaCha8Poly1305,
            ],
            allow_none_cipher: false,
            version: (0, 0, 0),
            handshake_timeout: Duration::from_secs(10),
            none_authentication: None,
            key_authentication: None,
            password_authentication: None,
            ca_authentication: None,
            send_queue_max_pending_messages: 1024,
        }
    }

    pub fn with_bind_address(mut self, bind_address: SocketAddr) -> Self {
        self.bind_address = bind_address;
        self
    }

    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        assert_ne!(
            timeout,
            Duration::from_secs(0),
            "Handshake timeout cannot be 0"
        );
        self.handshake_timeout = timeout;
        self
    }

    /// Sets the preferred ciphers for the connection, from most preferred to least preferred
    pub fn with_preferred_ciphers(mut self, ciphers: Vec<SymCipherAlgorithm>) -> Self {
        assert!(
            self.preferred_ciphers.len() <= 5,
            "Preferred ciphers contains a duplicate"
        );
        self.preferred_ciphers = ciphers;
        self
    }

    /// Sets the preferred ciphers for the connection automatically.
    /// Super secure will only benchmark AES256GCM and ChaCha20Poly1305
    pub fn with_preferred_ciphers_auto(self, super_secure: bool) -> Self {
        self.with_preferred_ciphers(SymCipherAlgorithm::rank(super_secure))
    }

    /// Sets the version of the client, this will be sent to the server
    /// to check for game version compatibility, the default is 0.0.0
    pub fn with_version(mut self, major: u32, minor: u32, patch: u32) -> Self {
        self.version = (major, minor, patch);
        self
    }

    pub fn with_allow_none_cipher(mut self, allow: bool) -> Self {
        self.allow_none_cipher = allow;
        self
    }

    pub fn with_none_authentication(mut self, authentication: Option<AuthenticationNone>) -> Self {
        self.none_authentication = authentication;
        self
    }

    pub fn with_key_authentication(mut self, authentication: Option<AuthenticationKey>) -> Self {
        self.key_authentication = authentication;
        self
    }

    pub fn with_password_authentication(
        mut self,
        authentication: Option<AuthenticationPassword>,
    ) -> Self {
        self.password_authentication = authentication;
        self
    }

    pub fn with_ca_authentication(mut self, authentication: Option<AuthenticationCA>) -> Self {
        self.ca_authentication = authentication;
        self
    }

    pub fn with_send_queue_max_pending_messages(mut self, max: usize) -> Self {
        self.send_queue_max_pending_messages = max;
        self
    }

    pub fn connect(
        &self,
        server_address: SocketAddr,
        trusted_server_key: Option<VerifyingKey>,
    ) -> Result<EisenbahnClient, ConnectError> {
        let socket = UdpSocket::bind(self.bind_address)?;
        socket.connect(server_address)?;
        let mut buf = [0u8; 1201];

        // Send client hello
        buf[0] |= PACKET_ID_CLIENT_HELLO << 4;
        let mut b = &mut buf[1..];
        b.write_all(MAGIC)?;
        b.write_u8(self.preferred_ciphers.len() as u8)?;
        for cipher in &self.preferred_ciphers {
            b.write_u8(*cipher as u8)?;
        }
        let salt: u32 = thread_rng().gen();
        b.write_u32::<byteorder::LittleEndian>(salt)?;
        b.write_u32::<byteorder::LittleEndian>(self.version.0)?;
        b.write_u32::<byteorder::LittleEndian>(self.version.1)?;
        b.write_u32::<byteorder::LittleEndian>(self.version.2)?;
        socket.send(&buf[..1200])?;

        // Recv server hello
        let start = Instant::now();
        socket.set_read_timeout(Some(self.handshake_timeout))?;
        let size = match socket.recv(&mut buf) {
            Ok(size) => size,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(ConnectError::TimedOut),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(ConnectError::TimedOut),
            Err(e) => return Err(ConnectError::IoError(e)),
        };
        if size != 37 && size != 58 {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid server hello packet size",
            )));
        }
        if (&buf[9..13]).read_u32::<LittleEndian>()? != salt {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid server hello packet salt",
            )));
        }
        if buf[0] >> 4 != PACKET_ID_SERVER_HELLO {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid server hello packet id",
            )));
        }
        if buf[0] & 0b0000_1000 == 0 {
            if size != 37 {
                return Err(ConnectError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid server hello packet size for version incompatibility server hello",
                )));
            }
            let mut b = &buf[13..];
            let min_supported_version = (
                b.read_u32::<LittleEndian>()?,
                b.read_u32::<LittleEndian>()?,
                b.read_u32::<LittleEndian>()?,
            );
            let max_supported_version = (
                b.read_u32::<LittleEndian>()?,
                b.read_u32::<LittleEndian>()?,
                b.read_u32::<LittleEndian>()?,
            );
            return Err(ConnectError::VersionIncompatibility {
                min_supported_version,
                max_supported_version,
            });
        }
        let mut b = &buf[13..];
        let challenge = b.read_u32::<LittleEndian>()?;
        let Some(chosen_cipher) = SymCipherAlgorithm::from_u8(b.read_u8()?) else {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid chosen cipher in server hello",
            )));
        };
        let Ok(server_pub_key) = VerifyingKey::from_bytes(b[..32].try_into().unwrap()) else {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Something went wrong while reading the server public key",
            )));
        };
        if let Some(trusted_server_key) = trusted_server_key {
            if server_pub_key != trusted_server_key {
                return Err(ConnectError::KeyMismatch {
                    received_key: server_pub_key,
                });
            }
        }
        let Some(auth_kind) = AuthenticationKind::from_u8((buf[0] & 0b0000_0110) >> 1) else {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid authentication kind in server hello",
            )));
        };
        if chosen_cipher == SymCipherAlgorithm::None {
            if !self.allow_none_cipher {
                return Err(ConnectError::NoneCipherNotAllowed);
            }
        }
        match auth_kind {
            AuthenticationKind::None => {
                if self.none_authentication.is_none() {
                    return Err(ConnectError::AuthenticationNotSupported(
                        AuthenticationKind::None,
                    ));
                }
            }
            AuthenticationKind::Password => {
                if self.password_authentication.is_none() {
                    return Err(ConnectError::AuthenticationNotSupported(
                        AuthenticationKind::Password,
                    ));
                }
            }
            AuthenticationKind::Key => {
                if self.key_authentication.is_none() {
                    return Err(ConnectError::AuthenticationNotSupported(
                        AuthenticationKind::Key,
                    ));
                }
            }
            AuthenticationKind::CA => {
                if self.ca_authentication.is_none() {
                    return Err(ConnectError::AuthenticationNotSupported(
                        AuthenticationKind::CA,
                    ));
                }
            }
        }

        // Send connection request
        let client_x25519_key = EphemeralSecret::random_from_rng(&mut thread_rng());
        let client_x25519_pub_key = PublicKey::from(&client_x25519_key);

        buf[0] = PACKET_ID_CONNECTION_REQUEST << 4;
        // We keep everything from time stamp to server siphash
        let mut b = &mut buf[58..];
        b.write_u32::<LittleEndian>((challenge << 1) ^ challenge)?;
        b.write_all(client_x25519_pub_key.as_bytes())?;
        let size;
        match auth_kind {
            AuthenticationKind::None => {
                let auth = self.none_authentication.as_ref().unwrap();
                b.write(auth.username.as_bytes())?;
                size = 94 + auth.username.len();
            }
            AuthenticationKind::Key => {
                let auth = self.key_authentication.as_ref().unwrap();
                b.write(auth.username.as_bytes())?;
                b.write(auth.key.as_bytes())?;
                let offset = 126 + auth.username.len();
                let signature = auth.key.sign(&buf[..offset]);
                buf[offset..offset + 64].copy_from_slice(&signature.to_bytes());
                size = offset + 64;
            }
            AuthenticationKind::CA => {
                let auth = self.ca_authentication.as_ref().unwrap();
                b.write(&auth.ticket)?;
                size = 126;
            }
            AuthenticationKind::Password => {
                size = 94;
            }
        }
        socket.send(&buf[..size])?;

        // Recv connection response
        socket.set_read_timeout(Some(
            self.handshake_timeout.saturating_sub(start.elapsed()) + Duration::from_millis(5),
        ))?;
        let size = match socket.recv(&mut buf) {
            Ok(size) => size,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(ConnectError::TimedOut),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(ConnectError::TimedOut),
            Err(e) => return Err(ConnectError::IoError(e)),
        };
        if size < 117 || size > 1200 {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid connection response packet size",
            )));
        }
        if buf[0] >> 4 != PACKET_ID_CONNECTION_RESPONSE {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid connection response packet id",
            )));
        }
        let signature: [u8; 64] = buf[size - 64..size].try_into().unwrap();
        if server_pub_key
            .verify_strict(&buf[..size - 64], &signature.into())
            .is_err()
        {
            return Err(ConnectError::SignatureIncorrect);
        }
        if (&buf[1..5]).read_u32::<LittleEndian>()? != salt {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid connection salt in connection response packet",
            )));
        }
        let mut b = &buf[5..];
        let mut password_salt = [0u8; 16];
        b.read_exact(&mut password_salt)?;

        let mut server_x25519_pub_key_bytes = [0u8; 32];
        b.read_exact(&mut server_x25519_pub_key_bytes)?;
        let server_x25519_pub_key = PublicKey::from(server_x25519_pub_key_bytes);
        let shared_secret = client_x25519_key.diffie_hellman(&server_x25519_pub_key);
        if !shared_secret.was_contributory() {
            return Err(ConnectError::KeyExchangeWasNotContributory);
        }
        let encryption = Encryption::new(shared_secret, false, chosen_cipher);

        if buf[0] & 0b0000_1000 == 0 {
            let info = match size {
                x if x > 153 => {
                    let mut info = buf[153..size - 64 - 16].to_vec();
                    let tag = &buf[size - 64 - 16..size - 64];
                    if !encryption.decrypt(&NONCE_CONNECTION_RESPONSE, &[], &mut info, &tag) {
                        return Err(ConnectError::DecryptionError);
                    }
                    info
                }
                _ => Vec::new(),
            };
            return Err(ConnectError::ConnectionDenied { info });
        }

        if auth_kind != AuthenticationKind::Password {
            let info = match size {
                x if x > 153 => {
                    let mut info = buf[153..size - 64 - 16].to_vec();
                    let tag = &buf[size - 64 - 16..size - 64];
                    if !encryption.decrypt(&NONCE_CONNECTION_RESPONSE, &[], &mut info, &tag) {
                        return Err(ConnectError::DecryptionError);
                    }
                    info
                }
                _ => Vec::new(),
            };
            return Ok(EisenbahnClient::new(
                socket,
                encryption,
                self.send_queue_max_pending_messages,
            ));
        }

        // If we get here, we need to do the additional password authentication steps
        // Send password request
        buf[0] = PACKET_ID_PASSWORD_REQUEST << 4;
        // Salt is already in the buffer
        let password_auth = self.password_authentication.as_ref().unwrap();
        let username = password_auth.username.as_bytes();
        let password_hash = password_auth.hashed(password_salt);
        let mut b = &mut buf[5..];
        b.write_all(username)?;
        b.write_all(&password_hash)?;
        let tag_offset = 5 + username.len() + password_hash.len();
        let aad: [u8; 5] = buf[..5].try_into().unwrap();
        let tag = encryption.encrypt(&NONCE_PASSWORD_REQUEST, &aad, &mut buf[5..tag_offset]);
        buf[tag_offset..tag_offset + 16].copy_from_slice(&tag);
        socket.send(&buf[..tag_offset + 16])?;

        // Recv password response
        socket.set_read_timeout(Some(
            start.elapsed().saturating_sub(self.handshake_timeout) + Duration::from_millis(5),
        ))?;
        let size = match socket.recv(&mut buf) {
            Ok(size) => size,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(ConnectError::TimedOut),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(ConnectError::TimedOut),
            Err(e) => return Err(ConnectError::IoError(e)),
        };
        if (size != 5 && size < 22) || size > 1200 {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid password response packet size",
            )));
        }
        if buf[0] >> 4 != PACKET_ID_PASSWORD_RESPONSE {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid password response packet id",
            )));
        }
        if (&buf[1..5]).read_u32::<LittleEndian>()? != salt {
            return Err(ConnectError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid password response packet salt",
            )));
        }
        let info = match size {
            x if x > 5 => {
                let mut info = buf[5..size].to_vec();
                let aad: [u8; 5] = buf[..5].try_into().unwrap();
                let tag = &buf[size - 16..size];
                if !encryption.decrypt(&NONCE_PASSWORD_RESPONSE, &aad, &mut info, &tag) {
                    return Err(ConnectError::DecryptionError);
                }
                info
            }
            _ => Vec::new(),
        };
        if buf[0] | 0b0000_1000 != 1 {
            return Err(ConnectError::ConnectionDenied { info });
        }
        Ok(EisenbahnClient::new(
            socket,
            encryption,
            self.send_queue_max_pending_messages,
        ))
    }
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("The client is not running")]
    ClientStopped,
    #[error("The send queue is full")]
    SendQueueFull,
}

#[derive(Debug, Error)]
pub enum RecvError {
    #[error("The client is not running")]
    ClientStopped,
}

#[derive(Clone)]
pub struct EisenbahnClient {
    network_thread: Arc<Mutex<Option<JoinHandle<Result<(), std::io::Error>>>>>,
    client_cmds: crossbeam_channel::Sender<ClientCmd>,
    waker: Arc<Waker>,
    to_send_tx: crossbeam_channel::Sender<ToSend>,
    received_rx: crossbeam_channel::Receiver<Received>,
}

impl EisenbahnClient {
    pub fn new(
        socket: UdpSocket,
        encryption: Encryption,
        send_queue_max_pending_messages: usize,
    ) -> Self {
        socket.set_nonblocking(true).unwrap();
        let (client_cmds_tx, client_cmds_rx) = crossbeam_channel::unbounded();
        let (to_send_tx, to_send_rx) = crossbeam_channel::bounded(send_queue_max_pending_messages);
        let (received_tx, received_rx) = crossbeam_channel::unbounded();

        let poll = Poll::new().unwrap();
        let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN).unwrap());
        let _waker = waker.clone();
        let network_thread = std::thread::spawn(|| {
            let mut state = ClientState::new(
                client_cmds_rx,
                mio::net::UdpSocket::from_std(socket),
                poll,
                _waker,
                Rc::new(encryption),
                to_send_rx,
                received_tx,
            );
            state.run()
        });

        Self {
            network_thread:Arc::new(Mutex::new( Some(network_thread))),
            client_cmds: client_cmds_tx,
            waker,
            to_send_tx,
            received_rx,
        }
    }

    pub fn shutdown(&mut self) {
        let _ = self.client_cmds.send(ClientCmd::Shutdown);
        let _ = self.waker.wake();
        if let Some(handle) = self.network_thread.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    pub fn send(&self, to_send: ToSend) -> Result<(), SendError> {
        match self.to_send_tx.try_send(to_send) {
            Ok(_) => {}
            Err(TrySendError::Full(_)) => return Err(SendError::SendQueueFull),
            _ => return Err(SendError::ClientStopped),
        }
        let _ = self.waker.wake();
        Ok(())
    }

    /// This will never return SendError::SendQueueFull
    pub fn blocking_send(&self, to_send: ToSend) -> Result<(), SendError> {
        match self.to_send_tx.send(to_send) {
            Ok(_) => {}
            _ => return Err(SendError::ClientStopped),
        }
        let _ = self.waker.wake();
        Ok(())
    }

    pub fn recv(&self) -> Result<Option<Received>, RecvError> {
        match self.received_rx.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(_) => Err(RecvError::ClientStopped),
        }
    }

    pub fn blocking_recv(&self) -> Result<Received, RecvError> {
        match self.received_rx.recv() {
            Ok(msg) => Ok(msg),
            Err(_) => Err(RecvError::ClientStopped),
        }
    }
}
