use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};

use ahash::HashMap;
use ed25519_dalek::SigningKey;
use mio::{Poll, Waker};
use rand::random;
use siphasher::sip::SipHasher;
use thiserror::Error;

use crate::common::{
    encryption::{auth::AuthenticationKind, sym::SymCipherAlgorithm},
    socket::{NetworkConditions, Socket},
};

use super::{
    auth::{self, AuthState, Authenticator},
    send_queue::{SendError, SendQueue},
    Channel, DisconnectReason, ServerCmd, State, WAKE_TOKEN,
};

#[derive(Debug, Error)]
pub enum ServerStartError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Defines how the server chooses a cipher per connection
/// Server best is recommended most of the time because the server
/// has to encrypt and decrypt way more packets on average.
#[derive(Debug, Clone, Copy)]
pub enum CipherPolicy {
    /// The server is greedy and chooses it's most performant cipher
    /// Does not take into account the client's preferences
    ServerBest,
    /// The server is nice and chooses the client's most performant cipher
    ClientBest,
}

/// Holds all the information needed to start the server threads
pub struct ServerBuilder {
    bind_address: SocketAddr,
    /// From most preferred to least preferred
    preferred_ciphers: Vec<SymCipherAlgorithm>,
    cipher_policy: CipherPolicy,
    compatible_versions_min: (u32, u32, u32),
    compatible_versions_max: (u32, u32, u32),
    authenticator: Authenticator,
    signing_key: SigningKey,
    password_salt: [u8; 16],
    packet_receive_queue_size: usize,
    max_pending_messages_per_connection: usize,
    network_circumstances: Option<Box<dyn NetworkConditions>>,
}

impl ServerBuilder {
    pub fn new(
        bind_address: SocketAddr,
        authenticator: Authenticator,
        signing_key: SigningKey,
        password_salt: [u8; 16],
    ) -> Self {
        ServerBuilder {
            bind_address,
            preferred_ciphers: vec![
                SymCipherAlgorithm::ChaCha20Poly1305,
                SymCipherAlgorithm::ChaCha8Poly1305,
            ],
            compatible_versions_max: (0, 0, 0),
            compatible_versions_min: (0, 0, 0),
            cipher_policy: CipherPolicy::ServerBest,
            authenticator,
            signing_key,
            password_salt,
            packet_receive_queue_size: 4096,
            max_pending_messages_per_connection: 1024,
            network_circumstances: None,
        }
    }

    /// Sets the bind address of the server
    pub fn with_bind_address(mut self, bind_address: SocketAddr) -> Self {
        self.bind_address = bind_address;
        self
    }

    /// Sets the preferred ciphers, from most preferred to least preferred
    pub fn with_preferred_ciphers(mut self, ciphers: Vec<SymCipherAlgorithm>) -> Self {
        assert!(
            self.preferred_ciphers.len() <= 5,
            "Preferred ciphers contains a duplicate"
        );
        self.preferred_ciphers = ciphers;
        self
    }

    /// Sets the preferred ciphers automatically.
    /// Super secure will only benchmark AES256GCM and ChaCha20Poly1305
    pub fn with_preferred_ciphers_auto(self, super_secure: bool) -> Self {
        self.with_preferred_ciphers(SymCipherAlgorithm::rank(super_secure))
    }

    /// Sets the compatible client versions
    pub fn with_compatible_versions(mut self, min: (u32, u32, u32), max: (u32, u32, u32)) -> Self {
        self.compatible_versions_min = min;
        self.compatible_versions_max = max;
        self
    }

    /// Sets the cipher selection policy
    pub fn with_cipher_policy(mut self, policy: CipherPolicy) -> Self {
        self.cipher_policy = policy;
        self
    }

    /// Sets the authenticator
    pub fn with_authenticator(mut self, authenticator: Authenticator) -> Self {
        self.authenticator = authenticator;
        self
    }

    pub fn with_signing_key(mut self, signing_key: SigningKey) -> Self {
        self.signing_key = signing_key;
        self
    }

    pub fn with_password_salt(mut self, password_salt: [u8; 16]) -> Self {
        self.password_salt = password_salt;
        self
    }

    pub fn with_packet_receive_queue_size(mut self, packet_receive_queue_size: usize) -> Self {
        self.packet_receive_queue_size = packet_receive_queue_size;
        self
    }

    pub fn with_max_pending_messages_per_connection(
        mut self,
        max_pending_messages_per_connection: usize,
    ) -> Self {
        self.max_pending_messages_per_connection = max_pending_messages_per_connection;
        self
    }

    /// Only active with crate feature "network_testing"
    pub fn with_network_conditions(
        mut self,
        network_circumstances: Box<dyn NetworkConditions>,
    ) -> Self {
        self.network_circumstances = Some(network_circumstances);
        self
    }

    pub fn run(self) -> Result<EisenbahnServer, ServerStartError> {
        let socket = UdpSocket::bind(self.bind_address)?;
        let auth_kind = match &self.authenticator {
            Authenticator::None(_) => AuthenticationKind::None,
            Authenticator::Key(_) => AuthenticationKind::Key,
            Authenticator::Password(_) => AuthenticationKind::Password,
            Authenticator::CA(_) => AuthenticationKind::CA,
        };
        let siphasher = SipHasher::new_with_keys(random(), random());

        let (server_cmds_tx, server_cmds_rx) = crossbeam_channel::unbounded();
        let (auth_cmds_tx, auth_cmds_rx) = crossbeam_channel::unbounded();

        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN)?);

        let (recv_queue_tx, recv_queue_rx) =
            crossbeam_channel::bounded(self.packet_receive_queue_size);
        let send_queue = SendQueue::new(self.max_pending_messages_per_connection, waker.clone());

        let server_info = Arc::new(Mutex::new(ServerInfo::new()));

        // Spawn auth thread
        let _server_cmds_tx = server_cmds_tx.clone();
        let auth_thread = std::thread::spawn(move || {
            let mut state = AuthState::new(self.authenticator, auth_cmds_rx, _server_cmds_tx);
            state.run()
        });

        // Spawn network thread
        let _auth_cmds_tx = auth_cmds_tx.clone();
        let _send_queue = send_queue.clone();
        let _server_info = server_info.clone();
        let network_thread = std::thread::spawn(move || {
            let mut state = State::new(
                poll,
                waker,
                server_cmds_rx,
                _auth_cmds_tx,
                self.preferred_ciphers,
                self.cipher_policy,
                Socket::new(socket, self.network_circumstances)?,
                self.compatible_versions_min,
                self.compatible_versions_max,
                auth_kind,
                self.signing_key,
                siphasher,
                self.password_salt,
                _send_queue,
                recv_queue_tx,
                _server_info,
            );
            state.run()
        });
        Ok(EisenbahnServer::new(
            Some(auth_thread),
            Some(network_thread),
            auth_cmds_tx,
            server_cmds_tx,
            send_queue,
            recv_queue_rx,
            server_info,
        ))
    }
}

#[derive(Debug, Error)]
pub enum ReceiveError {
    #[error("The eisenbahn server has shut down.")]
    ServerStopped,
}

#[derive(Debug)]
pub enum Received {
    Connected {
        player_name: String,
    },
    Message {
        data: Vec<u8>,
    },
    Disconnected {
        reason: DisconnectReason,
        data: Vec<u8>,
    },
}

pub enum ToSend {
    Message { channel: Channel, data: Vec<u8> },
    Disconnect { data: Vec<u8> },
}

#[derive(Debug)]
pub struct ServerInfo {
    per_connection: HashMap<SocketAddr, ConnectionInfo>,
}

#[derive(Debug)]
pub struct ConnectionInfo {
    pub(crate) player_name: String,
    pub(crate) latency: Duration,
}

impl ConnectionInfo {
    pub fn new(player_name: String) -> Self {
        Self {
            player_name,
            latency: Duration::from_secs(0),
        }
    }

    pub fn get_latency(&self) -> Duration {
        self.latency
    }
}

impl ServerInfo {
    pub fn new() -> Self {
        Self {
            per_connection: HashMap::default(),
        }
    }

    pub fn get_con_info(&self, addr: &SocketAddr) -> Option<&ConnectionInfo> {
        self.per_connection.get(addr)
    }

    pub(crate) fn get_con_info_mut(&mut self, addr: &SocketAddr) -> Option<&mut ConnectionInfo> {
        self.per_connection.get_mut(addr)
    }

    pub(crate) fn new_con(&mut self, addr: SocketAddr, player_name: String) {
        self.per_connection
            .insert(addr, ConnectionInfo::new(player_name));
    }
}

pub struct EisenbahnServer {
    auth_thread: Option<JoinHandle<()>>,
    network_thread: Option<JoinHandle<Result<(), std::io::Error>>>,
    auth_cmds_tx: crossbeam_channel::Sender<auth::AuthCmd>,
    server_cmds_tx: crossbeam_channel::Sender<ServerCmd>,

    send_queue: SendQueue,
    recv_queue_rx: crossbeam_channel::Receiver<(SocketAddr, Received)>,
    server_info: Arc<Mutex<ServerInfo>>,
}

impl EisenbahnServer {
    pub(crate) fn new(
        auth_thread: Option<JoinHandle<()>>,
        network_thread: Option<JoinHandle<Result<(), std::io::Error>>>,
        auth_cmds_tx: crossbeam_channel::Sender<auth::AuthCmd>,
        server_cmds_tx: crossbeam_channel::Sender<ServerCmd>,
        send_queue: SendQueue,
        recv_queue_rx: crossbeam_channel::Receiver<(SocketAddr, Received)>,
        server_info: Arc<Mutex<ServerInfo>>,
    ) -> Self {
        Self {
            auth_thread,
            network_thread,
            auth_cmds_tx,
            server_cmds_tx,
            send_queue,
            recv_queue_rx,
            server_info,
        }
    }

    pub fn shutdown(&mut self) {
        let _ = self.auth_cmds_tx.send(auth::AuthCmd::Shutdown);
        let _ = self.server_cmds_tx.send(ServerCmd::Shutdown);
        if let Some(handle) = self.auth_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.network_thread.take() {
            let _ = handle.join();
        }
    }

    pub fn recv(&self) -> Result<Option<(SocketAddr, Received)>, ReceiveError> {
        match self.recv_queue_rx.try_recv() {
            Ok(data) => Ok(Some(data)),
            Err(crossbeam_channel::TryRecvError::Empty) => Ok(None),
            Err(crossbeam_channel::TryRecvError::Disconnected) => Err(ReceiveError::ServerStopped),
        }
    }

    /// Blocks until a packet is received
    pub fn blocking_recv(&self) -> Result<(SocketAddr, Received), ReceiveError> {
        match self.recv_queue_rx.recv() {
            Ok(data) => Ok(data),
            Err(crossbeam_channel::RecvError) => Err(ReceiveError::ServerStopped),
        }
    }

    pub fn send(&self, addr: SocketAddr, to_send: ToSend) -> Result<(), SendError> {
        self.send_queue.send(addr, to_send)
    }

    pub fn blocking_send(&self, addr: SocketAddr, to_send: ToSend) -> Result<(), SendError> {
        self.send_queue.blocking_send(addr, to_send)
    }

    /// NOTE: Locking this mutex blocks the network thread.
    /// Make sure to lock this mutex as little and as short as possible.
    pub fn get_info(&self) -> Arc<Mutex<ServerInfo>> {
        self.server_info.clone()
    }
}
