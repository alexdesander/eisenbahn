use std::{
    collections::BinaryHeap,
    io::{self, Read, Write},
    net::SocketAddr,
    ops::DerefMut,
    rc::Rc,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ahash::HashMap;
use auth::AuthCmd;
use builder::{CipherPolicy, Received, ServerInfo, ToSend};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use connection::Connection;
use crossbeam_channel::TryRecvError;
use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey, VerifyingKey};
use mio::{Events, Interest, Poll, Token, Waker};
use rand::{rngs::SmallRng, thread_rng, Rng, SeedableRng};
use send_queue::SendQueue;
use siphasher::sip::SipHasher;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::common::{constants::*, encryption::auth::AuthenticationKind};
use crate::common::{
    encryption::{sym::SymCipherAlgorithm, Encryption},
    socket::Socket,
};

pub mod auth;
pub mod builder;
mod connection;
pub mod send_queue;

pub(crate) enum ServerCmd {
    SendConnectionResponse {
        addr: SocketAddr,
        cipher: SymCipherAlgorithm,
        salt: u32,
        client_x25519_pub_key: [u8; 32],
        response_type: SendConnectionResponseType,
    },
    SendPasswordResponse {
        addr: SocketAddr,
        salt: u32,
        success: bool,
        encryption: Encryption,
        info: Vec<u8>,
        player_name: String,
    },
    Shutdown,
}

pub(crate) struct TimedEvent {
    deadline: Instant,
    event: Event,
}

impl PartialEq for TimedEvent {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl Eq for TimedEvent {}

impl PartialOrd for TimedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(other.deadline.cmp(&self.deadline))
    }
}

impl Ord for TimedEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.deadline.cmp(&self.deadline)
    }
}

#[derive(Debug)]
pub(crate) enum Event {
    RemoveExpectedPasswordRequest(SocketAddr, u32),
    SendAckOnly(SocketAddr),
    Send(SocketAddr),
    CheckForTimeout,
    Disconnect(SocketAddr, DisconnectReason, Vec<u8>),
    LatencyDiscovery(SocketAddr),
}

pub(crate) enum SendConnectionResponseType {
    Success {
        payload: Vec<u8>,
        player_name: String,
    },
    Failure {
        payload: Vec<u8>,
    },
    NeedsPassword,
}

const RECV_TOKEN: Token = Token(0);
const WAKE_TOKEN: Token = Token(1);

pub(crate) struct State {
    poll: Poll,
    waker: Arc<Waker>,
    rng: SmallRng,

    cmds: crossbeam_channel::Receiver<ServerCmd>,
    auth_cmds: crossbeam_channel::Sender<AuthCmd>,
    /// From most preferred to least preferred
    preferred_ciphers: Vec<SymCipherAlgorithm>,
    cipher_policy: CipherPolicy,

    min_client_version: (u32, u32, u32),
    max_client_version: (u32, u32, u32),
    auth_kind: AuthenticationKind,
    signing_key: SigningKey,
    siphasher: SipHasher,
    password_salt: [u8; 16],

    socket: Socket,
    buf: [u8; 1201],
    events: BinaryHeap<TimedEvent>,
    expected_password_requests: HashMap<(SocketAddr, u32), Encryption>,
    connections: HashMap<SocketAddr, Connection>,

    send_queue: SendQueue,
    to_send_staging_buffer: Vec<(SocketAddr, ToSend)>,
    recv_queue_tx: crossbeam_channel::Sender<(SocketAddr, Received)>,

    timeout_duration: Duration,
    is_checking_for_timeouts: bool,
    latency_discovery_cooldown: Duration,

    server_info: Arc<Mutex<ServerInfo>>,
}

impl State {
    pub(crate) fn new(
        poll: Poll,
        waker: Arc<Waker>,
        cmds: crossbeam_channel::Receiver<ServerCmd>,
        auth_cmds: crossbeam_channel::Sender<AuthCmd>,
        preferred_ciphers: Vec<SymCipherAlgorithm>,
        cipher_policy: CipherPolicy,
        socket: Socket,
        min_client_version: (u32, u32, u32),
        max_client_version: (u32, u32, u32),
        auth_kind: AuthenticationKind,
        signing_key: SigningKey,
        siphasher: SipHasher,
        password_salt: [u8; 16],
        send_queue: SendQueue,
        recv_queue_tx: crossbeam_channel::Sender<(SocketAddr, Received)>,
        server_info: Arc<Mutex<ServerInfo>>,
    ) -> Self {
        State {
            poll,
            waker,
            rng: SmallRng::from_entropy(),
            cmds,
            auth_cmds,
            preferred_ciphers,
            cipher_policy,

            min_client_version,
            max_client_version,
            auth_kind,
            signing_key,
            siphasher,
            password_salt,

            socket,
            buf: [0; 1201],
            events: BinaryHeap::new(),
            expected_password_requests: HashMap::default(),
            connections: HashMap::default(),

            send_queue,
            to_send_staging_buffer: Vec::new(),
            recv_queue_tx,

            timeout_duration: Duration::from_secs(12),
            is_checking_for_timeouts: false,
            latency_discovery_cooldown: Duration::from_secs(2),

            server_info,
        }
    }

    pub fn run(&mut self) -> io::Result<()> {
        let mut events = Events::with_capacity(16);
        self.poll.registry().register(
            self.socket.inner().deref_mut(),
            RECV_TOKEN,
            Interest::READABLE,
        )?;

        loop {
            //TODO: Better timeout handling and waking
            let time_to_wait = match self.events.peek() {
                Some(e) => e
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_micros(50)),
                None => Duration::from_micros(50),
            };

            self.poll.poll(&mut events, Some(time_to_wait))?;

            for event in events.iter() {
                match event.token() {
                    RECV_TOKEN => {
                        self.recv_all()?;
                    }
                    WAKE_TOKEN => {
                        self.handle_send_queue();
                    }
                    _ => unreachable!(),
                }
            }
            if self.handle_all_cmds() || self.handle_all_events()? {
                return Ok(());
            }
        }
    }

    fn recv_all(&mut self) -> io::Result<bool> {
        loop {
            let (size, addr) = match self.socket.recv_from(&mut self.buf) {
                Ok(r) => r,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break Ok(false);
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e),
            };
            if match (self.buf[0] & 0b1111_0000) >> 4 {
                7..=10 => self.handle_payload(size, addr),
                PACKET_ID_LATENCY_RESPONSE => self.handle_latency_response(size, addr),
                PACKET_ID_CLIENT_HELLO => self.handle_client_hello(size, addr),
                PACKET_ID_CONNECTION_REQUEST => self.handle_connection_request(size, addr),
                PACKET_ID_PASSWORD_REQUEST => self.handle_password_request(size, addr),
                PACKET_ID_ACK_ONLY => self.handle_ack_only(size, addr),
                PACKET_ID_DISCONNECT => self.handle_disconnect(size, addr),
                _ => continue,
            } {
                return Ok(true);
            }
        }
    }

    fn handle_all_cmds(&mut self) -> bool {
        loop {
            let cmd = match self.cmds.try_recv() {
                Ok(cmd) => cmd,
                Err(TryRecvError::Disconnected) => return true,
                Err(_) => break,
            };
            match cmd {
                ServerCmd::SendConnectionResponse {
                    addr,
                    cipher,
                    salt,
                    client_x25519_pub_key,
                    response_type,
                } => {
                    if self.send_connection_response(
                        addr,
                        cipher,
                        salt,
                        client_x25519_pub_key,
                        response_type,
                    ) {
                        return true;
                    }
                }
                ServerCmd::SendPasswordResponse {
                    addr,
                    salt,
                    success,
                    encryption,
                    info,
                    player_name,
                } => {
                    if self.send_password_response(
                        addr,
                        salt,
                        success,
                        encryption,
                        info,
                        player_name,
                    ) {
                        return true;
                    }
                }
                ServerCmd::Shutdown => return true,
            }
        }
        false
    }

    /// Returns true if server should be shutdown.
    fn handle_send_queue(&mut self) -> bool {
        if self
            .send_queue
            .get_all_to_send(&mut self.to_send_staging_buffer)
        {
            return true;
        }
        for (addr, to_send) in self.to_send_staging_buffer.drain(..) {
            let Some(con) = self.connections.get_mut(&addr) else {
                continue;
            };
            match to_send {
                ToSend::Message { channel, data } => {
                    con.push(channel, data);
                    if !con.is_currently_sending() {
                        con.start_sending(&mut self.events);
                    }
                }
                ToSend::Disconnect { data } => {
                    let size = con.build_disconnect(
                        &mut self.buf[0..1200],
                        DisconnectReason::UserInitiated,
                        &data,
                    );
                    for _ in 0..2 {
                        if self.socket.send_to(addr, &self.buf[0..size]).is_err() {
                            return true;
                        }
                    }
                    self.connections.remove(&addr);
                    if self
                        .recv_queue_tx
                        .send((
                            addr,
                            Received::Disconnected {
                                reason: DisconnectReason::UserInitiated,
                                data,
                            },
                        ))
                        .is_err()
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn handle_all_events(&mut self) -> Result<bool, io::Error> {
        let now = Instant::now();
        let now_tolerance = Duration::from_micros(500);
        loop {
            if self
                .events
                .peek()
                .map(|e| e.deadline > now + now_tolerance)
                .unwrap_or(true)
            {
                break;
            }
            let event = self.events.pop().unwrap().event;
            match event {
                Event::RemoveExpectedPasswordRequest(addr, salt) => {
                    self.expected_password_requests.remove(&(addr, salt));
                }
                Event::SendAckOnly(addr) => {
                    if let Some(con) = self.connections.get_mut(&addr) {
                        let size = con.build_ack_only(&mut self.buf[..1200]);
                        if self.socket.send_to(addr, &self.buf[..size]).is_err() {
                            return Ok(true);
                        }
                    }
                }
                Event::Send(addr) => {
                    if let Some(con) = self.connections.get_mut(&addr) {
                        match con.build_next_payload(&mut self.buf) {
                            Ok(size) => {
                                self.socket.send_to(addr, &self.buf[0..size])?;
                                self.events.push(TimedEvent {
                                    deadline: Instant::now() + con.send_cooldown(size as u32),
                                    event: Event::Send(addr),
                                });
                            }
                            Err(Some(next_send)) => {
                                self.events.push(TimedEvent {
                                    deadline: Instant::now() + next_send,
                                    event: Event::Send(addr),
                                });
                            }
                            Err(None) => {
                                con.stop_sending();
                            }
                        }
                    }
                }
                Event::CheckForTimeout => {
                    let now = Instant::now();
                    let mut timeouts = 0;
                    for (addr, con) in &mut self.connections {
                        if now.duration_since(con.last_received()) > self.timeout_duration {
                            self.events.push(TimedEvent {
                                deadline: now
                                    + con.send_cooldown(24)
                                    + Duration::from_millis(self.rng.gen_range(0..150)),
                                event: Event::Disconnect(
                                    *addr,
                                    DisconnectReason::TimeOut,
                                    Vec::new(),
                                ),
                            });
                            timeouts += 1;
                        }
                    }
                    if timeouts == self.connections.len() {
                        self.is_checking_for_timeouts = false;
                    } else {
                        self.is_checking_for_timeouts = true;
                        self.events.push(TimedEvent {
                            deadline: now
                                + self.timeout_duration
                                + Duration::from_millis(self.rng.gen_range(0..150)),
                            event: Event::CheckForTimeout,
                        });
                    }
                }
                Event::Disconnect(addr, reason, data) => {
                    let Some(mut con) = self.connections.remove(&addr) else {
                        continue;
                    };
                    if reason == DisconnectReason::TimeOut {
                        if self
                            .recv_queue_tx
                            .send((addr, Received::Disconnected { reason, data }))
                            .is_err()
                        {
                            return Ok(true);
                        }
                        continue;
                    }
                    let size = con.build_disconnect(&mut self.buf[..1200], reason, &data);
                    for _ in 0..2 {
                        if self.socket.send_to(addr, &self.buf[..size]).is_err() {
                            return Ok(true);
                        }
                    }
                    if self
                        .recv_queue_tx
                        .send((addr, Received::Disconnected { reason, data }))
                        .is_err()
                    {
                        return Ok(true);
                    }
                }
                Event::LatencyDiscovery(addr) => {
                    let Some(con) = self.connections.get_mut(&addr) else {
                        continue;
                    };
                    let size = con.build_latency_discovery(&mut self.buf[..1200]);
                    if self.socket.send_to(addr, &self.buf[..size]).is_err() {
                        return Ok(true);
                    }
                    self.events.push(TimedEvent {
                        deadline: Instant::now()
                            + self.latency_discovery_cooldown
                            + Duration::from_millis(self.rng.gen_range(0..15)),
                        event: Event::LatencyDiscovery(addr),
                    });
                }
            }
        }
        Ok(false)
    }

    fn handle_payload(&mut self, size: usize, addr: SocketAddr) -> bool {
        let Some(con) = self.connections.get_mut(&addr) else {
            return false;
        };
        for message in con.handle_payload_packet(&mut self.buf[..size], &mut self.events) {
            match self
                .recv_queue_tx
                .send((addr, Received::Message { data: message }))
            {
                Ok(_) => continue,
                Err(_) => return true,
            }
        }
        false
    }

    fn handle_ack_only(&mut self, size: usize, addr: SocketAddr) -> bool {
        let Some(con) = self.connections.get_mut(&addr) else {
            return false;
        };
        con.handle_ack_only(&mut self.buf[..size]);
        false
    }

    fn handle_disconnect(&mut self, size: usize, addr: SocketAddr) -> bool {
        let Some(con) = self.connections.get_mut(&addr) else {
            return false;
        };
        if let Some((reason, data)) = con.handle_disconnect(&mut self.buf[..size]) {
            match self
                .recv_queue_tx
                .send((addr, Received::Disconnected { reason, data }))
            {
                Ok(_) => {}
                Err(_) => return true,
            }
            self.connections.remove(&addr);
        }
        false
    }

    fn handle_latency_response(&mut self, size: usize, addr: SocketAddr) -> bool {
        let Some(con) = self.connections.get_mut(&addr) else {
            return false;
        };
        let Some(size) = con.handle_latency_response(&mut self.buf[..size]) else {
            return false;
        };
        self.server_info
            .lock()
            .unwrap()
            .get_con_info_mut(&addr)
            .unwrap()
            .latency = con.latency();
        if self.socket.send_to(addr, &self.buf[..size]).is_err() {
            return true;
        }
        false
    }

    fn handle_client_hello(&mut self, size: usize, addr: SocketAddr) -> bool {
        if size != 1200 || &self.buf[1..14] != b"EisenbahnV1.0" {
            return false;
        }
        let mut b = &self.buf[14..];
        let amount_ciphers = b.read_u8().unwrap();
        if amount_ciphers == 0 || amount_ciphers > 5 {
            return false;
        }
        let mut client_ciphers: [SymCipherAlgorithm; 5] = [SymCipherAlgorithm::None; 5];
        for i in 0..amount_ciphers {
            client_ciphers[i as usize] = match SymCipherAlgorithm::from_u8(b.read_u8().unwrap()) {
                Some(c) => c,
                None => return false,
            };
        }
        let Some(cipher) = choose_cipher(
            &self.preferred_ciphers,
            &client_ciphers[..amount_ciphers as usize],
            self.cipher_policy,
        ) else {
            return false;
        };
        let salt = b.read_u32::<LittleEndian>().unwrap();
        let client_version_major = b.read_u32::<LittleEndian>().unwrap();
        let client_version_minor = b.read_u32::<LittleEndian>().unwrap();
        let client_version_patch = b.read_u32::<LittleEndian>().unwrap();

        self.send_server_hello(
            addr,
            cipher,
            salt,
            (
                client_version_major,
                client_version_minor,
                client_version_patch,
            ),
        )
    }

    fn handle_connection_request(&mut self, size: usize, addr: SocketAddr) -> bool {
        if size < 94 {
            return false;
        }
        let received_siphash: u64 = (&self.buf[50..58]).read_u64::<LittleEndian>().unwrap();
        let siphash = self.siphasher.hash(&self.buf[1..49]);
        if siphash != received_siphash {
            return false;
        }
        let mut b = &self.buf[1..];
        let time_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp = b.read_u64::<LittleEndian>().unwrap();
        if timestamp > time_now || time_now - timestamp > 5 {
            return false;
        }
        let salt = b.read_u32::<LittleEndian>().unwrap();
        let challenge = b.read_u32::<LittleEndian>().unwrap();
        let Some(cipher) = SymCipherAlgorithm::from_u8(b.read_u8().unwrap()) else {
            return false;
        };
        let mut b = &self.buf[58..];
        let challenge_result = b.read_u32::<LittleEndian>().unwrap();
        if challenge_result != ((challenge << 1) ^ challenge) {
            return false;
        }
        let mut client_x25519_pub_key = [0u8; 32];
        b.read_exact(&mut client_x25519_pub_key).unwrap();
        match self.auth_kind {
            AuthenticationKind::Password => {
                return self.send_connection_response(
                    addr,
                    cipher,
                    salt,
                    client_x25519_pub_key,
                    SendConnectionResponseType::NeedsPassword,
                );
            }
            AuthenticationKind::None => {
                if size <= 94 {
                    return false;
                }
                let username = &self.buf[94..size];
                let Ok(username) = String::from_utf8(username.to_vec()) else {
                    return false;
                };
                if self.auth_cmds.len() >= 250 {
                    return false;
                }
                if self
                    .auth_cmds
                    .send(AuthCmd::AuthenticateNone {
                        addr,
                        salt,
                        cipher,
                        client_x25519_pub_key,
                        player_name: username,
                    })
                    .is_err()
                {
                    return true;
                }
                return false;
            }
            AuthenticationKind::Key => {
                if size <= 94 + 32 + 64 {
                    return false;
                }
                let username = &self.buf[94..size - 32 - 64];
                let Ok(username) = String::from_utf8(username.to_vec()) else {
                    return false;
                };
                let player_public_key_bytes: [u8; 32] =
                    self.buf[size - 32 - 64..size - 64].try_into().unwrap();
                let client_signature: [u8; 64] = self.buf[size - 64..size].try_into().unwrap();
                let Ok(player_public_key) = VerifyingKey::from_bytes(&player_public_key_bytes)
                else {
                    return false;
                };
                if player_public_key
                    .verify_strict(&self.buf[..size - 64], &client_signature.into())
                    .is_err()
                {
                    return false;
                }
                if self.auth_cmds.len() >= 250 {
                    return false;
                }
                if self
                    .auth_cmds
                    .send(AuthCmd::AuthenticateKey {
                        addr,
                        salt,
                        cipher,
                        client_x25519_pub_key,
                        player_name: username,
                        player_public_key,
                    })
                    .is_err()
                {
                    return true;
                }
                return false;
            }
            AuthenticationKind::CA => {
                if size != 94 + 32 {
                    return false;
                }
                let ticket: [u8; 32] = self.buf[94..size].try_into().unwrap();
                if self.auth_cmds.len() >= 250 {
                    return false;
                }
                if self
                    .auth_cmds
                    .send(AuthCmd::AuthenticateCA {
                        addr,
                        salt,
                        cipher,
                        client_x25519_pub_key,
                        ticket,
                    })
                    .is_err()
                {
                    return true;
                }
                return false;
            }
        }
    }

    fn handle_password_request(&mut self, size: usize, addr: SocketAddr) -> bool {
        if self.auth_kind != AuthenticationKind::Password {
            return false;
        }
        if size < 41 || size > 296 {
            return false;
        }
        let mut b = &self.buf[1..];
        let salt = b.read_u32::<LittleEndian>().unwrap();
        let encryption = match self.expected_password_requests.remove(&(addr, salt)) {
            Some(ciphers) => ciphers,
            None => {
                return false;
            }
        };
        let tag: [u8; 16] = self.buf[size - 16..size].try_into().unwrap();
        let aad: [u8; 5] = self.buf[..5].try_into().unwrap();
        if !encryption.decrypt(
            &NONCE_PASSWORD_REQUEST,
            &aad,
            &mut self.buf[5..size - 16],
            &tag,
        ) {
            return false;
        }
        let password_hash: [u8; 20] = self.buf[size - 16 - 20..size - 16].try_into().unwrap();
        let Ok(player_name) = String::from_utf8(self.buf[5..size - 16 - 20].to_vec()) else {
            return false;
        };
        if self.auth_cmds.len() >= 250 {
            return false;
        }
        if self
            .auth_cmds
            .send(AuthCmd::AuthenticatePassword {
                addr,
                salt,
                encryption,
                player_name,
                password_hash,
            })
            .is_err()
        {
            return true;
        }
        false
    }

    fn send_server_hello(
        &mut self,
        addr: SocketAddr,
        sym_cipher: SymCipherAlgorithm,
        salt: u32,
        client_version: (u32, u32, u32),
    ) -> bool {
        self.buf[0] = PACKET_ID_SERVER_HELLO << 4;
        let version_supported =
            client_version >= self.min_client_version && client_version <= self.max_client_version;
        self.buf[0] |= (version_supported as u8) << 3;
        self.buf[0] |= (self.auth_kind as u8) << 1;
        let time_stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut b = &mut self.buf[1..];
        b.write_u64::<LittleEndian>(time_stamp).unwrap();
        b.write_u32::<LittleEndian>(salt).unwrap();
        if !version_supported {
            b.write_u32::<LittleEndian>(self.min_client_version.0)
                .unwrap();
            b.write_u32::<LittleEndian>(self.min_client_version.1)
                .unwrap();
            b.write_u32::<LittleEndian>(self.min_client_version.2)
                .unwrap();
            b.write_u32::<LittleEndian>(self.max_client_version.0)
                .unwrap();
            b.write_u32::<LittleEndian>(self.max_client_version.1)
                .unwrap();
            b.write_u32::<LittleEndian>(self.max_client_version.2)
                .unwrap();
            self.socket.send_to(addr, &self.buf[..37]).unwrap();
            return false;
        }
        let challenge: u32 = thread_rng().gen();
        b.write_u32::<LittleEndian>(challenge).unwrap();
        b.write_u8(sym_cipher as u8).unwrap();
        let pub_key_bytes = self.signing_key.verifying_key().to_bytes();
        b.write_all(&pub_key_bytes).unwrap();
        let siphash = self.siphasher.hash(&self.buf[1..49]);
        (&mut self.buf[50..])
            .write_u64::<LittleEndian>(siphash)
            .unwrap();
        self.socket.send_to(addr, &self.buf[..58]).unwrap();
        false
    }

    fn send_connection_response(
        &mut self,
        addr: SocketAddr,
        cipher: SymCipherAlgorithm,
        salt: u32,
        client_x25519_pub_key: [u8; 32],
        response_type: SendConnectionResponseType,
    ) -> bool {
        let server_x25519_key = EphemeralSecret::random_from_rng(&mut thread_rng());
        let server_x25519_pub_key = PublicKey::from(&server_x25519_key);
        let client_x25519_pub_key = PublicKey::from(client_x25519_pub_key);

        let shared_secret = server_x25519_key.diffie_hellman(&client_x25519_pub_key);
        if !shared_secret.was_contributory() {
            return false;
        }
        let encryption = Encryption::new(shared_secret, true, cipher);

        let success = match &response_type {
            SendConnectionResponseType::Success { .. } => true,
            SendConnectionResponseType::Failure { .. } => false,
            SendConnectionResponseType::NeedsPassword => true,
        };
        self.buf[0] = PACKET_ID_CONNECTION_RESPONSE << 4;
        self.buf[0] |= (success as u8) << 3;
        let mut b = &mut self.buf[1..];
        b.write_u32::<LittleEndian>(salt).unwrap();
        b.write_all(&self.password_salt).unwrap();
        b.write_all(server_x25519_pub_key.as_bytes()).unwrap();

        match response_type {
            SendConnectionResponseType::Success {
                mut payload,
                player_name,
            } => {
                assert!(payload.len() <= 1067);
                match payload.len() {
                    0 => {
                        let signature = self.signing_key.sign(&self.buf[..53]);
                        self.buf[53..53 + 64].copy_from_slice(&signature.to_bytes());
                        self.socket.send_to(addr, &self.buf[..53 + 64]).unwrap();
                    }
                    x => {
                        let tag = encryption.encrypt(&NONCE_CONNECTION_RESPONSE, &[], &mut payload);
                        b.write_all(&payload).unwrap();
                        b.write_all(&tag).unwrap();
                        let signature = self.signing_key.sign(&self.buf[..53 + x + 16]);
                        self.buf[53 + x + 16..53 + x + 16 + 64]
                            .copy_from_slice(&signature.to_bytes());
                        self.socket
                            .send_to(addr, &self.buf[..53 + x + 16 + 64])
                            .unwrap();
                    }
                }
                self.send_queue.add(addr);
                self.connections.insert(
                    addr,
                    Connection::new(addr, player_name.clone(), Rc::new(encryption)),
                );
                self.server_info
                    .lock()
                    .unwrap()
                    .new_con(addr, player_name.clone());
                if !self.is_checking_for_timeouts {
                    self.is_checking_for_timeouts = true;
                    self.events.push(TimedEvent {
                        deadline: Instant::now() + self.timeout_duration,
                        event: Event::CheckForTimeout,
                    });
                }
                self.events.push(TimedEvent {
                    deadline: Instant::now(),
                    event: Event::LatencyDiscovery(addr),
                });
                if self
                    .recv_queue_tx
                    .send((addr, Received::Connected { player_name }))
                    .is_err()
                {
                    return true;
                }
            }
            SendConnectionResponseType::Failure { mut payload } => {
                assert!(payload.len() <= 1067);
                match payload.len() {
                    0 => {
                        let signature = self.signing_key.sign(&self.buf[..53]);
                        self.buf[53..53 + 64].copy_from_slice(&signature.to_bytes());
                        self.socket.send_to(addr, &self.buf[..53 + 64]).unwrap();
                    }
                    x => {
                        let tag = encryption.encrypt(&NONCE_CONNECTION_RESPONSE, &[], &mut payload);
                        b.write_all(&payload).unwrap();
                        b.write_all(&tag).unwrap();
                        let signature = self.signing_key.sign(&self.buf[..53 + x + 16]);
                        self.buf[53 + x + 16..53 + x + 16 + 64]
                            .copy_from_slice(&signature.to_bytes());
                        self.socket
                            .send_to(addr, &self.buf[..53 + x + 16 + 64])
                            .unwrap();
                    }
                }
            }
            SendConnectionResponseType::NeedsPassword => {
                let signature = self.signing_key.sign(&self.buf[..53]);
                self.buf[53..53 + 64].copy_from_slice(&signature.to_bytes());

                if self.expected_password_requests.contains_key(&(addr, salt)) {
                    return false;
                }
                self.expected_password_requests
                    .insert((addr, salt), encryption);
                self.events.push(TimedEvent {
                    deadline: Instant::now() + std::time::Duration::from_secs(5),
                    event: Event::RemoveExpectedPasswordRequest(addr, salt),
                });
                self.socket.send_to(addr, &self.buf[..53 + 64]).unwrap();
            }
        }

        false
    }

    fn send_password_response(
        &mut self,
        addr: SocketAddr,
        salt: u32,
        success: bool,
        encryption: Encryption,
        mut connection_information: Vec<u8>,
        player_name: String,
    ) -> bool {
        self.buf[0] = PACKET_ID_PASSWORD_RESPONSE << 4;
        self.buf[0] |= (success as u8) << 3;
        let mut b = &mut self.buf[1..];
        b.write_u32::<LittleEndian>(salt).unwrap();
        assert!(connection_information.len() <= 1179);
        let aad: [u8; 5] = self.buf[..5].try_into().unwrap();
        let tag = encryption.encrypt(&NONCE_PASSWORD_RESPONSE, &aad, &mut connection_information);
        let mut b = &mut self.buf[5..];
        b.write_all(&connection_information).unwrap();
        b.write_all(&tag).unwrap();
        if success {
            self.send_queue.add(addr);
            self.connections.insert(
                addr,
                Connection::new(addr, player_name.clone(), Rc::new(encryption)),
            );
            self.server_info
                .lock()
                .unwrap()
                .new_con(addr, player_name.clone());
            if !self.is_checking_for_timeouts {
                self.is_checking_for_timeouts = true;
                self.events.push(TimedEvent {
                    deadline: Instant::now() + self.timeout_duration,
                    event: Event::CheckForTimeout,
                });
            }
            self.events.push(TimedEvent {
                deadline: Instant::now(),
                event: Event::LatencyDiscovery(addr),
            });
            if self
                .recv_queue_tx
                .send((addr, Received::Connected { player_name }))
                .is_err()
            {
                return true;
            }
        }
        self.socket
            .send_to(addr, &self.buf[..5 + connection_information.len() + 16])
            .unwrap();
        false
    }
}

fn choose_cipher(
    server_ciphers: &[SymCipherAlgorithm],
    client_ciphers: &[SymCipherAlgorithm],
    policy: CipherPolicy,
) -> Option<SymCipherAlgorithm> {
    match policy {
        CipherPolicy::ServerBest => server_ciphers.get(0).copied(),
        CipherPolicy::ClientBest => client_ciphers.get(0).copied(),
    }
}
