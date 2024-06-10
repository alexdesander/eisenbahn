use std::{
    collections::BinaryHeap,
    io::{self, Write},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use byteorder::WriteBytesExt;
use crossbeam_channel::{TryRecvError, TrySendError};
use mio::{net::UdpSocket, Events, Interest, Poll, Token, Waker};
use rand::{rngs::SmallRng, Rng, SeedableRng};

use crate::common::{
    ack_manager::AckManager,
    constants::{
        Channel, DisconnectReason, NONCE_DISCONNECT, PACKET_ID_ACK_ONLY, PACKET_ID_DISCONNECT,
        PACKET_ID_LATENCY_DISCOVERY, PACKET_ID_LATENCY_RESPONSE, PACKET_ID_LATENCY_RESPONSE_2,
    },
    encryption::Encryption,
    reliable::{channel::ReliableChannelId, ReliableChannels},
};

pub mod builder;

pub enum ClientCmd {
    Shutdown,
}

#[derive(Debug)]
pub enum ToSend {
    Message { channel: Channel, data: Vec<u8> },
    Disconnect { data: Vec<u8> },
}

#[derive(Debug)]
pub enum Received {
    Message {
        data: Vec<u8>,
    },
    Disconnect {
        reason: DisconnectReason,
        data: Vec<u8>,
    },
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

pub(crate) enum Event {
    SendNext,
    SendAckOnly,
    CheckForTimeout,
}

const RECV_TOKEN: Token = Token(0);
pub(crate) const WAKE_TOKEN: Token = Token(1);

pub struct ClientState {
    rng: SmallRng,
    cmds: crossbeam_channel::Receiver<ClientCmd>,
    socket: UdpSocket,
    poll: Poll,
    waker: Arc<Waker>,
    buf: [u8; 1201],
    events: BinaryHeap<TimedEvent>,

    encryption: Rc<Encryption>,
    reliable: ReliableChannels,
    ack_manager: AckManager,
    has_ack_event_queued: bool,
    ack_only_delay: Duration,

    to_send_rx: crossbeam_channel::Receiver<ToSend>,
    received_tx: crossbeam_channel::Sender<Received>,

    is_sending: bool,
    last_sent: Instant,
    last_received: Instant,
    send_cooldown: Duration,
    timeout_duration: Duration,
    last_latency_discovery: Option<(Instant, u32)>,

    latency: Duration,
    packet_resend_cooldown: Duration,
}

impl ClientState {
    pub fn new(
        cmds: crossbeam_channel::Receiver<ClientCmd>,
        socket: UdpSocket,
        poll: Poll,
        waker: Arc<Waker>,
        encryption: Rc<Encryption>,
        to_send_rx: crossbeam_channel::Receiver<ToSend>,
        received_tx: crossbeam_channel::Sender<Received>,
    ) -> Self {
        Self {
            rng: SmallRng::from_entropy(),
            cmds,
            socket,
            poll,
            waker,
            buf: [0; 1201],
            events: BinaryHeap::new(),
            encryption: encryption.clone(),
            reliable: ReliableChannels::new(encryption),
            ack_manager: AckManager::new(),
            has_ack_event_queued: false,
            ack_only_delay: Duration::from_millis(100),
            to_send_rx,
            received_tx,
            is_sending: false,
            last_sent: Instant::now(),
            last_received: Instant::now(),
            send_cooldown: Duration::from_micros(50),
            timeout_duration: Duration::from_secs(10),
            last_latency_discovery: None,

            latency: Duration::from_millis(100),
            packet_resend_cooldown: Duration::from_micros(125),
        }
    }

    pub fn run(&mut self) -> io::Result<()> {
        let mut events = Events::with_capacity(16);
        self.poll
            .registry()
            .register(&mut self.socket, RECV_TOKEN, Interest::READABLE)?;
        self.events.push(TimedEvent {
            deadline: Instant::now()
                + self.timeout_duration
                + Duration::from_millis(self.rng.gen_range(0..150)),
            event: Event::CheckForTimeout,
        });

        loop {
            //TODO: Better timeout handling and waking
            self.poll
                .poll(&mut events, Some(Duration::from_millis(10)))?;

            for event in events.iter() {
                match event.token() {
                    RECV_TOKEN => {
                        self.recv_all()?;
                    }
                    WAKE_TOKEN => {
                        if self.handle_to_send_rx() {
                            return Ok(());
                        }
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
            let size = match self.socket.recv(&mut self.buf) {
                Ok(r) => r,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break Ok(false);
                }
                Err(e) => return Err(e),
            };
            let should_shutdown = match (self.buf[0] & 0b1111_0000) >> 4 {
                PACKET_ID_ACK_ONLY => {
                    self.handle_ack_only(size);
                    false
                }
                7..=10 => {
                    for message in self.handle_payload(size) {
                        match self
                            .received_tx
                            .try_send(Received::Message { data: message })
                        {
                            Ok(_) => continue,
                            Err(TrySendError::Disconnected(_)) => return Ok(true),
                            _ => break,
                        }
                    }
                    false
                }
                PACKET_ID_LATENCY_DISCOVERY => self.handle_latency_discovery(size),
                PACKET_ID_LATENCY_RESPONSE_2 => self.handle_latency_response_2(size),
                PACKET_ID_DISCONNECT => self.handle_disconnect(size),
                _ => false,
            };
            if should_shutdown {
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
                ClientCmd::Shutdown => return true,
            }
        }
        false
    }

    fn handle_all_events(&mut self) -> Result<bool, io::Error> {
        let now = Instant::now();
        loop {
            if self.events.peek().map(|e| e.deadline > now).unwrap_or(true) {
                break;
            }
            let event = self.events.pop().unwrap().event;
            match event {
                Event::SendNext => self.send_next()?,
                Event::SendAckOnly => {
                    let size = self.build_ack_only();
                    if self.socket.send(&self.buf[..size]).is_err() {
                        return Ok(true);
                    }
                }
                Event::CheckForTimeout => {
                    if self.last_received.elapsed() > self.timeout_duration {
                        let _ = self.received_tx.send(Received::Disconnect {
                            reason: DisconnectReason::TimeOut,
                            data: Vec::new(),
                        });
                        return Ok(true);
                    }
                    self.events.push(TimedEvent {
                        deadline: Instant::now()
                            + self.timeout_duration
                            + Duration::from_millis(self.rng.gen_range(0..150)),
                        event: Event::CheckForTimeout,
                    });
                }
            }
        }
        Ok(false)
    }

    fn handle_to_send_rx(&mut self) -> bool {
        while let Ok(to_send) = self.to_send_rx.try_recv() {
            match to_send {
                ToSend::Message { channel, data } => {
                    match channel {
                        Channel::Reliable0 => {
                            self.reliable.push(ReliableChannelId::Reliable0, data)
                        }
                        Channel::Reliable1 => {
                            self.reliable.push(ReliableChannelId::Reliable1, data)
                        }
                        Channel::Reliable2 => {
                            self.reliable.push(ReliableChannelId::Reliable2, data)
                        }
                        Channel::Reliable3 => {
                            self.reliable.push(ReliableChannelId::Reliable3, data)
                        }
                    }
                    if !self.is_sending {
                        self.start_sending();
                    }
                }
                ToSend::Disconnect { data } => {
                    let size = self.build_disconnect(DisconnectReason::UserInitiated, &data);
                    for _ in 0..2 {
                        if self.socket.send(&self.buf[..size]).is_err() {
                            return true;
                        }
                        std::thread::sleep(Duration::from_millis(self.rng.gen_range(4..20)));
                    }
                    return true;
                }
            }
        }
        false
    }

    fn start_sending(&mut self) {
        self.is_sending = true;
        let deadline = self.last_sent + self.send_cooldown;
        self.events.push(TimedEvent {
            deadline,
            event: Event::SendNext,
        });
    }

    fn send_next(&mut self) -> Result<(), io::Error> {
        let result = self.reliable.next(&mut self.buf[0..1200]);
        match result {
            Ok(size) => {
                self.socket.send(&self.buf[0..size])?;
                self.events.push(TimedEvent {
                    deadline: Instant::now() + self.send_cooldown,
                    event: Event::SendNext,
                });
            }
            Err(Some(next_send)) => {
                self.events.push(TimedEvent {
                    deadline: Instant::now() + next_send,
                    event: Event::SendNext,
                });
            }
            Err(None) => {
                self.is_sending = false;
            }
        }
        Ok(())
    }

    fn build_ack_only(&mut self) -> usize {
        assert!(self.has_ack_event_queued);
        self.has_ack_event_queued = false;
        self.buf[0] = PACKET_ID_ACK_ONLY << 4;
        let reliable0_needs_ack = self.ack_manager.needs_ack(Channel::Reliable0);
        let reliable1_needs_ack = self.ack_manager.needs_ack(Channel::Reliable0);
        let reliable2_needs_ack = self.ack_manager.needs_ack(Channel::Reliable0);
        let reliable3_needs_ack = self.ack_manager.needs_ack(Channel::Reliable0);
        if reliable0_needs_ack {
            self.buf[0] |= 1 << 3;
        }
        if reliable1_needs_ack {
            self.buf[0] |= 1 << 2;
        }
        if reliable2_needs_ack {
            self.buf[0] |= 1 << 1;
        }
        if reliable3_needs_ack {
            self.buf[0] |= 1;
        }
        let mut b = &mut self.buf[2..];
        let mut offset = 2;
        if reliable0_needs_ack {
            let (oldest, field) = self.reliable.get_ack(ReliableChannelId::Reliable0);
            b.write_u8(field.len() as u8).unwrap();
            b.write_all(&oldest.to_le_bytes()[..5]).unwrap();
            b.write_all(field).unwrap();
            offset += 6 + field.len();
        }
        if reliable1_needs_ack {
            let (oldest, field) = self.reliable.get_ack(ReliableChannelId::Reliable1);
            b.write_u8(field.len() as u8).unwrap();
            b.write_all(&oldest.to_le_bytes()[..5]).unwrap();
            b.write_all(field).unwrap();
            offset += 6 + field.len();
        }
        if reliable2_needs_ack {
            let (oldest, field) = self.reliable.get_ack(ReliableChannelId::Reliable2);
            b.write_u8(field.len() as u8).unwrap();
            b.write_all(&oldest.to_le_bytes()[..5]).unwrap();
            b.write_all(field).unwrap();
            offset += 6 + field.len();
        }
        if reliable3_needs_ack {
            let (oldest, field) = self.reliable.get_ack(ReliableChannelId::Reliable3);
            b.write_u8(field.len() as u8).unwrap();
            b.write_all(&oldest.to_le_bytes()[..5]).unwrap();
            b.write_all(field).unwrap();
            offset += 6 + field.len();
        }
        let siphash = self.encryption.siphash_out(&self.buf[0..offset]);
        self.buf[offset..offset + 3].copy_from_slice(&siphash.to_le_bytes()[..3]);
        offset + 3
    }

    fn handle_ack_only(&mut self, size: usize) {
        if self.buf[size - 3..size]
            != self
                .encryption
                .siphash_in(&self.buf[0..size - 3])
                .to_le_bytes()[..3]
        {
            debug_assert!(false, "Ack Only siphash mismatch");
            return;
        }
        let contains_reliable0_ack = self.buf[0] & 0b0000_1000 != 0;
        let contains_reliable1_ack = self.buf[0] & 0b0000_0100 != 0;
        let contains_reliable2_ack = self.buf[0] & 0b0000_0010 != 0;
        let contains_reliable3_ack = self.buf[0] & 0b0000_0001 != 0;
        let mut offset = 2;
        if contains_reliable0_ack {
            let size = self.buf[offset];
            let mut oldest_bytes = [0u8; 8];
            oldest_bytes[..5].copy_from_slice(&self.buf[offset + 1..offset + 6]);
            let oldest = u64::from_le_bytes(oldest_bytes);
            let field = &self.buf[offset + 6..offset + 6 + size as usize];
            self.reliable
                .handle_ack(ReliableChannelId::Reliable0, oldest, field);
            offset += 5 + size as usize;
        }
        if contains_reliable1_ack {
            let size = self.buf[offset];
            let mut oldest_bytes = [0u8; 8];
            oldest_bytes[..5].copy_from_slice(&self.buf[offset + 1..offset + 6]);
            let oldest = u64::from_le_bytes(oldest_bytes);
            let field = &self.buf[offset + 6..offset + 6 + size as usize];
            self.reliable
                .handle_ack(ReliableChannelId::Reliable1, oldest, field);
            offset += 6 + size as usize;
        }
        if contains_reliable2_ack {
            let size = self.buf[offset];
            let mut oldest_bytes = [0u8; 8];
            oldest_bytes[..5].copy_from_slice(&self.buf[offset + 1..offset + 6]);
            let oldest = u64::from_le_bytes(oldest_bytes);
            let field = &self.buf[offset + 6..offset + 6 + size as usize];
            self.reliable
                .handle_ack(ReliableChannelId::Reliable2, oldest, field);
            offset += 6 + size as usize;
        }
        if contains_reliable3_ack {
            let size = self.buf[offset];
            let mut oldest_bytes = [0u8; 8];
            oldest_bytes[..5].copy_from_slice(&self.buf[offset + 1..offset + 6]);
            let oldest = u64::from_le_bytes(oldest_bytes);
            let field = &self.buf[offset + 6..offset + 6 + size as usize];
            self.reliable
                .handle_ack(ReliableChannelId::Reliable3, oldest, field);
            offset += 6 + size as usize;
        }
        self.last_received = Instant::now();
    }

    fn handle_payload(&mut self, size: usize) -> Vec<Vec<u8>> {
        match self.buf[0] >> 4 {
            x if x == ReliableChannelId::Reliable0.to_u8() => {
                self.ack_manager.handle_received(Channel::Reliable0);
                if !self.has_ack_event_queued {
                    self.has_ack_event_queued = true;
                    self.events.push(TimedEvent {
                        deadline: Instant::now() + self.ack_only_delay,
                        event: Event::SendAckOnly,
                    });
                }
                match self
                    .reliable
                    .handle(ReliableChannelId::Reliable0, &mut self.buf[..size])
                {
                    Ok(x) => {
                        self.last_received = Instant::now();
                        x
                    }
                    Err(_) => {
                        debug_assert!(false, "Reliable0 handle failed");
                        Vec::new()
                    }
                }
            }
            x if x == ReliableChannelId::Reliable1.to_u8() => {
                self.ack_manager.handle_received(Channel::Reliable1);
                if !self.has_ack_event_queued {
                    self.has_ack_event_queued = true;
                    self.events.push(TimedEvent {
                        deadline: Instant::now() + self.ack_only_delay,
                        event: Event::SendAckOnly,
                    });
                }
                match self
                    .reliable
                    .handle(ReliableChannelId::Reliable1, &mut self.buf[..size])
                {
                    Ok(x) => {
                        self.last_received = Instant::now();
                        x
                    }
                    Err(_) => {
                        debug_assert!(false, "Reliable1 handle failed");
                        Vec::new()
                    }
                }
            }
            x if x == ReliableChannelId::Reliable2.to_u8() => {
                self.ack_manager.handle_received(Channel::Reliable2);
                if !self.has_ack_event_queued {
                    self.has_ack_event_queued = true;
                    self.events.push(TimedEvent {
                        deadline: Instant::now() + self.ack_only_delay,
                        event: Event::SendAckOnly,
                    });
                }
                match self
                    .reliable
                    .handle(ReliableChannelId::Reliable2, &mut self.buf[..size])
                {
                    Ok(x) => {
                        self.last_received = Instant::now();
                        x
                    }
                    Err(_) => {
                        debug_assert!(false, "Reliable2 handle failed");
                        Vec::new()
                    }
                }
            }
            x if x == ReliableChannelId::Reliable3.to_u8() => {
                self.ack_manager.handle_received(Channel::Reliable3);
                if !self.has_ack_event_queued {
                    self.has_ack_event_queued = true;
                    self.events.push(TimedEvent {
                        deadline: Instant::now() + self.ack_only_delay,
                        event: Event::SendAckOnly,
                    });
                }
                match self
                    .reliable
                    .handle(ReliableChannelId::Reliable3, &mut self.buf[..size])
                {
                    Ok(x) => {
                        self.last_received = Instant::now();
                        x
                    }
                    Err(_) => {
                        debug_assert!(false, "Reliable3 handle failed");
                        Vec::new()
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    fn handle_disconnect(&mut self, size: usize) -> bool {
        if size < 17 {
            debug_assert!(false, "Disconnect packet too short");
            return false;
        }
        let tag: [u8; 16] = self.buf[size - 16..size].try_into().unwrap();
        if !self
            .encryption
            .decrypt(&NONCE_DISCONNECT, &[], &mut self.buf[1..size - 16], &tag)
        {
            debug_assert!(false, "Failed to decrypt disconnect packet");
            return false;
        }
        let Some(reason) = DisconnectReason::from_u8(self.buf[1]) else {
            debug_assert!(false, "Invalid disconnect reason");
            return false;
        };
        let payload;
        if size > 17 {
            payload = self.buf[2..size - 16].to_vec();
        } else {
            payload = Vec::new();
        }
        self.received_tx
            .send(Received::Disconnect {
                reason,
                data: payload,
            })
            .is_err()
    }

    fn build_disconnect(&mut self, reason: DisconnectReason, data: &[u8]) -> usize {
        assert!(data.len() <= 1182);
        self.buf[0] = PACKET_ID_DISCONNECT << 4;
        self.buf[1] = reason.as_u8();
        self.buf[2..2 + data.len()].copy_from_slice(data);
        let tag = self
            .encryption
            .encrypt(&NONCE_DISCONNECT, &[], &mut self.buf[1..2 + data.len()]);
        self.buf[2 + data.len()..2 + data.len() + 16].copy_from_slice(&tag);
        2 + data.len() + 16
    }

    /// Also sends the latency response packet
    fn handle_latency_discovery(&mut self, size: usize) -> bool {
        if size != 9 {
            debug_assert!(false, "Invalid latency discovery packet size");
            return false;
        }
        let siphash = self.encryption.siphash_in(&self.buf[1..5]);
        if siphash.to_le_bytes()[..4] != self.buf[5..9] {
            debug_assert!(false, "Invalid siphash in latency discovery packet");
            return false;
        }
        let salt_bytes: [u8; 4] = self.buf[1..5].try_into().unwrap();
        let salt = u32::from_le_bytes(salt_bytes);

        // Send latency response
        self.buf[0] = PACKET_ID_LATENCY_RESPONSE << 4;
        let siphash = self.encryption.siphash_out(&self.buf[1..9]);
        self.buf[9..13].copy_from_slice(&siphash.to_le_bytes()[..4]);
        self.last_latency_discovery = Some((Instant::now(), salt));
        self.last_received = Instant::now();
        if self.socket.send(&self.buf[..13]).is_err() {
            return true;
        }
        false
    }

    fn handle_latency_response_2(&mut self, size: usize) -> bool {
        let Some((last, salt)) = self.last_latency_discovery else {
            debug_assert!(
                false,
                "Received latency response 2 without sending discovery packet"
            );
            return false;
        };
        if size != 13 {
            debug_assert!(false, "Invalid latency response 2 packet size");
            return false;
        }
        let siphash = self.encryption.siphash_in(&self.buf[1..5]);
        if siphash.to_le_bytes()[..4] != self.buf[5..9] {
            debug_assert!(false, "Invalid siphash in latency discovery packet 0");
            return false;
        }
        if salt.to_le_bytes() != self.buf[1..5] {
            debug_assert!(false, "Invalid salt in latency response 2 packet");
            return false;
        }
        let siphash = self.encryption.siphash_in(&self.buf[1..9]);
        if siphash.to_le_bytes()[..4] != self.buf[9..13] {
            debug_assert!(false, "Invalid siphash in latency discovery packet 1");
            return false;
        }
        self.last_latency_discovery = None;
        self.set_latency(last.elapsed());
        self.last_received = Instant::now();
        false
    }

    fn set_latency(&mut self, latency: Duration) {
        self.latency = latency;
        self.packet_resend_cooldown = Duration::from_secs_f32(latency.as_secs_f32() * 1.25);
        self.reliable
            .set_packet_resend_cooldown(self.packet_resend_cooldown);
    }
}
