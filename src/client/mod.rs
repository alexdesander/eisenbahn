use std::{
    collections::BinaryHeap,
    io::{self, Write},
    ops::DerefMut,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use byteorder::WriteBytesExt;
use crossbeam_channel::{TryRecvError, TrySendError};
use mio::{Events, Interest, Poll, Token, Waker};
use rand::{rngs::SmallRng, Rng, SeedableRng};

use crate::common::{
    ack_manager::AckManager,
    congestion::CongestionController,
    constants::{
        Channel, DisconnectReason, NONCE_DISCONNECT, PACKET_ID_ACK_ONLY, PACKET_ID_DISCONNECT,
        PACKET_ID_LATENCY_DISCOVERY, PACKET_ID_LATENCY_RESPONSE, PACKET_ID_LATENCY_RESPONSE_2,
    },
    encryption::Encryption,
    reliable::{channel::ReliableChannelId, ReliableChannels},
    socket::Socket,
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
    socket: Socket,
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
    base_send_cooldown: u32,
    timeout_duration: Duration,
    last_latency_discovery: Option<(Instant, u32)>,

    latency: Duration,

    congestion_controller: CongestionController,
}

impl ClientState {
    pub fn new(
        cmds: crossbeam_channel::Receiver<ClientCmd>,
        socket: Socket,
        poll: Poll,
        waker: Arc<Waker>,
        encryption: Rc<Encryption>,
        to_send_rx: crossbeam_channel::Receiver<ToSend>,
        received_tx: crossbeam_channel::Sender<Received>,
    ) -> Self {
        let congestion_controller = CongestionController::new();

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
            ack_only_delay: Duration::from_millis(30),
            to_send_rx,
            received_tx,
            is_sending: false,
            last_sent: Instant::now(),
            last_received: Instant::now(),
            base_send_cooldown: congestion_controller.base_send_cooldown,
            timeout_duration: Duration::from_secs(10),
            last_latency_discovery: None,

            latency: congestion_controller.latest_latency,

            congestion_controller,
        }
    }

    pub fn run(&mut self) -> io::Result<()> {
        let mut events = Events::with_capacity(16);
        self.poll.registry().register(
            self.socket.inner().deref_mut(),
            RECV_TOKEN,
            Interest::READABLE,
        )?;
        self.events.push(TimedEvent {
            deadline: Instant::now()
                + self.timeout_duration
                + Duration::from_millis(self.rng.gen_range(0..150)),
            event: Event::CheckForTimeout,
        });

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

    pub fn send_cooldown(&self, packet_size: u32) -> Duration {
        Duration::from_millis((self.base_send_cooldown * packet_size) as u64)
    }

    fn start_sending(&mut self) {
        self.is_sending = true;
        let deadline = self.last_sent + Duration::from_micros(self.base_send_cooldown as u64 * 48);
        self.events.push(TimedEvent {
            deadline,
            event: Event::SendNext,
        });
    }

    fn send_next(&mut self) -> Result<(), io::Error> {
        if self.congestion_controller.packet_sent() {
            self.sync_congestion_controller();
        }
        let result = self
            .reliable
            .next(&mut self.congestion_controller, &mut self.buf[0..1200]);
        match result {
            Ok((size, congestion_updated)) => {
                if congestion_updated {
                    self.sync_congestion_controller();
                }
                self.socket.send(&self.buf[0..size])?;
                self.events.push(TimedEvent {
                    deadline: Instant::now() + self.send_cooldown(size as u32),
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
        self.reliable.build_ack_only(&mut self.encryption, &mut self.ack_manager, &mut self.buf[0..1200])
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
        let time_stamp_bytes: [u8; 4] = self.buf[1..5].try_into().unwrap();
        let time_stamp = u32::from_le_bytes(time_stamp_bytes);
        let real_time_stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        if time_stamp + 5 < real_time_stamp {
            return false;
        }

        // Send latency response
        self.buf[0] = PACKET_ID_LATENCY_RESPONSE << 4;
        let siphash = self.encryption.siphash_out(&self.buf[1..9]);
        self.buf[9..13].copy_from_slice(&siphash.to_le_bytes()[..4]);
        self.last_latency_discovery = Some((Instant::now(), time_stamp));
        self.last_received = Instant::now();
        if self.socket.send(&self.buf[..13]).is_err() {
            return true;
        }
        false
    }

    fn handle_latency_response_2(&mut self, size: usize) -> bool {
        let Some((last, time_stamp)) = self.last_latency_discovery else {
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
        if time_stamp.to_le_bytes() != self.buf[1..5] {
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
        if self.congestion_controller.update_latency(latency) {
            self.sync_congestion_controller();
        }
    }

    fn sync_congestion_controller(&mut self) {
        self.base_send_cooldown = self.congestion_controller.base_send_cooldown;
        self.latency = self.congestion_controller.latest_latency;
        self.reliable
            .sync_congestion_controller(&mut self.congestion_controller);
    }
}
