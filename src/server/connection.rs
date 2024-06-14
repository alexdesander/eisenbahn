use std::{
    collections::BinaryHeap,
    io::Write,
    net::SocketAddr,
    rc::Rc,
    time::{Duration, Instant, SystemTime},
};

use byteorder::WriteBytesExt;

use crate::{
    common::{
        ack_manager::AckManager,
        encryption::Encryption,
        reliable::{channel::ReliableChannelId, ReliableChannels},
    },
    server::PACKET_ID_ACK_ONLY,
};

use super::{
    Channel, DisconnectReason, Event, TimedEvent, NONCE_DISCONNECT, PACKET_ID_DISCONNECT,
    PACKET_ID_LATENCY_DISCOVERY, PACKET_ID_LATENCY_RESPONSE_2,
};

pub struct Connection {
    addr: SocketAddr,
    player_name: String,
    encryption: Rc<Encryption>,
    reliable: ReliableChannels,
    ack_manager: AckManager,
    // Whether or not an ack event is queued in the timed events binary heap.
    has_ack_event_queued: bool,
    ack_only_delay: Duration,
    is_currently_sending: bool,
    send_cool_down: Duration,
    last_received: Instant,
    last_latency_discovery: Option<(Instant, u32)>,

    pub latency: Duration,
    packet_resend_cooldown: Duration,
}

impl Connection {
    pub fn new(addr: SocketAddr, player_name: String, encryption: Rc<Encryption>) -> Self {
        Self {
            addr,
            player_name,
            encryption: encryption.clone(),
            reliable: ReliableChannels::new(encryption),
            ack_manager: AckManager::new(),
            has_ack_event_queued: false,
            ack_only_delay: Duration::from_millis(30),
            is_currently_sending: false,
            send_cool_down: Duration::from_micros(1),
            last_received: Instant::now(),
            last_latency_discovery: None,
            // TODO: Discover latency at the connection building
            latency: Duration::from_millis(100),
            packet_resend_cooldown: Duration::from_millis(125),
        }
    }

    pub fn is_currently_sending(&self) -> bool {
        self.is_currently_sending
    }

    pub fn send_cool_down(&self) -> Duration {
        self.send_cool_down
    }

    pub fn last_received(&self) -> Instant {
        self.last_received
    }

    pub fn push(&mut self, channel: Channel, message: Vec<u8>) {
        match channel {
            Channel::Reliable0 => self.reliable.push(ReliableChannelId::Reliable0, message),
            Channel::Reliable1 => self.reliable.push(ReliableChannelId::Reliable1, message),
            Channel::Reliable2 => self.reliable.push(ReliableChannelId::Reliable2, message),
            Channel::Reliable3 => self.reliable.push(ReliableChannelId::Reliable3, message),
        }
    }

    pub fn start_sending(&mut self, events: &mut BinaryHeap<TimedEvent>) {
        assert!(!self.is_currently_sending);
        self.is_currently_sending = true;
        events.push(TimedEvent {
            deadline: Instant::now() + self.send_cool_down,
            event: Event::Send(self.addr),
        });
    }

    pub fn stop_sending(&mut self) {
        self.is_currently_sending = false;
    }

    pub fn handle_payload_packet(
        &mut self,
        buf: &mut [u8],
        events: &mut BinaryHeap<TimedEvent>,
    ) -> Vec<Vec<u8>> {
        match buf[0] >> 4 {
            x if x == ReliableChannelId::Reliable0.to_u8() => {
                self.ack_manager.handle_received(Channel::Reliable0);
                if !self.has_ack_event_queued {
                    self.has_ack_event_queued = true;
                    events.push(TimedEvent {
                        deadline: Instant::now() + self.ack_only_delay,
                        event: Event::SendAckOnly(self.addr),
                    });
                }
                match self.reliable.handle(ReliableChannelId::Reliable0, buf) {
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
                    events.push(TimedEvent {
                        deadline: Instant::now() + self.ack_only_delay,
                        event: Event::SendAckOnly(self.addr),
                    });
                }
                match self.reliable.handle(ReliableChannelId::Reliable1, buf) {
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
                    events.push(TimedEvent {
                        deadline: Instant::now() + self.ack_only_delay,
                        event: Event::SendAckOnly(self.addr),
                    });
                }
                match self.reliable.handle(ReliableChannelId::Reliable2, buf) {
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
                    events.push(TimedEvent {
                        deadline: Instant::now() + self.ack_only_delay,
                        event: Event::SendAckOnly(self.addr),
                    });
                }
                match self.reliable.handle(ReliableChannelId::Reliable3, buf) {
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

    pub fn handle_ack_only(&mut self, buf: &mut [u8]) {
        let size = buf.len();
        if buf[size - 3..size] != self.encryption.siphash_in(&buf[0..size - 3]).to_le_bytes()[..3] {
            debug_assert!(false, "Ack Only siphash mismatch");
            return;
        }
        let contains_reliable0_ack = buf[0] & 0b0000_1000 != 0;
        let contains_reliable1_ack = buf[0] & 0b0000_0100 != 0;
        let contains_reliable2_ack = buf[0] & 0b0000_0010 != 0;
        let contains_reliable3_ack = buf[0] & 0b0000_0001 != 0;
        let mut offset = 2;
        if contains_reliable0_ack {
            let size = buf[offset];
            let mut oldest_bytes = [0u8; 8];
            oldest_bytes[..5].copy_from_slice(&buf[offset + 1..offset + 6]);
            let oldest = u64::from_le_bytes(oldest_bytes);
            let field = &buf[offset + 6..offset + 6 + size as usize];
            self.reliable
                .handle_ack(ReliableChannelId::Reliable0, oldest, field);
            offset += 5 + size as usize;
        }
        if contains_reliable1_ack {
            let size = buf[offset];
            let mut oldest_bytes = [0u8; 8];
            oldest_bytes[..5].copy_from_slice(&buf[offset + 1..offset + 6]);
            let oldest = u64::from_le_bytes(oldest_bytes);
            let field = &buf[offset + 6..offset + 6 + size as usize];
            self.reliable
                .handle_ack(ReliableChannelId::Reliable1, oldest, field);
            offset += 6 + size as usize;
        }
        if contains_reliable2_ack {
            let size = buf[offset];
            let mut oldest_bytes = [0u8; 8];
            oldest_bytes[..5].copy_from_slice(&buf[offset + 1..offset + 6]);
            let oldest = u64::from_le_bytes(oldest_bytes);
            let field = &buf[offset + 6..offset + 6 + size as usize];
            self.reliable
                .handle_ack(ReliableChannelId::Reliable2, oldest, field);
            offset += 6 + size as usize;
        }
        if contains_reliable3_ack {
            let size = buf[offset];
            let mut oldest_bytes = [0u8; 8];
            oldest_bytes[..5].copy_from_slice(&buf[offset + 1..offset + 6]);
            let oldest = u64::from_le_bytes(oldest_bytes);
            let field = &buf[offset + 6..offset + 6 + size as usize];
            self.reliable
                .handle_ack(ReliableChannelId::Reliable3, oldest, field);
            offset += 6 + size as usize;
        }
        self.last_received = Instant::now();
    }

    /// Returns the reason and payload if the disconnect packet is valid.
    pub fn handle_disconnect(&mut self, buf: &mut [u8]) -> Option<(DisconnectReason, Vec<u8>)> {
        let len = buf.len();
        if len < 17 {
            debug_assert!(false, "Disconnect packet too short");
            return None;
        }
        let tag: [u8; 16] = buf[len - 16..len].try_into().unwrap();
        if !self
            .encryption
            .decrypt(&NONCE_DISCONNECT, &[], &mut buf[1..len - 16], &tag)
        {
            debug_assert!(false, "Failed to decrypt disconnect packet");
            return None;
        }
        let Some(reason) = DisconnectReason::from_u8(buf[1]) else {
            debug_assert!(false, "Invalid disconnect reason");
            return None;
        };
        let payload;
        if len > 17 {
            payload = buf[2..len - 16].to_vec();
        } else {
            payload = Vec::new();
        }
        Some((reason, payload))
    }

    pub fn build_ack_only(&mut self, buf: &mut [u8], events: &mut BinaryHeap<TimedEvent>) -> usize {
        self.has_ack_event_queued = false;
        buf[0] = PACKET_ID_ACK_ONLY << 4;
        let reliable0_needs_ack = self.ack_manager.needs_ack(Channel::Reliable0);
        let reliable1_needs_ack = self.ack_manager.needs_ack(Channel::Reliable0);
        let reliable2_needs_ack = self.ack_manager.needs_ack(Channel::Reliable0);
        let reliable3_needs_ack = self.ack_manager.needs_ack(Channel::Reliable0);
        if reliable0_needs_ack {
            buf[0] |= 1 << 3;
        }
        if reliable1_needs_ack {
            buf[0] |= 1 << 2;
        }
        if reliable2_needs_ack {
            buf[0] |= 1 << 1;
        }
        if reliable3_needs_ack {
            buf[0] |= 1;
        }
        buf[1] = 0;
        let mut b = &mut buf[2..];
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
        let siphash = self.encryption.siphash_out(&buf[0..offset]);
        buf[offset..offset + 3].copy_from_slice(&siphash.to_le_bytes()[..3]);
        offset + 3
    }

    pub fn build_next_payload(&mut self, buf: &mut [u8]) -> Result<usize, Option<Duration>> {
        self.reliable.next(buf)
    }

    pub fn build_disconnect(
        &mut self,
        buf: &mut [u8],
        reason: DisconnectReason,
        data: &[u8],
    ) -> usize {
        assert!(data.len() <= 1182);
        buf[0] = PACKET_ID_DISCONNECT << 4;
        buf[1] = reason.as_u8();
        buf[2..2 + data.len()].copy_from_slice(data);
        let tag = self
            .encryption
            .encrypt(&NONCE_DISCONNECT, &[], &mut buf[1..2 + data.len()]);
        buf[2 + data.len()..2 + data.len() + 16].copy_from_slice(&tag);
        2 + data.len() + 16
    }

    pub fn build_latency_discovery(&mut self, buf: &mut [u8]) -> usize {
        buf[0] = PACKET_ID_LATENCY_DISCOVERY << 4;
        // Truncate to u32, doesn't matter because we only look at the difference of timestamps
        let time_stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        buf[1..5].copy_from_slice(&time_stamp.to_le_bytes());
        let siphash = self.encryption.siphash_out(&buf[1..5]);
        buf[5..9].copy_from_slice(&siphash.to_le_bytes()[..4]);
        self.last_latency_discovery = Some((Instant::now(), time_stamp));
        9
    }

    /// Also builds latency response 2
    pub fn handle_latency_response(&mut self, buf: &mut [u8]) -> Option<usize> {
        // Calculate latency
        let len = buf.len();
        if len != 13 {
            debug_assert!(false, "Invalid latency response length");
            return None;
        }
        let Some((last, time_stamp)) = self.last_latency_discovery else {
            debug_assert!(false, "No latency discovery sent before latency response");
            return None;
        };
        if buf[1..5] != time_stamp.to_le_bytes() {
            debug_assert!(false, "Invalid latency response salt");
            return None;
        }
        let siphash = self.encryption.siphash_out(&buf[1..5]);
        if siphash.to_le_bytes()[..4] != buf[5..9] {
            debug_assert!(false, "Invalid latency response siphash 0");
            return None;
        }
        let siphash = self.encryption.siphash_in(&buf[1..9]);
        if siphash.to_le_bytes()[..4] != buf[9..13] {
            debug_assert!(false, "Invalid latency response siphash 1");
            return None;
        }
        self.set_latency(last.elapsed());
        self.last_received = Instant::now();

        // Build latency response 2
        buf[0] = PACKET_ID_LATENCY_RESPONSE_2 << 4;
        let siphash = self.encryption.siphash_out(&buf[1..9]);
        buf[9..13].copy_from_slice(&siphash.to_le_bytes()[..4]);
        self.last_latency_discovery = None;
        Some(13)
    }

    fn set_latency(&mut self, latency: Duration) {
        self.latency = latency;
    }
}
