use std::{
    collections::BinaryHeap,
    io::Write,
    net::SocketAddr,
    rc::Rc,
    time::{Duration, Instant},
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

use super::{Channel, Event, TimedEvent};

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
            ack_only_delay: Duration::from_millis(100),
            is_currently_sending: false,
            send_cool_down: Duration::from_micros(50),
        }
    }

    pub fn is_currently_sending(&self) -> bool {
        self.is_currently_sending
    }

    pub fn send_cool_down(&self) -> Duration {
        self.send_cool_down
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

    pub fn handle_packet(
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
                self.reliable.handle(ReliableChannelId::Reliable0, buf)
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
                self.reliable.handle(ReliableChannelId::Reliable1, buf)
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
                self.reliable.handle(ReliableChannelId::Reliable2, buf)
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
                self.reliable.handle(ReliableChannelId::Reliable3, buf)
            }
            _ => unreachable!(),
        }
    }

    pub fn handle_ack_only(&mut self, buf: &mut [u8]) {
        let size = buf.len();
        if buf[size - 3..size] != self.encryption.siphash(&buf[0..size - 3]).to_le_bytes()[..3] {
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
    }

    pub fn build_ack_only(&mut self, buf: &mut [u8], events: &mut BinaryHeap<TimedEvent>) -> usize {
        assert!(self.has_ack_event_queued);
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
        let siphash = self.encryption.siphash(&buf[0..offset]);
        buf[offset..offset + 3].copy_from_slice(&siphash.to_le_bytes()[..3]);
        offset + 3
    }

    pub fn build_next_payload(&mut self, buf: &mut [u8]) -> Result<usize, Option<Duration>> {
        self.reliable.next(buf)
    }
}
