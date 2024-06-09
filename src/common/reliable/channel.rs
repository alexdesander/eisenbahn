use std::{
    collections::BinaryHeap,
    rc::Rc,
    time::{Duration, Instant},
};

use ahash::HashSet;

use crate::common::encryption::Encryption;

use super::{assembler::PacketAssembler, disassembler::MessageDisassembler};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReliableChannelId {
    Reliable0 = 7,
    Reliable1 = 8,
    Reliable2 = 9,
    Reliable3 = 10,
}

impl ReliableChannelId {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            7 => Some(ReliableChannelId::Reliable0),
            8 => Some(ReliableChannelId::Reliable1),
            9 => Some(ReliableChannelId::Reliable2),
            10 => Some(ReliableChannelId::Reliable3),
            _ => None,
        }
    }

    pub fn to_index(&self) -> usize {
        match self {
            ReliableChannelId::Reliable0 => 0,
            ReliableChannelId::Reliable1 => 1,
            ReliableChannelId::Reliable2 => 2,
            ReliableChannelId::Reliable3 => 3,
        }
    }

    pub fn from_index(index: usize) -> Self {
        match index {
            0 => ReliableChannelId::Reliable0,
            1 => ReliableChannelId::Reliable1,
            2 => ReliableChannelId::Reliable2,
            3 => ReliableChannelId::Reliable3,
            _ => unreachable!(),
        }
    }

    pub fn round_robin(&self) -> Self {
        match self {
            ReliableChannelId::Reliable0 => ReliableChannelId::Reliable1,
            ReliableChannelId::Reliable1 => ReliableChannelId::Reliable2,
            ReliableChannelId::Reliable2 => ReliableChannelId::Reliable3,
            ReliableChannelId::Reliable3 => ReliableChannelId::Reliable0,
        }
    }
}

/// Represents a fragment that is currently in flight.
/// In flight means that the fragment is being sent/has been sent, but has not been acknowledged yet.
struct FragmentInFlight {
    last_sent: Option<Instant>,
    id: u64,
    encrypted_data: Vec<u8>,
    tag: Option<[u8; 16]>,
}

impl PartialEq for FragmentInFlight {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for FragmentInFlight {}

impl PartialOrd for FragmentInFlight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match other.last_sent.cmp(&self.last_sent) {
            std::cmp::Ordering::Equal => Some(other.id.cmp(&self.id)),
            x => Some(x),
        }
    }
}

impl Ord for FragmentInFlight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match other.last_sent.cmp(&self.last_sent) {
            std::cmp::Ordering::Equal => other.id.cmp(&self.id),
            x => x,
        }
    }
}

pub struct ReliableChannel {
    id: ReliableChannelId,
    encryption: Rc<Encryption>,
    assembler: PacketAssembler,
    disassembler: MessageDisassembler,

    next_id: u64,
    max_in_flight: usize,
    in_flight: BinaryHeap<FragmentInFlight>,
    per_packet_cooldown: Duration,
    acked: HashSet<u64>,
    acked_cutoff: u64,
}

impl ReliableChannel {
    pub fn new(id: ReliableChannelId, encryption: Rc<Encryption>) -> Self {
        Self {
            id,
            encryption: encryption.clone(),
            assembler: PacketAssembler::new(32),
            disassembler: MessageDisassembler::new(),

            next_id: 0,
            max_in_flight: 32,
            in_flight: BinaryHeap::new(),
            per_packet_cooldown: Duration::from_millis(120),
            acked: HashSet::default(),
            acked_cutoff: 0,
        }
    }

    pub fn set_max_in_flight(&mut self, max_in_flight: usize) {
        assert!(max_in_flight > 0 && max_in_flight < 255 * 8 + 1);
        self.max_in_flight = max_in_flight;
        self.assembler.set_max_in_flight(max_in_flight);
    }

    pub fn get_ack(&self) -> (u64, &[u8]) {
        self.assembler.get_ack()
    }

    pub fn push(&mut self, message: Vec<u8>) {
        self.disassembler.insert(message);
    }

    /// TODO: Optimize this
    pub fn ack(&mut self, oldest_unacked: u64, ack_bitfield: &[u8]) {
        for i in self.acked_cutoff..oldest_unacked {
            self.acked.remove(&i);
            self.acked_cutoff += 1;
        }
        for i in 0..ack_bitfield.len() as u64 {
            for j in 0..8 as u64 {
                if ack_bitfield[i as usize] & (1 << (7 - j)) != 0 {
                    self.acked.insert(oldest_unacked + i * 8 + j + 1);
                }
            }
        }
    }

    /// Fully builds a packet to be sent.
    /// Returns the length of the packet or the duration to wait until the next packet can be sent.
    pub fn next(&mut self, buf: &mut [u8]) -> Result<usize, Option<Duration>> {
        // Remove acked packets
        self.in_flight.retain(|in_flight| {
            if in_flight.id < self.acked_cutoff {
                assert!(!self.acked.remove(&in_flight.id));
            }
            !(in_flight.id < self.acked_cutoff || self.acked.contains(&in_flight.id))
        });

        // Get new in flights
        let mut target_size = 1200 - 6;
        if !self.encryption.is_none() {
            target_size -= 16;
        }
        target_size -= 1 + 5 + (self.max_in_flight + 7) / 8 + 3;
        for _ in 0..(self.max_in_flight - self.in_flight.len()) {
            let Some(mut fragment) = self.disassembler.next(target_size) else {
                break;
            };
            // Encrypt
            let mut tag = None;
            if !self.encryption.is_none() {
                let mut nonce = [self.id.to_u8(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                nonce[7..].copy_from_slice(&self.next_id.to_le_bytes()[..5]);
                tag = Some(self.encryption.encrypt(&nonce, &[], &mut fragment));
            }
            self.in_flight.push(FragmentInFlight {
                last_sent: None,
                id: self.next_id,
                encrypted_data: fragment,
                tag,
            });
            self.next_id += 1;
        }

        // Return the next fragment to send or the wait time until the next fragment can be sent
        if let Some(in_flight) = self.in_flight.peek() {
            let now = Instant::now();
            if in_flight.last_sent.map_or(true, |l| {
                now.saturating_duration_since(l) > self.per_packet_cooldown
            }) {
                let (oldest_unacked, ack_bitfield) = self.assembler.get_ack();
                let mut fragment = self.in_flight.pop().unwrap();
                let ack_size = ((self.max_in_flight + 7) / 8)
                    .min(1200 - fragment.encrypted_data.len() - 6 - 1 - 5 - 3 - 16);
                buf[0] = self.id.to_u8() << 4;
                buf[0] |= 0b0000_1000;
                buf[1..6].copy_from_slice(&fragment.id.to_le_bytes()[..5]);
                assert!(ack_size <= 255, "Ack size too large");
                buf[6] = ack_size as u8;
                buf[7..12].copy_from_slice(&oldest_unacked.to_le_bytes()[..5]);
                buf[12..12 + ack_size].copy_from_slice(&ack_bitfield[..ack_size]);
                let siphash = self.encryption.siphash(&buf[6..12 + ack_size]);
                buf[12 + ack_size..15 + ack_size].copy_from_slice(&siphash.to_le_bytes()[..3]);
                let payload_offset = 15 + ack_size;

                buf[payload_offset..payload_offset + fragment.encrypted_data.len()]
                    .copy_from_slice(&fragment.encrypted_data);
                let mut size = payload_offset + fragment.encrypted_data.len();
                if let Some(tag) = fragment.tag {
                    buf[size..size + 16].copy_from_slice(&tag);
                    size += 16;
                }
                fragment.last_sent = Some(now);
                self.in_flight.push(fragment);
                return Ok(size);
            } else {
                return Err(Some(self.per_packet_cooldown.saturating_sub(
                    now.saturating_duration_since(in_flight.last_sent.unwrap()),
                )));
            }
        }
        return Err(None);
    }

    /// Handles an incoming packet.
    /// The buf must contain the entire packet (from packet type id to end of packet).
    /// Returns assembled messages in order.
    pub fn handle(&mut self, buf: &mut [u8]) -> Result<Vec<Vec<u8>>, ()> {
        debug_assert!(buf[0] & 0b1111_0000 == self.id.to_u8() << 4);
        let mut id_bytes = [0u8; 8];
        id_bytes[..5].copy_from_slice(&buf[1..6]);
        let id = u64::from_le_bytes(id_bytes);
        let mut offset = 6;
        if buf[0] & 0b0000_1000 > 0 {
            let ack_size = buf[6] as usize;

            // Check siphash of ack
            let ack_siphash = &buf[12 + ack_size..15 + ack_size];
            if ack_siphash
                != &self
                    .encryption
                    .siphash(&buf[6..12 + ack_size])
                    .to_le_bytes()[..3]
            {
                // In release mode, we just ignore the ack.
                debug_assert!(false, "Invalid siphash");
                return Err(());
            }

            let mut oldest_unacked_bytes = [0u8; 8];
            oldest_unacked_bytes[..5].copy_from_slice(&buf[7..12]);
            let oldest_unacked = u64::from_le_bytes(oldest_unacked_bytes);
            self.ack(oldest_unacked, &buf[12..12 + ack_size]);
            offset += 9 + ack_size;
        }
        if self.encryption.is_none() {
            if self.assembler.needs_fragment(id) {
                self.assembler.add_fragment(id, buf[offset..].to_vec());
            }
        } else {
            let mut data = buf[offset..buf.len() - 16].to_vec();
            let mut nonce = [self.id.to_u8(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            nonce[7..].copy_from_slice(&id_bytes[..5]);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&buf[buf.len() - 16..]);
            if !self.encryption.decrypt(&nonce, &[], &mut data, &tag) {
                // In release mode, we just ignore the packet.
                debug_assert!(false, "Failed to decrypt packet");
                return Err(());
            }
            if self.assembler.needs_fragment(id) {
                self.assembler.add_fragment(id, data);
            }
        }

        Ok(self.assembler.assemble())
    }
}
