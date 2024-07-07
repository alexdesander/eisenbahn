use std::{cell::RefCell, io::Write, rc::Rc, time::Duration};

use byteorder::WriteBytesExt;
use channel::{ReliableChannel, ReliableChannelId};

use super::{
    ack_manager::AckManager,
    congestion::CongestionController,
    constants::{Channel, PACKET_ID_ACK_ONLY},
    encryption::Encryption,
};

mod assembler;
pub mod channel;
mod disassembler;

pub struct ReliableChannels {
    round_robin: ReliableChannelId,
    channels: [ReliableChannel; 4],
}

impl ReliableChannels {
    pub fn new(encryption: Rc<Encryption>) -> Self {
        Self {
            round_robin: ReliableChannelId::Reliable0,
            channels: [
                ReliableChannel::new(ReliableChannelId::Reliable0, encryption.clone()),
                ReliableChannel::new(ReliableChannelId::Reliable1, encryption.clone()),
                ReliableChannel::new(ReliableChannelId::Reliable2, encryption.clone()),
                ReliableChannel::new(ReliableChannelId::Reliable3, encryption),
            ],
        }
    }

    pub fn push(&mut self, channel: ReliableChannelId, message: Vec<u8>) {
        self.channels[channel.to_index()].push(message);
    }

    pub fn handle(
        &mut self,
        channel: ReliableChannelId,
        buf: &mut [u8],
    ) -> Result<Vec<Vec<u8>>, ()> {
        self.channels[channel.to_index()].handle(buf)
    }

    /// Returns (length of the packet, congestion controller updated) or the duration to wait until the next packet can be sent.
    pub fn next(
        &mut self,
        congestion_controller: &mut CongestionController,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Option<Duration>> {
        let mut cool_downs = [None, None, None, None];
        for _ in 0..4 {
            self.round_robin = self.round_robin.round_robin();
            let result =
                self.channels[self.round_robin.to_index()].next(congestion_controller, buf);
            match result {
                Ok((size, congestion_updated)) => return Ok((size, congestion_updated)),
                Err(Some(cool_down)) => cool_downs[self.round_robin.to_index()] = Some(cool_down),
                Err(None) => continue,
            }
        }
        Err(cool_downs.iter().filter_map(|x| *x).min())
    }

    pub fn get_ack(&self, channel: ReliableChannelId) -> (u64, &[u8]) {
        self.channels[channel.to_index()].get_ack()
    }

    /// TODO: Optimize this
    pub fn handle_ack(&mut self, channel: ReliableChannelId, oldest: u64, ack_field: &[u8]) {
        self.channels[channel.to_index()].ack(oldest, ack_field);
    }

    pub fn sync_congestion_controller(&mut self, congestion_controller: &mut CongestionController) {
        for channel in self.channels.iter_mut() {
            channel.sync_congestion_controller(congestion_controller);
        }
    }

    pub fn build_ack_only(
        &mut self,
        encryption: &Encryption,
        ack_manager: &mut AckManager,
        buf: &mut [u8],
    ) -> usize {
        buf[0] = PACKET_ID_ACK_ONLY << 4;
        let reliable0_needs_ack = ack_manager.needs_ack(Channel::Reliable0);
        let reliable1_needs_ack = ack_manager.needs_ack(Channel::Reliable1);
        let reliable2_needs_ack = ack_manager.needs_ack(Channel::Reliable2);
        let reliable3_needs_ack = ack_manager.needs_ack(Channel::Reliable3);
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
        let reliable0_ack = self.get_ack(ReliableChannelId::Reliable0);
        let reliable1_ack = self.get_ack(ReliableChannelId::Reliable1);
        let reliable2_ack = self.get_ack(ReliableChannelId::Reliable2);
        let reliable3_ack = self.get_ack(ReliableChannelId::Reliable3);

        let mut sum_ack_len = 0;
        let mut amount_channels = 0;
        if reliable0_needs_ack {
            sum_ack_len += reliable0_ack.1.len();
            amount_channels += 1;
        }
        if reliable1_needs_ack {
            sum_ack_len += reliable1_ack.1.len();
            amount_channels += 1;
        }
        if reliable2_needs_ack {
            sum_ack_len += reliable2_ack.1.len();
            amount_channels += 1;
        }
        if reliable3_needs_ack {
            sum_ack_len += reliable3_ack.1.len();
            amount_channels += 1;
        }
        let available_ack_len = 1195 - 6 * amount_channels;
        let mut max_ack_len_per_channel = available_ack_len;
        if sum_ack_len > available_ack_len {
            max_ack_len_per_channel = available_ack_len / amount_channels;
        }

        let mut b = &mut buf[2..];
        let mut offset = 2;
        if reliable0_needs_ack {
            let (oldest, ack_field) = reliable0_ack;
            b.write_u8(ack_field.len() as u8).unwrap();
            b.write_all(&oldest.to_le_bytes()[..5]).unwrap();
            let len = ack_field.len().min(max_ack_len_per_channel);
            b.write_all(&ack_field[..len]).unwrap();
            offset += 6 + len;
        }
        if reliable1_needs_ack {
            let (oldest, ack_field) = reliable1_ack;
            b.write_u8(ack_field.len() as u8).unwrap();
            b.write_all(&oldest.to_le_bytes()[..5]).unwrap();
            let len = ack_field.len().min(max_ack_len_per_channel);
            b.write_all(&ack_field[..len]).unwrap();
            offset += 6 + len;
        }
        if reliable2_needs_ack {
            let (oldest, ack_field) = reliable2_ack;
            b.write_u8(ack_field.len() as u8).unwrap();
            b.write_all(&oldest.to_le_bytes()[..5]).unwrap();
            let len = ack_field.len().min(max_ack_len_per_channel);
            b.write_all(&ack_field[..len]).unwrap();
            offset += 6 + len;
        }
        if reliable3_needs_ack {
            let (oldest, ack_field) = reliable3_ack;
            b.write_u8(ack_field.len() as u8).unwrap();
            b.write_all(&oldest.to_le_bytes()[..5]).unwrap();
            let len = ack_field.len().min(max_ack_len_per_channel);
            b.write_all(&ack_field[..len]).unwrap();
            offset += 6 + len;
        }
        let siphash = encryption.siphash_out(&buf[0..offset]);
        buf[offset..offset + 3].copy_from_slice(&siphash.to_le_bytes()[..3]);
        offset + 3
    }
}
