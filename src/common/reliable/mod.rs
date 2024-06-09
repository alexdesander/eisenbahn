use std::{rc::Rc, time::Duration};

use channel::{ReliableChannel, ReliableChannelId};

use super::encryption::Encryption;

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

    pub fn next(&mut self, buf: &mut [u8]) -> Result<usize, Option<Duration>> {
        let mut cool_downs = [None, None, None, None];
        for _ in 0..4 {
            self.round_robin = self.round_robin.round_robin();
            let result = self.channels[self.round_robin.to_index()].next(buf);
            match result {
                Ok(size) => return Ok(size),
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
}
