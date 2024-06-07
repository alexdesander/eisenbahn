use bitvec::{order, vec::BitVec};
use integer_encoding::*;
use std::{collections::BinaryHeap, num::NonZeroUsize};

struct Fragment {
    id: u64, // u40
    data: Vec<u8>,
    read_offset: usize,
}

impl PartialEq for Fragment {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Fragment {}

impl PartialOrd for Fragment {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        other.id.partial_cmp(&self.id)
    }
}

impl Ord for Fragment {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.id.cmp(&self.id)
    }
}

pub struct PacketAssembler {
    max_in_flight: usize,
    lowest_needed: u64,
    ack_bitfield: BitVec<u8, order::Msb0>,

    available: BinaryHeap<Fragment>,

    /// The message that is currently being assembled
    message: Vec<u8>,
    still_needed: Option<NonZeroUsize>,
}

impl PacketAssembler {
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            max_in_flight,
            lowest_needed: 0,
            ack_bitfield: BitVec::repeat(false, max_in_flight - 1),
            available: BinaryHeap::new(),
            message: Vec::new(),
            still_needed: None,
        }
    }

    pub fn set_max_in_flight(&mut self, max_in_flight: usize) {
        self.max_in_flight = max_in_flight;
        if self.ack_bitfield.len() < max_in_flight - 1 {
            self.ack_bitfield.resize(max_in_flight - 1, false);
        }
    }

    pub fn get_ack(&self) -> (u64, &[u8]) {
        (self.lowest_needed, &self.ack_bitfield.as_raw_slice())
    }

    pub fn needs_fragment(&self, id: u64) -> bool {
        if id >= self.lowest_needed + self.max_in_flight as u64 {
            return false;
        }
        if id < self.lowest_needed {
            return false;
        }
        if id == self.lowest_needed {
            return true;
        } else {
            return !self.ack_bitfield[(id - self.lowest_needed) as usize - 1];
        }
    }

    /// Make sure to call needs_fragment before calling this function.
    pub fn add_fragment(&mut self, id: u64, data: Vec<u8>) {
        debug_assert!(self.needs_fragment(id));
        if id == self.lowest_needed {
            let leading_ones = self.ack_bitfield.leading_ones();
            self.lowest_needed += 1 + leading_ones as u64;
            self.ack_bitfield.shift_left(1 + leading_ones);
        } else {
            self.ack_bitfield
                .set((id - self.lowest_needed) as usize - 1, true);
        }
        self.available.push(Fragment {
            id,
            data,
            read_offset: 0,
        });
    }

    /// Returns fully reassembled messages, if none are available, returns an empty vec
    pub fn assemble(&mut self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        loop {
            let mut available = match self.available.peek_mut() {
                Some(x) => x,
                None => break,
            };
            if available.id >= self.lowest_needed {
                break;
            }
            if available.data.len() == available.read_offset {
                drop(available);
                self.available.pop();
                continue;
            }
            let payload_size = available.data.len() - available.read_offset;
            match self.still_needed {
                Some(still_needed) if still_needed.get() > payload_size => {
                    self.message
                        .extend_from_slice(&available.data[available.read_offset..]);
                    self.still_needed = NonZeroUsize::new(still_needed.get() - payload_size);
                    drop(available);
                    self.available.pop();
                    continue;
                }
                Some(still_needed) if still_needed.get() < payload_size => {
                    self.message.extend_from_slice(
                        &available.data
                            [available.read_offset..available.read_offset + still_needed.get()],
                    );
                    available.read_offset += still_needed.get();
                    self.still_needed = None;
                    result.push(std::mem::take(&mut self.message));
                    continue;
                }
                Some(_) => {
                    drop(available);
                    let available = self.available.pop().unwrap();
                    self.message
                        .extend_from_slice(&available.data[available.read_offset..]);
                    self.still_needed = None;
                    result.push(std::mem::take(&mut self.message));
                    continue;
                }
                None => {
                    let (still_needed, start_offset) =
                        match u32::decode_var(&available.data[available.read_offset..]) {
                            Some(x) => x,
                            None => unreachable!("Varint decoding failed"),
                        };
                    self.still_needed = NonZeroUsize::new(still_needed as usize);
                    self.message = Vec::with_capacity(still_needed as usize);
                    available.read_offset += start_offset;
                    continue;
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::SmallRng, Rng, SeedableRng};

    use crate::common::reliable::{assembler::PacketAssembler, disassembler::MessageDisassembler};

    #[test]
    fn disassembling_and_assembling() {
        let mut disassembler = MessageDisassembler::new();
        let mut assembler = PacketAssembler::new(1024);
        let mut rng = SmallRng::from_entropy();

        let mut msgs = Vec::new();
        for _ in 0..50000 {
            let size = rng.gen_range(1..5000);
            let mut msg: Vec<u8> = Vec::with_capacity(size);
            for _ in 0..size {
                msg.push(rng.gen());
            }
            msgs.push(msg);
        }

        for msg in msgs.iter() {
            disassembler.insert(msg.clone());
        }

        let mut result: Vec<Vec<u8>> = Vec::new();
        let mut i = 0;
        while let Some(payload) = disassembler.next(rng.gen_range(5..2000)) {
            assembler.add_fragment(i, payload);
            i += 1;
            if rng.gen_bool(0.01) {
                result.append(&mut assembler.assemble());
            }
        }
        result.append(&mut assembler.assemble());

        assert_eq!(msgs, result);
    }
}
