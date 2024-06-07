use std::collections::VecDeque;

use integer_encoding::VarInt;

pub struct MessageDisassembler {
    /// (message, offset, size written)
    messages: VecDeque<(Vec<u8>, usize, bool)>,
}

impl MessageDisassembler {
    pub fn new() -> Self {
        Self {
            messages: VecDeque::new(),
        }
    }

    pub fn insert(&mut self, message: Vec<u8>) {
        assert!(
            message.len() < u32::MAX as usize,
            "Message too large, max size: 2^32 bytes"
        );
        self.messages.push_back((message, 0, false));
    }

    pub fn next(&mut self, max_size: usize) -> Option<Vec<u8>> {
        assert!(
            max_size >= 5,
            "Max size must be greater than or 5 bytes due to varint encoding"
        );
        if self.messages.is_empty() {
            return None;
        }
        let mut result: Vec<u8> = if max_size >= 32 {
            Vec::with_capacity(32)
        } else {
            Vec::new()
        };

        let mut remaining = max_size;
        while let Some((message, offset, size_written)) = self.messages.front_mut() {
            if !*size_written && *offset == 0 {
                let mut encoded_size = [0u8; 5];
                let encoded_len = message.len().encode_var(&mut encoded_size);
                if remaining < encoded_len {
                    break;
                }
                result.extend_from_slice(&encoded_size[..encoded_len]);
                remaining -= encoded_len;
                *size_written = true;
            }
            let msg_size = message.len() - *offset;
            match remaining {
                _ if remaining > msg_size => {
                    result.extend_from_slice(&message[*offset..]);
                    remaining -= msg_size;
                    self.messages.pop_front();
                }
                _ if remaining < msg_size => {
                    result.extend_from_slice(&message[*offset..*offset + remaining]);
                    *offset += remaining;
                    break;
                }
                _ => {
                    result.extend_from_slice(&message[*offset..]);
                    self.messages.pop_front();
                    break;
                }
            }
        }
        Some(result)
    }
}
