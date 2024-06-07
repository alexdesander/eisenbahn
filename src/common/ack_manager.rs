use super::constants::Channel;

pub struct AckManager {
    // One entry for each channel.
    // The number is the amount of dedicated (contained in a full ack) acks that need to be sent.
    // This is not a bool, because we could need to send acks multiple times to make sure they arrive. (This is not needed as of yet)
    needs_acks: [u8; 4],
}

impl AckManager {
    pub fn new() -> Self {
        Self { needs_acks: [0; 4] }
    }

    pub fn handle_received(&mut self, channel: Channel) {
        self.needs_acks[channel.as_index()] = 1;
    }

    /// Note: This function changes the state of the AckManager.
    pub fn needs_ack(&mut self, channel: Channel) -> bool {
        if self.needs_acks[channel.as_index()] > 0 {
            self.needs_acks[channel.as_index()] -= 1;
            return true;
        }
        false
    }
}
