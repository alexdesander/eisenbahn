#[derive(Debug)]
pub enum Channel {
    Reliable0,
    Reliable1,
    Reliable2,
    Reliable3,
}

impl Channel {
    pub fn as_index(&self) -> usize {
        match self {
            Channel::Reliable0 => 0,
            Channel::Reliable1 => 1,
            Channel::Reliable2 => 2,
            Channel::Reliable3 => 3,
        }
    }
}

pub(crate) const MAGIC: &'static [u8; 13] = b"EisenbahnV1.0";

pub(crate) const PACKET_ID_CLIENT_HELLO: u8 = 0;
pub(crate) const PACKET_ID_SERVER_HELLO: u8 = 1;
pub(crate) const PACKET_ID_CONNECTION_REQUEST: u8 = 2;
pub(crate) const PACKET_ID_CONNECTION_RESPONSE: u8 = 3;
pub(crate) const PACKET_ID_PASSWORD_REQUEST: u8 = 4;
pub(crate) const PACKET_ID_PASSWORD_RESPONSE: u8 = 5;
pub(crate) const PACKET_ID_ACK_ONLY: u8 = 11;

pub(crate) const NONCE_CONNECTION_RESPONSE: [u8; 12] = [255; 12];
pub(crate) const NONCE_PASSWORD_REQUEST: [u8; 12] =
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254];
pub(crate) const NONCE_PASSWORD_RESPONSE: [u8; 12] =
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253];
