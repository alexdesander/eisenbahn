use argon2::Params;
use ed25519_dalek::SigningKey;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[repr(u8)]
pub enum AuthenticationKind {
    None = 0,
    Password = 1,
    Key = 2,
    CA = 3,
}

impl AuthenticationKind {
    pub fn from_u8(auth: u8) -> Option<Self> {
        match auth {
            0 => Some(Self::None),
            1 => Some(Self::Password),
            2 => Some(Self::Key),
            3 => Some(Self::CA),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug)]
pub struct AuthenticationNone {
    pub(crate) username: String,
}

impl AuthenticationNone {
    pub fn new(username: String) -> Self {
        assert!(username.len() <= 255, "Username is too long, max 255 bytes");
        Self { username }
    }
}

#[derive(Debug)]
pub struct AuthenticationPassword {
    pub(crate) username: String,
    pub(crate) password: String,
}

impl AuthenticationPassword {
    pub fn new(username: String, password: String) -> Self {
        assert!(username.len() <= 255, "Username is too long, max 255 bytes");
        Self { username, password }
    }

    pub(crate) fn hashed(&self, salt: [u8; 16]) -> [u8; 20] {
        let mut hash = [0u8; 20];
        argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(65536, 2, 1, Some(20)).unwrap(),
        )
        .hash_password_into(self.password.as_bytes(), &salt, &mut hash)
        .unwrap();
        hash
    }
}

#[derive(Debug)]
pub struct AuthenticationCA {
    pub ticket: [u8; 32],
}

impl AuthenticationCA {
    pub fn new(ticket: [u8; 32]) -> Self {
        Self { ticket }
    }
}

#[derive(Debug)]
pub struct AuthenticationKey {
    pub(crate) username: String,
    pub(crate) key: SigningKey,
}

impl AuthenticationKey {
    pub fn new(username: String, key: SigningKey) -> Self {
        assert!(username.len() <= 255, "Username is too long, max 255 bytes");
        Self { username, key }
    }
}
