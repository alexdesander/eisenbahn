use hkdf::Hkdf;
use sha2::Sha256;
use siphasher::sip::SipHasher;
use sym::{SymCipher, SymCipherAlgorithm};
use x25519_dalek::SharedSecret;

/// Authentication
pub mod auth;
/// Symmetric encryption
pub mod sym;

/// Holds all the encryption state and data for a connection.
#[derive(Clone)]
pub struct Encryption {
    siphasher: SipHasher,
    sym_out: SymCipher,
    sym_in: SymCipher,
}

impl Encryption {
    /// Creates a new encryption state with the given shared secret.
    pub fn new(shared_secret: SharedSecret, is_server: bool, sym_algo: SymCipherAlgorithm) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"EisenbahnV1.0"), shared_secret.as_bytes());
        let mut outgoing_key = [0u8; 32];
        let mut incoming_key = [0u8; 32];
        let mut siphash_key = [0u8; 16];
        if is_server {
            hk.expand(b"Client->Server", &mut incoming_key).unwrap();
            hk.expand(b"Server->Client", &mut outgoing_key).unwrap();
            hk.expand(b"SipHash Key", &mut siphash_key).unwrap();
        } else {
            hk.expand(b"Client->Server", &mut outgoing_key).unwrap();
            hk.expand(b"Server->Client", &mut incoming_key).unwrap();
            hk.expand(b"SipHash Key", &mut siphash_key).unwrap();
        }

        let siphasher = SipHasher::new_with_key(&siphash_key);
        let sym_out = SymCipher::new(sym_algo, outgoing_key);
        let sym_in = SymCipher::new(sym_algo, incoming_key);

        Self {
            siphasher,
            sym_out,
            sym_in,
        }
    }

    pub fn siphash(&self, data: &[u8]) -> u64 {
        self.siphasher.hash(data)
    }

    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], to_encrypt: &mut [u8]) -> [u8; 16] {
        self.sym_out.encrypt(nonce, aad, to_encrypt)
    }

    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], to_decrypt: &mut [u8], tag: &[u8]) -> bool {
        self.sym_in.decrypt(nonce, aad, to_decrypt, tag)
    }

    pub fn is_none(&self) -> bool {
        self.sym_out.is_none() && self.sym_in.is_none()
    }
}
