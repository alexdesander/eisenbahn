use std::time::{Duration, Instant};

use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit};
use ahash::HashMap;
use chacha20poly1305::{ChaCha20Poly1305, ChaCha8Poly1305};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use strum::{EnumIter, IntoEnumIterator};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
#[repr(u8)]
pub enum SymCipherAlgorithm {
    None = 0,
    AES128GCM = 1,
    AES256GCM = 2,
    ChaCha8Poly1305 = 3,
    ChaCha20Poly1305 = 4,
}

impl SymCipherAlgorithm {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(SymCipherAlgorithm::None),
            1 => Some(SymCipherAlgorithm::AES128GCM),
            2 => Some(SymCipherAlgorithm::AES256GCM),
            3 => Some(SymCipherAlgorithm::ChaCha8Poly1305),
            4 => Some(SymCipherAlgorithm::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }

    /// Measures the performance of the algorithms and returns them in order of preference, based on the performance.
    /// The first element is the most preferred algorithm.
    /// If super_secure is true, the function will only consider AES256GCM and ChaCha20Poly1305.
    /// This never considers the None cipher.
    pub fn rank(super_secure: bool) -> Vec<SymCipherAlgorithm> {
        let mut rng = SmallRng::from_entropy();
        let key: [u8; 32] = rng.gen();
        let nonce: [u8; 12] = rng.gen();
        let aad = b"Eisenbahn";
        let mut data = [0u8; 1159];
        rng.fill(&mut data[..]);

        let mut times: HashMap<SymCipherAlgorithm, Duration> = HashMap::default();
        for _ in 0..3 {
            for algo in SymCipherAlgorithm::iter() {
                if algo == SymCipherAlgorithm::None {
                    continue;
                }
                if super_secure
                    && algo != SymCipherAlgorithm::AES256GCM
                    && algo != SymCipherAlgorithm::ChaCha20Poly1305
                {
                    continue;
                }
                let new_time = Self::measure(algo, key, nonce, aad, &mut data);
                if let Some(old_time) = times.get(&algo) {
                    if new_time < *old_time {
                        times.insert(algo, new_time);
                    }
                } else {
                    times.insert(algo, new_time);
                }
            }
        }
        let mut times: Vec<(SymCipherAlgorithm, Duration)> = times.into_iter().collect();
        times.sort_unstable_by_key(|(_, time)| *time);
        times.into_iter().map(|(algo, _)| algo).collect()
    }

    fn measure(
        algorithm: SymCipherAlgorithm,
        key: [u8; 32],
        nonce: [u8; 12],
        aad: &[u8],
        data: &mut [u8],
    ) -> Duration {
        let cipher = SymCipher::new(algorithm, key);
        let start = Instant::now();
        for _ in 0..100 {
            let tag = cipher.encrypt(&nonce, aad, data);
            let _ = cipher.decrypt(&nonce, aad, data, &tag);
        }
        start.elapsed()
    }
}

#[derive(Clone)]
pub(crate) enum SymCipher {
    None,
    AES128GCM(aes_gcm::Aes128Gcm),
    AES256GCM(aes_gcm::Aes256Gcm),
    ChaCha8Poly1305(chacha20poly1305::ChaCha8Poly1305),
    ChaCha20Poly1305(chacha20poly1305::ChaCha20Poly1305),
}

impl SymCipher {
    /// The cipher is set to None (no encryption).
    pub fn is_none(&self) -> bool {
        match self {
            SymCipher::None => true,
            _ => false,
        }
    }

    pub fn get_algorithm(&self) -> SymCipherAlgorithm {
        match self {
            SymCipher::None => SymCipherAlgorithm::None,
            SymCipher::AES128GCM(_) => SymCipherAlgorithm::AES128GCM,
            SymCipher::AES256GCM(_) => SymCipherAlgorithm::AES256GCM,
            SymCipher::ChaCha8Poly1305(_) => SymCipherAlgorithm::ChaCha8Poly1305,
            SymCipher::ChaCha20Poly1305(_) => SymCipherAlgorithm::ChaCha20Poly1305,
        }
    }

    /// If the algorithm needs a smaller key, it will be truncated.
    pub fn new(algorithm: SymCipherAlgorithm, key: [u8; 32]) -> SymCipher {
        match algorithm {
            SymCipherAlgorithm::None => SymCipher::None,
            SymCipherAlgorithm::AES128GCM => {
                SymCipher::AES128GCM(Aes128Gcm::new((&key[..16]).into()))
            }
            SymCipherAlgorithm::AES256GCM => SymCipher::AES256GCM(Aes256Gcm::new((&key).into())),
            SymCipherAlgorithm::ChaCha8Poly1305 => {
                SymCipher::ChaCha8Poly1305(ChaCha8Poly1305::new((&key).into()))
            }
            SymCipherAlgorithm::ChaCha20Poly1305 => {
                SymCipher::ChaCha20Poly1305(ChaCha20Poly1305::new((&key).into()))
            }
        }
    }

    /// Encrypts the data in place. The nonce must be 12 bytes long.
    /// The tag will be returned
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], to_encrypt: &mut [u8]) -> [u8; 16] {
        match self {
            SymCipher::None => panic!("Cannot encrypt with None cipher"),
            SymCipher::AES128GCM(cipher) => {
                let tag = cipher
                    .encrypt_in_place_detached(nonce.into(), aad, to_encrypt)
                    .unwrap();
                tag.into()
            }
            SymCipher::ChaCha8Poly1305(cipher) => {
                let tag = cipher
                    .encrypt_in_place_detached(nonce.into(), aad, to_encrypt)
                    .unwrap();
                tag.into()
            }
            SymCipher::AES256GCM(cipher) => {
                let tag = cipher
                    .encrypt_in_place_detached(nonce.into(), aad, to_encrypt)
                    .unwrap();
                tag.into()
            }
            SymCipher::ChaCha20Poly1305(cipher) => {
                let tag = cipher
                    .encrypt_in_place_detached(nonce.into(), aad, to_encrypt)
                    .unwrap();
                tag.into()
            }
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], to_decrypt: &mut [u8], tag: &[u8]) -> bool {
        match self {
            SymCipher::None => panic!("Cannot decrypt with None cipher"),
            SymCipher::AES128GCM(cipher) => cipher
                .decrypt_in_place_detached(nonce.into(), aad, to_decrypt, tag.into())
                .is_ok(),
            SymCipher::ChaCha8Poly1305(cipher) => cipher
                .decrypt_in_place_detached(nonce.into(), aad, to_decrypt, tag.into())
                .is_ok(),
            SymCipher::AES256GCM(cipher) => cipher
                .decrypt_in_place_detached(nonce.into(), aad, to_decrypt, tag.into())
                .is_ok(),
            SymCipher::ChaCha20Poly1305(cipher) => cipher
                .decrypt_in_place_detached(nonce.into(), aad, to_decrypt, tag.into())
                .is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measure() {
        SymCipherAlgorithm::rank(false);
    }
}
