//! `keys.rs`: Public and private keys for X25519

use clear_on_drop::clear::Clear;
use rand::Rng;
use x25519_dalek::{generate_public, generate_secret};

/// Length of an X25519 key (private or public) in bytes
pub const KEY_SIZE: usize = 32;

/// X25519 private key (i.e. private scalar)
// TODO: Support for larger keys, e.g. X448?
pub struct PrivateKey(pub(crate) [u8; KEY_SIZE]);

impl PrivateKey {
    /// Generate a random key from the given random number generator
    pub fn generate<T: Rng>(csprng: &mut T) -> Self {
        PrivateKey(generate_secret(csprng))
    }

    /// Create a new key from the given slice
    ///
    /// Panics if the slice is the wrong size
    pub fn new(bytes: &[u8]) -> Self {
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        PrivateKey(key)
    }

    /// Obtain a public key from this PrivateKey
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(generate_public(&self.0).to_bytes())
    }

    /// Obtain this key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; KEY_SIZE]> for PrivateKey {
    fn from(bytes: [u8; KEY_SIZE]) -> Self {
        PrivateKey(bytes)
    }
}

impl Into<[u8; KEY_SIZE]> for PrivateKey {
    fn into(self) -> [u8; KEY_SIZE] {
        self.0
    }
}

/// Ensure private scalars are cleared from memory on drop
impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.clear()
    }
}

/// X25519 public key (i.e. compressed Montgomery-u coordinate)
pub struct PublicKey(pub(crate) [u8; KEY_SIZE]);

impl PublicKey {
    /// Create a new key from the given slice
    ///
    /// Panics if the slice is the wrong size
    pub fn new(bytes: &[u8]) -> Self {
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        PublicKey(key)
    }


    /// Obtain this key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; KEY_SIZE]> for PublicKey {
    fn from(bytes: [u8; KEY_SIZE]) -> Self {
        PublicKey(bytes)
    }
}

impl AsRef<[u8; KEY_SIZE]> for PublicKey {
    fn as_ref(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl Into<[u8; KEY_SIZE]> for PublicKey {
    fn into(self) -> [u8; KEY_SIZE] {
        self.0
    }
}
