//! `x25519_hkdf.rs`: STREAM ECIES using the X25519 Elliptic Curve
//! Diffie-Hellman function as described in RFC 7748, and the HMAC-based
//! Extract-and-Expand Key Derivation Function (HKDF) described in RFC 5869.
//! Can be used with any AEAD algorithm which implements the
//! `miscreant::aead::Algorithm` trait.

use super::{Encryptor, Decryptor};
use clear_on_drop::clear::Clear;
use digest::Digest;
use error::Error;
use generic_array::typenum::Unsigned;
use kdf::derive_key;
use keys;
use miscreant::aead;
use miscreant::stream::{self, NONCE_SIZE};
use rand::Rng;
use sha2::Sha256;
use std::marker::PhantomData;
use x25519_dalek::{generate_secret, generate_public};

/// Use a prefix of all zeroes for the STREAM nonce prefix, since we derive a
/// unique key for every STREAM. The STREAM construction handles producing a
/// unique nonce per message segment.
const NONCE_PREFIX: &[u8; NONCE_SIZE] = &[0u8; NONCE_SIZE];

/// Elliptic Curve Integrated Encryption Scheme (ECIES) encryptor object based
/// on the X25519 Diffie-Hellman function, HKDF, and generic over any AEAD
/// algorithm supported by Miscreant. Uses the STREAM construction to support
/// incremental encryption.
pub struct X25519HkdfEncryptor<A: aead::Algorithm, D: Digest> {
    stream: stream::Encryptor<A>,
    digest: PhantomData<D>,
}

/// A `XSTREAM` encryptor using X25519 and HKDF-SHA-256. This is the
/// recommended set of algorithms to use with `XSTREAM`.
pub type X25519HkdfSha256Encryptor<A> = X25519HkdfEncryptor<A, Sha256>;

impl<A, D> Encryptor for X25519HkdfEncryptor<A, D>
where
    A: aead::Algorithm,
    D: Digest,
{
    type PublicKey = keys::PublicKey;

    /// Create a new Encryptor object which seals a stream of messages under
    /// an X25519 public key.
    fn new<R: Rng>(
        csprng: &mut R,
        public_key: &Self::PublicKey,
        salt: Option<&[u8]>,
    ) -> (Self, Self::PublicKey) {
        // Create an ephemeral X25519 key
        let mut ephemeral_scalar = generate_secret(csprng);
        let ephemeral_public = generate_public(&ephemeral_scalar);

        // Perform an X25519 elliptic curve Diffie-Hellman operation and use
        // the resulting shared secret to derive a symmetric key (using HKDF)
        let mut symmetric_key = derive_key::<D>(
            &ephemeral_scalar,
            public_key.as_ref(),
            salt,
            A::KeySize::to_usize(),
        );

        // Erase the ephemeral private key/scalar now that we've performed the
        // Diffie-Hellman op
        ephemeral_scalar.clear();

        // Create a new STREAM encryptor object using the derived key.
        let stream = stream::Encryptor::new(&symmetric_key, NONCE_PREFIX);
        symmetric_key.clear();

        let encryptor = Self {
            stream: stream,
            digest: PhantomData,
        };

        (
            encryptor,
            Self::PublicKey::from(ephemeral_public.to_bytes()),
        )
    }

    /// Encrypt the next message in the stream in-place
    fn seal_next_in_place(&mut self, ad: &[u8], buffer: &mut [u8]) {
        self.stream.seal_next_in_place(ad, buffer);
    }

    /// Encrypt the final message in-place, consuming the stream encryptor
    fn seal_last_in_place(self, ad: &[u8], buffer: &mut [u8]) {
        self.stream.seal_last_in_place(ad, buffer);
    }

    /// Encrypt the next message in the stream, allocating and returning a
    /// `Vec<u8>` for the ciphertext
    fn seal_next(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        self.stream.seal_next(ad, plaintext)
    }

    /// Encrypt the final message in the stream, allocating and returning a
    /// `Vec<u8>` for the ciphertext
    fn seal_last(self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        self.stream.seal_last(ad, plaintext)
    }
}

/// Elliptic Curve Integrated Encryption Scheme (ECIES) decryptor object based
/// on the X25519 Diffie-Hellman function, HKDF, and generic over any AEAD
/// algorithm supported by Miscreant. Uses the STREAM construction to support
/// incremental decryption.
pub struct X25519HkdfDecryptor<A: aead::Algorithm, D: Digest> {
    stream: stream::Decryptor<A>,
    digest: PhantomData<D>,
}

/// A `XSTREAM` decryptor using X25519 and HKDF-SHA-256. This is the
/// recommended set of algorithms to use with `XSTREAM`.
pub type X25519HkdfSha256Decryptor<A> = X25519HkdfDecryptor<A, Sha256>;

impl<A, D> Decryptor for X25519HkdfDecryptor<A, D>
where
    A: aead::Algorithm,
    D: Digest,
{
    type PrivateKey = keys::PrivateKey;
    type PublicKey = keys::PublicKey;

    /// Create a new Decryptor object which unseals a stream of messages
    /// which were previously encrypted using the public key that cooresponds
    /// to the given private key.
    fn new(
        private_key: &Self::PrivateKey,
        ephemeral_key: &Self::PublicKey,
        salt: Option<&[u8]>,
    ) -> Self {
        // Perform an X25519 elliptic curve Diffie-Hellman operation and use
        // the resulting shared secret to derive a symmetric key (using HKDF)
        let mut symmetric_key = derive_key::<D>(
            &private_key.0,
            ephemeral_key.as_ref(),
            salt,
            A::KeySize::to_usize(),
        );

        // Create a new STREAM decryptor object using the derived key.
        let stream = stream::Decryptor::new(&symmetric_key, NONCE_PREFIX);
        symmetric_key.clear();

        Self {
            stream: stream,
            digest: PhantomData,
        }
    }

    /// Decrypt the next message in the stream in-place
    fn open_next_in_place<'a>(
        &mut self,
        ad: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.stream.open_next_in_place(ad, buffer).or(Err(Error))
    }

    /// Decrypt the final message in-place, consuming the stream decryptor
    fn open_last_in_place<'a>(self, ad: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
        self.stream.open_last_in_place(ad, buffer).or(Err(Error))
    }

    /// Decrypt the next message in the stream, allocating and returning a
    /// `Vec<u8>` for the plaintext
    fn open_next(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.stream.open_next(ad, ciphertext).or(Err(Error))
    }

    /// Decrypt the next message in the stream, allocating and returning a
    /// `Vec<u8>` for the plaintext
    fn open_last(self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.stream.open_last(ad, ciphertext).or(Err(Error))
    }
}
