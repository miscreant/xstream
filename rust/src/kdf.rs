//! `kdf.rs`: Key Derivation Function used by XSTREAM

use clear_on_drop::clear::Clear;
use digest::Digest;
use generic_array::GenericArray;
use hkdf::Hkdf;
use keys::KEY_SIZE;
use x25519_dalek::diffie_hellman;

/// Domain separation string passed as HKDF info
const HKDF_INFO: &[u8] = b"XSTREAM_X25519_HKDF";

/// Derive a symmetric encryption key from the combination of a public and
/// private key and salt using X25519 D-H and HKDF
pub fn derive_key<D: Digest>(
    private_key: &[u8; KEY_SIZE],
    public_key: &[u8; KEY_SIZE],
    salt: Option<&[u8]>,
    length: usize,
) -> Vec<u8> {
    // Compute the ECDH shared secret
    let mut shared_secret = diffie_hellman(private_key, public_key);

    // Use HKDF to derive a symmetric encryption key from the shared secret
    let mut hkdf: Hkdf<D> = Hkdf::new(
        &shared_secret,
        salt.unwrap_or(&GenericArray::<u8, D::OutputSize>::default()),
    );

    let symmetric_key = hkdf.derive(HKDF_INFO, length);
    shared_secret.clear();

    // TODO: avoid allocating a Vec when the hkdf crate adds no_std support
    symmetric_key
}
