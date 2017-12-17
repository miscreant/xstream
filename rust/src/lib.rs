//! `lib.rs`: Elliptic Curve Integrated Encryption Scheme (ECIES)
//! combining ECDH with an ephemeral key, a KDF, and the STREAM[1] constuction.
//!
//! [1]: https://eprint.iacr.org/2015/189.pdf

#![crate_name = "xstream"]
#![crate_type = "lib"]

#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

extern crate clear_on_drop;
extern crate digest;
extern crate generic_array;
extern crate hkdf;
extern crate miscreant;
extern crate rand;
extern crate sha2;
extern crate x25519_dalek;

mod error;
mod kdf;
mod keys;
mod traits;
mod x25519_hkdf;

pub use self::error::Error;
pub use self::keys::{PublicKey, PrivateKey};
pub use self::traits::{Encryptor, Decryptor};
pub use self::x25519_hkdf::{X25519HkdfSha256Encryptor, X25519HkdfSha256Decryptor};
