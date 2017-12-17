extern crate rand;
extern crate miscreant;
extern crate xstream;

mod test_rng;
mod xstream_vectors;

use miscreant::aead::{Aes128Siv, Aes128PmacSiv};
use test_rng::TestRng;
use xstream::{Encryptor, Decryptor, PrivateKey, PublicKey};
use xstream::{X25519HkdfSha256Encryptor, X25519HkdfSha256Decryptor};
use xstream_vectors::{XStreamExample, Block};

#[test]
fn xstream_examples_seal() {
    for ex in XStreamExample::load_all() {
        let mut rng = TestRng::new(ex.ephemeralkey.seckey.as_slice());
        let sealing_pk = PublicKey::new(ex.sealingkey.pubkey.as_slice());
        let salt = match ex.salt {
            Some(ref vec) => Some(vec.as_ref()),
            None => None,
        };

        match ex.alg.as_ref() {
            "XSTREAM_X25519_HKDF_SHA256_AES128_SIV" => {
                let (mut encryptor, pubkey) =
                    X25519HkdfSha256Encryptor::<Aes128Siv>::new(&mut rng, &sealing_pk, salt);

                test_encryptor(encryptor, &ex.blocks);
                assert_eq!(pubkey.as_bytes(), &ex.ephemeralkey.pubkey[..]);
            }
            "XSTREAM_X25519_HKDF_SHA256_AES128_PMAC_SIV" => {
                let (mut encryptor, pubkey) =
                    X25519HkdfSha256Encryptor::<Aes128PmacSiv>::new(&mut rng, &sealing_pk, salt);

                test_encryptor(encryptor, &ex.blocks);
                assert_eq!(pubkey.as_bytes(), &ex.ephemeralkey.pubkey[..]);
            }
            _ => panic!("unexpected algorithm: {}", ex.alg),
        }
    }
}

fn test_encryptor<E: Encryptor>(mut encryptor: E, blocks: &[Block]) {
    for (i, block) in blocks.iter().enumerate() {
        if i < blocks.len() - 1 {
            let ciphertext = encryptor.seal_next(&block.ad, &block.plaintext);
            assert_eq!(ciphertext, block.ciphertext);
        } else {
            let ciphertext = encryptor.seal_last(&block.ad, &block.plaintext);
            assert_eq!(ciphertext, block.ciphertext);
            return;
        }
    }
}

#[test]
fn xstream_examples_open() {
    for ex in XStreamExample::load_all() {
        let sealing_sk = PrivateKey::new(ex.sealingkey.seckey.as_slice());
        let ephemeral_pk = PublicKey::new(ex.ephemeralkey.pubkey.as_slice());
        let salt = match ex.salt {
            Some(ref vec) => Some(vec.as_ref()),
            None => None,
        };

        match ex.alg.as_ref() {
            "XSTREAM_X25519_HKDF_SHA256_AES128_SIV" => {
                let decryptor =
                    X25519HkdfSha256Decryptor::<Aes128Siv>::new(&sealing_sk, &ephemeral_pk, salt);

                test_decryptor(decryptor, &ex.blocks)
            }
            "XSTREAM_X25519_HKDF_SHA256_AES128_PMAC_SIV" => {
                let decryptor = X25519HkdfSha256Decryptor::<Aes128PmacSiv>::new(
                    &sealing_sk,
                    &ephemeral_pk,
                    salt,
                );

                test_decryptor(decryptor, &ex.blocks)
            }
            _ => panic!("unexpected algorithm: {}", ex.alg),
        }
    }
}

fn test_decryptor<D: Decryptor>(mut decryptor: D, blocks: &[Block]) {
    for (i, block) in blocks.iter().enumerate() {
        if i < blocks.len() - 1 {
            let plaintext = decryptor.open_next(&block.ad, &block.ciphertext).expect(
                "decrypt failure",
            );

            assert_eq!(plaintext, block.plaintext);
        } else {
            let plaintext = decryptor.open_last(&block.ad, &block.ciphertext).expect(
                "decrypt failure",
            );

            assert_eq!(plaintext, block.plaintext);
            return;
        }
    }
}
