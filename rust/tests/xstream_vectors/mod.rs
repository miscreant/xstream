extern crate data_encoding;
extern crate serde_json;

use self::data_encoding::HEXLOWER;
pub use self::serde_json::Value as JsonValue;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// AES-SIV test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct XStreamExample {
    pub alg: String,
    pub sealingkey: Keypair,
    pub ephemeralkey: Keypair,
    pub salt: Option<Vec<u8>>,
    pub blocks: Vec<Block>,
}

#[derive(Debug)]
pub struct Keypair {
    pub seckey: Vec<u8>,
    pub pubkey: Vec<u8>,
}

#[derive(Debug)]
pub struct Block {
    pub ad: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl XStreamExample {
    /// Load examples from xstream.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("../vectors/xstream.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid xstream.tjson");
        let mut tjson_string = String::new();

        file.read_to_string(&mut tjson_string).expect(
            "xstream.tjson read successfully",
        );

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("xstream.tjson parses successfully");

        let examples = &tjson["examples:A<O>"].as_array().expect(
            "xstream.tjson examples array",
        );

        examples
            .into_iter()
            .map(|ex| {
                Self {
                    alg: ex["alg:s"].as_str().expect("algorithm name").to_owned(),
                    sealingkey: Keypair {
                        seckey: HEXLOWER
                            .decode(
                                ex["sealingkey:O"]["seckey:d16"]
                                    .as_str()
                                    .expect("encoded example")
                                    .as_bytes(),
                            )
                            .expect("hex encoded"),
                        pubkey: HEXLOWER
                            .decode(
                                ex["sealingkey:O"]["pubkey:d16"]
                                    .as_str()
                                    .expect("encoded example")
                                    .as_bytes(),
                            )
                            .expect("hex encoded"),
                    },
                    ephemeralkey: Keypair {
                        seckey: HEXLOWER
                            .decode(
                                ex["ephemeralkey:O"]["seckey:d16"]
                                    .as_str()
                                    .expect("encoded example")
                                    .as_bytes(),
                            )
                            .expect("hex encoded"),
                        pubkey: HEXLOWER
                            .decode(
                                ex["ephemeralkey:O"]["pubkey:d16"]
                                    .as_str()
                                    .expect("encoded example")
                                    .as_bytes(),
                            )
                            .expect("hex encoded"),
                    },
                    salt: ex["salt:d16"].as_str().map(|s| {
                        HEXLOWER.decode(s.as_bytes()).expect("hex encoded")
                    }),
                    blocks: ex["blocks:A<O>"]
                        .as_array()
                        .expect("encoded example")
                        .iter()
                        .map(|ex| {
                            Block {
                                ad: HEXLOWER
                                    .decode(
                                        ex["ad:d16"].as_str().expect("encoded example").as_bytes(),
                                    )
                                    .expect("hex encoded"),
                                plaintext: HEXLOWER
                                    .decode(
                                        ex["plaintext:d16"]
                                            .as_str()
                                            .expect("encoded example")
                                            .as_bytes(),
                                    )
                                    .expect("hex encoded"),
                                ciphertext: HEXLOWER
                                    .decode(
                                        ex["ciphertext:d16"]
                                            .as_str()
                                            .expect("encoded example")
                                            .as_bytes(),
                                    )
                                    .expect("hex encoded"),
                            }
                        })
                        .collect(),
                }
            })
            .collect()
    }
}
