//! A random number generator that returns a test vector

use rand::Rng;

pub struct TestRng(Vec<u8>);

impl TestRng {
    pub fn new(data: &[u8]) -> Self {
        TestRng(Vec::from(data))
    }
}

impl Rng for TestRng {
    /// We don't actually implement this, but it's required for the Rng trait
    fn next_u32(&mut self) -> u32 {
        panic!("unimplemented");
    }

    /// This is the only method used by our implementation internally
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for (i, byte) in self.0.drain(..bytes.len()).into_iter().enumerate() {
            bytes[i] = byte;
        }
    }
}
