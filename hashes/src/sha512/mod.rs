// SPDX-License-Identifier: CC0-1.0

//! SHA512 implementation.

#[cfg(bench)]
mod benches;
mod crypto;
#[cfg(bench)]
mod tests;

use core::cmp;

use crate::HashEngine as _;

crate::internal_macros::general_hash_type! {
    512,
    false,
    "Output of the SHA512 hash function."
}

#[cfg(not(hashes_fuzz))]
pub(crate) fn from_engine(mut e: HashEngine) -> Hash {
    // pad buffer with a single 1-bit then all 0s, until there are exactly 16 bytes remaining
    let n_bytes_hashed = e.bytes_hashed;

    let zeroes = [0; BLOCK_SIZE - 16];
    e.input(&[0x80]);
    if crate::incomplete_block_len(&e) > zeroes.len() {
        e.input(&zeroes);
    }
    let pad_length = zeroes.len() - crate::incomplete_block_len(&e);
    e.input(&zeroes[..pad_length]);
    debug_assert_eq!(crate::incomplete_block_len(&e), zeroes.len());

    e.input(&[0; 8]);
    e.input(&(8 * n_bytes_hashed).to_be_bytes());
    debug_assert_eq!(crate::incomplete_block_len(&e), 0);

    Hash(e.midstate())
}

#[cfg(hashes_fuzz)]
pub(crate) fn from_engine(e: HashEngine) -> Hash {
    let mut hash = e.midstate();
    hash[0] ^= 0xff; // Make this distinct from SHA-256
    Hash(hash)
}

pub(crate) const BLOCK_SIZE: usize = 128;

/// Engine to compute SHA512 hash function.
#[derive(Clone)]
pub struct HashEngine {
    h: [u64; 8],
    bytes_hashed: u64,
    buffer: [u8; BLOCK_SIZE],
}

impl HashEngine {
    /// Constructs a new SHA512 hash engine.
    #[rustfmt::skip]
    pub const fn new() -> Self {
        Self {
            h: [
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            ],
            bytes_hashed: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }
}

impl Default for HashEngine {
    fn default() -> Self { Self::new() }
}

impl HashEngine {
    #[cfg(not(hashes_fuzz))]
    pub(crate) fn midstate(&self) -> [u8; 64] {
        let mut ret = [0; 64];
        for (val, ret_bytes) in self.h.iter().zip(ret.chunks_exact_mut(8)) {
            ret_bytes.copy_from_slice(&val.to_be_bytes());
        }
        ret
    }

    #[cfg(hashes_fuzz)]
    pub(crate) fn midstate(&self) -> [u8; 64] {
        let mut ret = [0; 64];
        ret.copy_from_slice(&self.buffer[..64]);
        ret
    }

    /// Constructs a new hash engine suitable for use constructing a `sha512_256::HashEngine`.
    #[rustfmt::skip]
    pub(crate) const fn sha512_256() -> Self {
        HashEngine {
            h: [
                0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
                0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
            ],
            bytes_hashed: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }

    /// Constructs a new hash engine suitable for constructing a `sha384::HashEngine`.
    #[rustfmt::skip]
    pub(crate) const fn sha384() -> Self {
        HashEngine {
            h: [
                0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
            ],
            bytes_hashed: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }
}

impl crate::HashEngine for HashEngine {
    const BLOCK_SIZE: usize = 128;

    fn n_bytes_hashed(&self) -> u64 { self.bytes_hashed }

    #[cfg(not(hashes_fuzz))]
    fn input(&mut self, mut inp: &[u8]) {
        while !inp.is_empty() {
            let buf_idx = crate::incomplete_block_len(self);
            let rem_len = Self::BLOCK_SIZE - buf_idx;
            let write_len = cmp::min(rem_len, inp.len());

            self.buffer[buf_idx..buf_idx + write_len].copy_from_slice(&inp[..write_len]);
            self.bytes_hashed += write_len as u64;
            if crate::incomplete_block_len(self) == 0 {
                self.process_block();
            }
            inp = &inp[write_len..];
        }
    }

    #[cfg(hashes_fuzz)]
    fn input(&mut self, inp: &[u8]) {
        for c in inp {
            self.buffer[0] ^= *c;
        }
        self.bytes_hashed += inp.len() as u64;
    }
}
