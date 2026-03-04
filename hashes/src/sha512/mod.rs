// SPDX-License-Identifier: CC0-1.0

//! SHA512 implementation.

#![allow(clippy::unreadable_literal)]

use internals::slice::SliceExt;

mod crypto;
#[cfg(test)]
mod tests;

use core::cmp;

use crate::{incomplete_block_len, HashEngine as _};

crate::internal_macros::general_hash_type! {
    512,
    false,
    "Output of the SHA512 hash function."
}

impl Hash {
    /// Finalize a hash engine to produce a hash.
    #[cfg(not(hashes_fuzz))]
    pub fn from_engine(mut e: HashEngine) -> Self {
        // pad buffer with a single 1-bit then all 0s, until there are exactly 16 bytes remaining
        let n_bytes_hashed = e.bytes_hashed;

        let zeroes = [0; BLOCK_SIZE - 16];
        e.input(&[0x80]);
        if incomplete_block_len(&e) > zeroes.len() {
            e.input(&zeroes);
        }
        let pad_length = zeroes.len() - incomplete_block_len(&e);
        e.input(&zeroes[..pad_length]);
        debug_assert_eq!(incomplete_block_len(&e), zeroes.len());

        e.input(&[0; 8]);
        e.input(&(8 * n_bytes_hashed).to_be_bytes());
        debug_assert_eq!(incomplete_block_len(&e), 0);

        Self(e.midstate())
    }

    /// Finalize a hash engine to produce a hash.
    #[cfg(hashes_fuzz)]
    pub fn from_engine(e: HashEngine) -> Self {
        let mut hash = e.midstate();
        hash[0] ^= 0xff; // Make this distinct from SHA-256
        Hash(hash)
    }
}

pub(crate) const BLOCK_SIZE: usize = 128;

/// Engine to compute SHA512 hash function.
#[derive(Debug, Clone)]
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
        for (val, ret_bytes) in self.h.iter().zip(ret.bitcoin_as_chunks_mut().0) {
            *ret_bytes = val.to_be_bytes();
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
        Self {
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
        Self {
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
    type Hash = Hash;
    type Bytes = [u8; 64];
    const BLOCK_SIZE: usize = 128;

    fn n_bytes_hashed(&self) -> u64 { self.bytes_hashed }
    crate::internal_macros::engine_input_impl!();
    fn finalize(self) -> Self::Hash { Hash::from_engine(self) }
}
