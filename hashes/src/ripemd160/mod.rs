// SPDX-License-Identifier: CC0-1.0

//! RIPEMD160 implementation.

use internals::slice::SliceExt;
mod crypto;
#[cfg(test)]
mod tests;

use crate::{incomplete_block_len};

crate::internal_macros::general_hash_type! {
    160,
    false,
    "Output of the RIPEMD160 hash function."
}

impl Hash {
    /// Finalize a hash engine to produce a hash.
    #[cfg(not(hashes_fuzz))]
    pub fn from_engine(mut e: HashEngine) -> Self {
        let n_bytes_hashed = e.bytes_hashed;
        let buf_idx = incomplete_block_len(&e);

        e.buffer[buf_idx] = 0x80;
        e.buffer[buf_idx + 1..].fill(0);

        if buf_idx >= BLOCK_SIZE - 8 {
            HashEngine::process_blocks(&mut e.h, &e.buffer);
            e.buffer[..BLOCK_SIZE - 8].fill(0);
        }

        e.buffer[BLOCK_SIZE - 8..].copy_from_slice(&(8 * n_bytes_hashed).to_le_bytes());
        HashEngine::process_blocks(&mut e.h, &e.buffer);

        Self(e.midstate())
    }

    /// Finalize a hash engine to produce a hash.
    #[cfg(hashes_fuzz)]
    pub fn from_engine(e: HashEngine) -> Self {
        let mut res = e.midstate();
        res[0] ^= (e.bytes_hashed & 0xff) as u8;
        Hash(res)
    }
}

const BLOCK_SIZE: usize = 64;

/// Engine to compute RIPEMD160 hash function.
#[derive(Debug, Clone)]
pub struct HashEngine {
    buffer: [u8; BLOCK_SIZE],
    h: [u32; 5],
    bytes_hashed: u64,
}

impl HashEngine {
    /// Constructs a new RIPEMD160 hash engine.
    pub const fn new() -> Self {
        Self {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            bytes_hashed: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }

    #[cfg(not(hashes_fuzz))]
    fn midstate(&self) -> [u8; 20] {
        let mut ret = [0; 20];
        for (val, ret_bytes) in self.h.iter().zip(ret.bitcoin_as_chunks_mut().0) {
            *ret_bytes = val.to_le_bytes();
        }
        ret
    }

    #[cfg(hashes_fuzz)]
    fn midstate(&self) -> [u8; 20] {
        let mut ret = [0; 20];
        ret.copy_from_slice(&self.buffer[..20]);
        ret
    }
}

impl Default for HashEngine {
    fn default() -> Self { Self::new() }
}

impl crate::HashEngine for HashEngine {
    type Hash = Hash;
    type Bytes = [u8; 20];
    const BLOCK_SIZE: usize = 64;

    fn n_bytes_hashed(&self) -> u64 { self.bytes_hashed }
    crate::internal_macros::engine_input_impl!();
    fn finalize(self) -> Self::Hash { Hash::from_engine(self) }
}
