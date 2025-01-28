// SPDX-License-Identifier: CC0-1.0

//! RIPEMD160 implementation.

#[cfg(bench)]
mod benches;
mod crypto;
#[cfg(bench)]
mod tests;

use core::cmp;

use crate::{incomplete_block_len, HashEngine as _};

crate::internal_macros::general_hash_type! {
    160,
    false,
    "Output of the RIPEMD160 hash function."
}

#[cfg(not(hashes_fuzz))]
fn from_engine(mut e: HashEngine) -> Hash {
    // pad buffer with a single 1-bit then all 0s, until there are exactly 8 bytes remaining
    let n_bytes_hashed = e.bytes_hashed;

    let zeroes = [0; BLOCK_SIZE - 8];
    e.input(&[0x80]);
    if crate::incomplete_block_len(&e) > zeroes.len() {
        e.input(&zeroes);
    }
    let pad_length = zeroes.len() - incomplete_block_len(&e);
    e.input(&zeroes[..pad_length]);
    debug_assert_eq!(incomplete_block_len(&e), zeroes.len());

    e.input(&(8 * n_bytes_hashed).to_le_bytes());
    debug_assert_eq!(incomplete_block_len(&e), 0);

    Hash(e.midstate())
}

#[cfg(hashes_fuzz)]
fn from_engine(e: HashEngine) -> Hash {
    let mut res = e.midstate();
    res[0] ^= (e.bytes_hashed & 0xff) as u8;
    Hash(res)
}

const BLOCK_SIZE: usize = 64;

/// Engine to compute RIPEMD160 hash function.
#[derive(Clone)]
pub struct HashEngine {
    buffer: [u8; BLOCK_SIZE],
    h: [u32; 5],
    bytes_hashed: u64,
}

impl HashEngine {
    /// Constructs a new SHA256 hash engine.
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
        for (val, ret_bytes) in self.h.iter().zip(ret.chunks_exact_mut(4)) {
            ret_bytes.copy_from_slice(&(*val).to_le_bytes());
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
    const BLOCK_SIZE: usize = 64;

    fn n_bytes_hashed(&self) -> u64 { self.bytes_hashed }

    crate::internal_macros::engine_input_impl!();
}
