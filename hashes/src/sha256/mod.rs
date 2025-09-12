// SPDX-License-Identifier: CC0-1.0

//! SHA256 implementation.

#[cfg(bench)]
mod benches;
mod crypto;
#[cfg(bench)]
mod tests;

use core::{cmp, convert, fmt};

use internals::slice::SliceExt;

use crate::{incomplete_block_len, sha256d, HashEngine as _};
#[cfg(doc)]
use crate::{sha256t, sha256t_tag};

crate::internal_macros::general_hash_type! {
    256,
    false,
    "Output of the SHA256 hash function."
}

const BLOCK_SIZE: usize = 64;

/// Engine to compute SHA256 hash function.
#[derive(Debug, Clone)]
pub struct HashEngine {
    buffer: [u8; BLOCK_SIZE],
    h: [u32; 8],
    bytes_hashed: u64,
}

impl HashEngine {
    /// Constructs a new SHA256 hash engine.
    pub const fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            bytes_hashed: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }

    /// Constructs a new [`HashEngine`] from a [`Midstate`].
    ///
    /// Please see docs on [`Midstate`] before using this function.
    pub fn from_midstate(midstate: Midstate) -> HashEngine {
        let mut ret = [0; 8];
        for (ret_val, midstate_bytes) in ret.iter_mut().zip(midstate.as_ref().bitcoin_as_chunks().0)
        {
            *ret_val = u32::from_be_bytes(*midstate_bytes);
        }

        HashEngine { buffer: [0; BLOCK_SIZE], h: ret, bytes_hashed: midstate.bytes_hashed }
    }

    /// Returns `true` if the midstate can be extracted from this engine.
    ///
    /// The midstate can only be extracted if the number of bytes input into
    /// the hash engine is a multiple of 64. See caveat on [`Self::midstate`].
    ///
    /// Please see docs on [`Midstate`] before using this function.
    pub const fn can_extract_midstate(&self) -> bool { self.bytes_hashed % 64 == 0 }

    /// Outputs the midstate of the hash engine.
    ///
    /// Please see docs on [`Midstate`] before using this function.
    pub fn midstate(&self) -> Result<Midstate, MidstateError> {
        if !self.can_extract_midstate() {
            return Err(MidstateError { invalid_n_bytes_hashed: self.bytes_hashed });
        }
        Ok(self.midstate_unchecked())
    }

    // Does not check that `HashEngine::can_extract_midstate`.
    #[cfg(not(hashes_fuzz))]
    fn midstate_unchecked(&self) -> Midstate {
        let mut ret = [0; 32];
        for (val, ret_bytes) in self.h.iter().zip(ret.bitcoin_as_chunks_mut::<4>().0) {
            *ret_bytes = val.to_be_bytes();
        }
        Midstate { bytes: ret, bytes_hashed: self.bytes_hashed }
    }

    // Does not check that `HashEngine::can_extract_midstate`.
    #[cfg(hashes_fuzz)]
    fn midstate_unchecked(&self) -> Midstate {
        let mut ret = [0; 32];
        ret.copy_from_slice(&self.buffer[..32]);
        Midstate { bytes: ret, bytes_hashed: self.bytes_hashed }
    }
}

impl Default for HashEngine {
    fn default() -> Self { Self::new() }
}

impl crate::HashEngine for HashEngine {
    type Hash = Hash;
    type Bytes = [u8; 32];
    const BLOCK_SIZE: usize = 64;

    fn n_bytes_hashed(&self) -> u64 { self.bytes_hashed }
    crate::internal_macros::engine_input_impl!();
    fn finalize(self) -> Self::Hash { Hash::from_engine(self) }
}

impl Hash {
    /// Finalize a hash engine to obtain a hash.
    #[cfg(not(hashes_fuzz))]
    pub fn from_engine(mut e: HashEngine) -> Self {
        // pad buffer with a single 1-bit then all 0s, until there are exactly 8 bytes remaining
        let n_bytes_hashed = e.bytes_hashed;

        let zeroes = [0; BLOCK_SIZE - 8];
        e.input(&[0x80]);
        if incomplete_block_len(&e) > zeroes.len() {
            e.input(&zeroes);
        }
        let pad_length = zeroes.len() - incomplete_block_len(&e);
        e.input(&zeroes[..pad_length]);
        debug_assert_eq!(incomplete_block_len(&e), zeroes.len());

        e.input(&(8 * n_bytes_hashed).to_be_bytes());
        debug_assert_eq!(incomplete_block_len(&e), 0);

        Hash(e.midstate_unchecked().bytes)
    }

    /// Finalize a hash engine to obtain a hash.
    #[cfg(hashes_fuzz)]
    pub fn from_engine(e: HashEngine) -> Self {
        let mut hash = e.midstate_unchecked().bytes;
        if hash == [0; 32] {
            // Assume sha256 is secure and never generate 0-hashes (which represent invalid
            // secp256k1 secret keys, causing downstream application breakage).
            hash[0] = 1;
        }
        Hash(hash)
    }

    /// Iterate the sha256 algorithm to turn a sha256 hash into a sha256d hash
    #[must_use]
    pub fn hash_again(&self) -> sha256d::Hash { sha256d::Hash::from_byte_array(hash(&self.0).0) }

    /// Computes hash from `bytes` in `const` context.
    ///
    /// Warning: this function is inefficient. It should be only used in `const` context.
    pub const fn hash_unoptimized(bytes: &[u8]) -> Self {
        Hash(Midstate::compute_midstate_unoptimized(bytes, true).bytes)
    }
}

/// Unfinalized output of the SHA256 hash function.
///
/// The `Midstate` type is obscure and specialized and should not be used unless you are sure of
/// what you are doing.
///
/// It represents "partially hashed data" but does not itself have properties of cryptographic
/// hashes. For example, when (ab)used as hashes, midstates are vulnerable to trivial
/// length-extension attacks. They are typically used to optimize the computation of full hashes.
/// For example, when implementing BIP-340 tagged hashes, which always begin by hashing the same
/// fixed 64-byte prefix, it makes sense to hash the prefix once, store the midstate as a constant,
/// and hash any future data starting from the constant rather than from a fresh hash engine.
///
/// For BIP-340 support we provide the [`sha256t`] module, and the [`sha256t_tag`] macro which will
/// create the midstate for you in const context.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Midstate {
    /// Raw bytes of the midstate i.e., the already-hashed contents of the hash engine.
    bytes: [u8; 32],
    /// Number of bytes hashed to achieve this midstate.
    // INVARIANT must always be a multiple of 64.
    bytes_hashed: u64,
}

impl Midstate {
    /// Constructs a new [`Midstate`] from the `state` and the `bytes_hashed` to get to that state.
    ///
    /// # Panics
    ///
    /// Panics if `bytes_hashed` is not a multiple of 64.
    pub const fn new(state: [u8; 32], bytes_hashed: u64) -> Self {
        if bytes_hashed % 64 != 0 {
            panic!("bytes hashed is not a multiple of 64");
        }

        Midstate { bytes: state, bytes_hashed }
    }

    /// Deconstructs the [`Midstate`], returning the underlying byte array and number of bytes hashed.
    pub const fn as_parts(&self) -> (&[u8; 32], u64) { (&self.bytes, self.bytes_hashed) }

    /// Deconstructs the [`Midstate`], returning the underlying byte array and number of bytes hashed.
    pub const fn to_parts(self) -> ([u8; 32], u64) { (self.bytes, self.bytes_hashed) }

    /// Constructs a new midstate for tagged hashes.
    ///
    /// Warning: this function is inefficient. It should be only used in `const` context.
    ///
    /// Computes non-finalized hash of `sha256(tag) || sha256(tag)` for use in [`sha256t`]. It's
    /// provided for use with [`sha256t`].
    #[must_use]
    pub const fn hash_tag(tag: &[u8]) -> Self {
        let hash = Hash::hash_unoptimized(tag);
        let mut buf = [0u8; 64];
        let mut i = 0usize;
        while i < buf.len() {
            buf[i] = hash.0[i % hash.0.len()];
            i += 1;
        }
        Self::compute_midstate_unoptimized(&buf, false)
    }
}

impl fmt::Debug for Midstate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct Encoder<'a> {
            bytes: &'a [u8; 32],
        }
        impl fmt::Debug for Encoder<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { crate::debug_hex(self.bytes, f) }
        }

        f.debug_struct("Midstate")
            .field("bytes", &Encoder { bytes: &self.bytes })
            .field("length", &self.bytes_hashed)
            .finish()
    }
}

impl convert::AsRef<[u8]> for Midstate {
    fn as_ref(&self) -> &[u8] { &self.bytes }
}

/// `Midstate` invariant violated (not a multiple of 64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MidstateError {
    /// The invalid number of bytes hashed.
    invalid_n_bytes_hashed: u64,
}

impl fmt::Display for MidstateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "invalid number of bytes hashed {} (should have been a multiple of 64)",
            self.invalid_n_bytes_hashed
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MidstateError {}
