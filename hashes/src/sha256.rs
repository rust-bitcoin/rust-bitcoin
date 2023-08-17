// SPDX-License-Identifier: CC0-1.0

//! SHA256 implementation.
//!

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::convert::TryInto;
use core::ops::Index;
use core::slice::SliceIndex;
use core::{cmp, str};

use crate::{hex, sha256d, FromSliceError, HashEngine as _};

crate::internal_macros::hash_type! {
    256,
    false,
    "Output of the SHA256 hash function.",
    "crate::util::json_hex_string::len_32"
}

#[cfg(not(hashes_fuzz))]
fn from_engine(mut e: HashEngine) -> Hash {
    // pad buffer with a single 1-bit then all 0s, until there are exactly 8 bytes remaining
    let data_len = e.length as u64;

    let zeroes = [0; BLOCK_SIZE - 8];
    e.input(&[0x80]);
    if e.length % BLOCK_SIZE > zeroes.len() {
        e.input(&zeroes);
    }
    let pad_length = zeroes.len() - (e.length % BLOCK_SIZE);
    e.input(&zeroes[..pad_length]);
    debug_assert_eq!(e.length % BLOCK_SIZE, zeroes.len());

    e.input(&(8 * data_len).to_be_bytes());
    debug_assert_eq!(e.length % BLOCK_SIZE, 0);

    Hash(e.midstate().to_byte_array())
}

#[cfg(hashes_fuzz)]
fn from_engine(e: HashEngine) -> Hash {
    let mut hash = e.midstate().to_byte_array();
    if hash == [0; 32] {
        // Assume sha256 is secure and never generate 0-hashes (which represent invalid
        // secp256k1 secret keys, causing downstream application breakage).
        hash[0] = 1;
    }
    Hash(hash)
}

const BLOCK_SIZE: usize = 64;

/// Engine to compute SHA256 hash function.
#[derive(Clone)]
pub struct HashEngine {
    buffer: [u8; BLOCK_SIZE],
    h: [u32; 8],
    length: usize,
}

impl Default for HashEngine {
    fn default() -> Self {
        HashEngine {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            length: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }
}

impl crate::HashEngine for HashEngine {
    type MidState = Midstate;

    #[cfg(not(hashes_fuzz))]
    fn midstate(&self) -> Midstate {
        let mut ret = [0; 32];
        for (val, ret_bytes) in self.h.iter().zip(ret.chunks_exact_mut(4)) {
            ret_bytes.copy_from_slice(&val.to_be_bytes());
        }
        Midstate(ret)
    }

    #[cfg(hashes_fuzz)]
    fn midstate(&self) -> Midstate {
        let mut ret = [0; 32];
        ret.copy_from_slice(&self.buffer[..32]);
        Midstate(ret)
    }

    const BLOCK_SIZE: usize = 64;

    fn n_bytes_hashed(&self) -> usize { self.length }

    engine_input_impl!();
}

impl Hash {
    /// Iterate the sha256 algorithm to turn a sha256 hash into a sha256d hash
    pub fn hash_again(&self) -> sha256d::Hash {
        crate::Hash::from_byte_array(<Self as crate::Hash>::hash(&self.0).0)
    }

    /// Computes hash from `bytes` in `const` context.
    ///
    /// Warning: this function is inefficient. It should be only used in `const` context.
    pub const fn const_hash(bytes: &[u8]) -> Self { Hash(Midstate::const_hash(bytes, true).0) }
}

/// Output of the SHA256 hash function.
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct Midstate(pub [u8; 32]);

crate::internal_macros::arr_newtype_fmt_impl!(Midstate, 32);
serde_impl!(Midstate, 32);
borrow_slice_impl!(Midstate);

impl<I: SliceIndex<[u8]>> Index<I> for Midstate {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output { &self.0[index] }
}

impl str::FromStr for Midstate {
    type Err = hex::HexToArrayError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { hex::FromHex::from_hex(s) }
}

impl Midstate {
    /// Length of the midstate, in bytes.
    const LEN: usize = 32;

    /// Flag indicating whether user-visible serializations of this hash
    /// should be backward. For some reason Satoshi decided this should be
    /// true for `Sha256dHash`, so here we are.
    const DISPLAY_BACKWARD: bool = true;

    /// Construct a new [`Midstate`] from the inner value.
    pub const fn from_byte_array(inner: [u8; 32]) -> Self { Midstate(inner) }

    /// Copies a byte slice into the [`Midstate`] object.
    pub fn from_slice(sl: &[u8]) -> Result<Midstate, FromSliceError> {
        if sl.len() != Self::LEN {
            Err(FromSliceError { expected: Self::LEN, got: sl.len() })
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Midstate(ret))
        }
    }

    /// Unwraps the [`Midstate`] and returns the underlying byte array.
    pub fn to_byte_array(self) -> [u8; 32] { self.0 }

    /// Creates midstate for tagged hashes.
    ///
    /// Warning: this function is inefficient. It should be only used in `const` context.
    ///
    /// Computes non-finalized hash of `sha256(tag) || sha256(tag)` for use in
    /// [`sha256t`](super::sha256t). It's provided for use with [`sha256t`](crate::sha256t).
    pub const fn hash_tag(tag: &[u8]) -> Self {
        let hash = Hash::const_hash(tag);
        let mut buf = [0u8; 64];
        let mut i = 0usize;
        while i < buf.len() {
            buf[i] = hash.0[i % hash.0.len()];
            i += 1;
        }
        Self::const_hash(&buf, false)
    }
}

impl hex::FromHex for Midstate {
    type Err = hex::HexToArrayError;
    fn from_byte_iter<I>(iter: I) -> Result<Self, Self::Err>
    where
        I: Iterator<Item = Result<u8, hex::HexToBytesError>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        // DISPLAY_BACKWARD is true
        Ok(Midstate::from_byte_array(hex::FromHex::from_byte_iter(iter.rev())?))
    }
}

#[allow(non_snake_case)]
const fn Ch(x: u32, y: u32, z: u32) -> u32 { z ^ (x & (y ^ z)) }
#[allow(non_snake_case)]
const fn Maj(x: u32, y: u32, z: u32) -> u32 { (x & y) | (z & (x | y)) }
#[allow(non_snake_case)]
const fn Sigma0(x: u32) -> u32 { x.rotate_left(30) ^ x.rotate_left(19) ^ x.rotate_left(10) }
#[allow(non_snake_case)]
const fn Sigma1(x: u32) -> u32 { x.rotate_left(26) ^ x.rotate_left(21) ^ x.rotate_left(7) }
const fn sigma0(x: u32) -> u32 { x.rotate_left(25) ^ x.rotate_left(14) ^ (x >> 3) }
const fn sigma1(x: u32) -> u32 { x.rotate_left(15) ^ x.rotate_left(13) ^ (x >> 10) }

#[cfg(feature = "small-hash")]
#[macro_use]
mod small_hash {
    use super::*;

    #[rustfmt::skip]
    pub(super) const fn round(a: u32, b: u32, c: u32, d: u32, e: u32,
                              f: u32, g: u32, h: u32, k: u32, w: u32) -> (u32, u32) {
        let t1 =
            h.wrapping_add(Sigma1(e)).wrapping_add(Ch(e, f, g)).wrapping_add(k).wrapping_add(w);
        let t2 = Sigma0(a).wrapping_add(Maj(a, b, c));
        (d.wrapping_add(t1), t1.wrapping_add(t2))
    }
    #[rustfmt::skip]
    pub(super) const fn later_round(a: u32, b: u32, c: u32, d: u32, e: u32,
                                    f: u32, g: u32, h: u32, k: u32, w: u32,
                                    w1: u32, w2: u32, w3: u32,
    ) -> (u32, u32, u32) {
        let w = w.wrapping_add(sigma1(w1)).wrapping_add(w2).wrapping_add(sigma0(w3));
        let (d, h) = round(a, b, c, d, e, f, g, h, k, w);
        (d, h, w)
    }

    macro_rules! round(
        // first round
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr, $w:expr) => (
            let updates = small_hash::round($a, $b, $c, $d, $e, $f, $g, $h, $k, $w);
            $d = updates.0;
            $h = updates.1;
        );
        // later rounds we reassign $w before doing the first-round computation
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr, $w:expr, $w1:expr, $w2:expr, $w3:expr) => (
            let updates = small_hash::later_round($a, $b, $c, $d, $e, $f, $g, $h, $k, $w, $w1, $w2, $w3);
            $d = updates.0;
            $h = updates.1;
            $w = updates.2;
        )
    );
}

#[cfg(not(feature = "small-hash"))]
#[macro_use]
mod fast_hash {
    macro_rules! round(
        // first round
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr, $w:expr) => (
            let t1 = $h.wrapping_add(Sigma1($e)).wrapping_add(Ch($e, $f, $g)).wrapping_add($k).wrapping_add($w);
            let t2 = Sigma0($a).wrapping_add(Maj($a, $b, $c));
            $d = $d.wrapping_add(t1);
            $h = t1.wrapping_add(t2);
        );
        // later rounds we reassign $w before doing the first-round computation
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr, $w:expr, $w1:expr, $w2:expr, $w3:expr) => (
            $w = $w.wrapping_add(sigma1($w1)).wrapping_add($w2).wrapping_add(sigma0($w3));
            round!($a, $b, $c, $d, $e, $f, $g, $h, $k, $w);
        )
    );
}

impl Midstate {
    #[allow(clippy::identity_op)] // more readble
    const fn read_u32(bytes: &[u8], index: usize) -> u32 {
        ((bytes[index + 0] as u32) << 24)
            | ((bytes[index + 1] as u32) << 16)
            | ((bytes[index + 2] as u32) << 8)
            | ((bytes[index + 3] as u32) << 0)
    }

    const fn copy_w(bytes: &[u8], index: usize) -> [u32; 16] {
        let mut w = [0u32; 16];
        let mut i = 0;
        while i < 16 {
            w[i] = Self::read_u32(bytes, index + i * 4);
            i += 1;
        }
        w
    }

    const fn const_hash(bytes: &[u8], finalize: bool) -> Self {
        let mut state = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];

        let num_chunks = (bytes.len() + 9 + 63) / 64;
        let mut chunk = 0;
        #[allow(clippy::precedence)]
        while chunk < num_chunks {
            if !finalize && chunk + 1 == num_chunks {
                break;
            }
            let mut w = if chunk * 64 + 64 <= bytes.len() {
                Self::copy_w(bytes, chunk * 64)
            } else {
                let mut buf = [0; 64];
                let mut i = 0;
                let offset = chunk * 64;
                while offset + i < bytes.len() {
                    buf[i] = bytes[offset + i];
                    i += 1;
                }
                if (bytes.len() % 64 <= 64 - 9) || (chunk + 2 == num_chunks) {
                    buf[i] = 0x80;
                }
                #[allow(clippy::identity_op)] // more readble
                #[allow(clippy::erasing_op)]
                if chunk + 1 == num_chunks {
                    let bit_len = bytes.len() as u64 * 8;
                    buf[64 - 8] = ((bit_len >> 8 * 7) & 0xFF) as u8;
                    buf[64 - 7] = ((bit_len >> 8 * 6) & 0xFF) as u8;
                    buf[64 - 6] = ((bit_len >> 8 * 5) & 0xFF) as u8;
                    buf[64 - 5] = ((bit_len >> 8 * 4) & 0xFF) as u8;
                    buf[64 - 4] = ((bit_len >> 8 * 3) & 0xFF) as u8;
                    buf[64 - 3] = ((bit_len >> 8 * 2) & 0xFF) as u8;
                    buf[64 - 2] = ((bit_len >> 8 * 1) & 0xFF) as u8;
                    buf[64 - 1] = ((bit_len >> 8 * 0) & 0xFF) as u8;
                }
                Self::copy_w(&buf, 0)
            };
            chunk += 1;

            let mut a = state[0];
            let mut b = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let mut e = state[4];
            let mut f = state[5];
            let mut g = state[6];
            let mut h = state[7];

            round!(a, b, c, d, e, f, g, h, 0x428a2f98, w[0]);
            round!(h, a, b, c, d, e, f, g, 0x71374491, w[1]);
            round!(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w[2]);
            round!(f, g, h, a, b, c, d, e, 0xe9b5dba5, w[3]);
            round!(e, f, g, h, a, b, c, d, 0x3956c25b, w[4]);
            round!(d, e, f, g, h, a, b, c, 0x59f111f1, w[5]);
            round!(c, d, e, f, g, h, a, b, 0x923f82a4, w[6]);
            round!(b, c, d, e, f, g, h, a, 0xab1c5ed5, w[7]);
            round!(a, b, c, d, e, f, g, h, 0xd807aa98, w[8]);
            round!(h, a, b, c, d, e, f, g, 0x12835b01, w[9]);
            round!(g, h, a, b, c, d, e, f, 0x243185be, w[10]);
            round!(f, g, h, a, b, c, d, e, 0x550c7dc3, w[11]);
            round!(e, f, g, h, a, b, c, d, 0x72be5d74, w[12]);
            round!(d, e, f, g, h, a, b, c, 0x80deb1fe, w[13]);
            round!(c, d, e, f, g, h, a, b, 0x9bdc06a7, w[14]);
            round!(b, c, d, e, f, g, h, a, 0xc19bf174, w[15]);

            round!(a, b, c, d, e, f, g, h, 0xe49b69c1, w[0], w[14], w[9], w[1]);
            round!(h, a, b, c, d, e, f, g, 0xefbe4786, w[1], w[15], w[10], w[2]);
            round!(g, h, a, b, c, d, e, f, 0x0fc19dc6, w[2], w[0], w[11], w[3]);
            round!(f, g, h, a, b, c, d, e, 0x240ca1cc, w[3], w[1], w[12], w[4]);
            round!(e, f, g, h, a, b, c, d, 0x2de92c6f, w[4], w[2], w[13], w[5]);
            round!(d, e, f, g, h, a, b, c, 0x4a7484aa, w[5], w[3], w[14], w[6]);
            round!(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w[6], w[4], w[15], w[7]);
            round!(b, c, d, e, f, g, h, a, 0x76f988da, w[7], w[5], w[0], w[8]);
            round!(a, b, c, d, e, f, g, h, 0x983e5152, w[8], w[6], w[1], w[9]);
            round!(h, a, b, c, d, e, f, g, 0xa831c66d, w[9], w[7], w[2], w[10]);
            round!(g, h, a, b, c, d, e, f, 0xb00327c8, w[10], w[8], w[3], w[11]);
            round!(f, g, h, a, b, c, d, e, 0xbf597fc7, w[11], w[9], w[4], w[12]);
            round!(e, f, g, h, a, b, c, d, 0xc6e00bf3, w[12], w[10], w[5], w[13]);
            round!(d, e, f, g, h, a, b, c, 0xd5a79147, w[13], w[11], w[6], w[14]);
            round!(c, d, e, f, g, h, a, b, 0x06ca6351, w[14], w[12], w[7], w[15]);
            round!(b, c, d, e, f, g, h, a, 0x14292967, w[15], w[13], w[8], w[0]);

            round!(a, b, c, d, e, f, g, h, 0x27b70a85, w[0], w[14], w[9], w[1]);
            round!(h, a, b, c, d, e, f, g, 0x2e1b2138, w[1], w[15], w[10], w[2]);
            round!(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w[2], w[0], w[11], w[3]);
            round!(f, g, h, a, b, c, d, e, 0x53380d13, w[3], w[1], w[12], w[4]);
            round!(e, f, g, h, a, b, c, d, 0x650a7354, w[4], w[2], w[13], w[5]);
            round!(d, e, f, g, h, a, b, c, 0x766a0abb, w[5], w[3], w[14], w[6]);
            round!(c, d, e, f, g, h, a, b, 0x81c2c92e, w[6], w[4], w[15], w[7]);
            round!(b, c, d, e, f, g, h, a, 0x92722c85, w[7], w[5], w[0], w[8]);
            round!(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w[8], w[6], w[1], w[9]);
            round!(h, a, b, c, d, e, f, g, 0xa81a664b, w[9], w[7], w[2], w[10]);
            round!(g, h, a, b, c, d, e, f, 0xc24b8b70, w[10], w[8], w[3], w[11]);
            round!(f, g, h, a, b, c, d, e, 0xc76c51a3, w[11], w[9], w[4], w[12]);
            round!(e, f, g, h, a, b, c, d, 0xd192e819, w[12], w[10], w[5], w[13]);
            round!(d, e, f, g, h, a, b, c, 0xd6990624, w[13], w[11], w[6], w[14]);
            round!(c, d, e, f, g, h, a, b, 0xf40e3585, w[14], w[12], w[7], w[15]);
            round!(b, c, d, e, f, g, h, a, 0x106aa070, w[15], w[13], w[8], w[0]);

            round!(a, b, c, d, e, f, g, h, 0x19a4c116, w[0], w[14], w[9], w[1]);
            round!(h, a, b, c, d, e, f, g, 0x1e376c08, w[1], w[15], w[10], w[2]);
            round!(g, h, a, b, c, d, e, f, 0x2748774c, w[2], w[0], w[11], w[3]);
            round!(f, g, h, a, b, c, d, e, 0x34b0bcb5, w[3], w[1], w[12], w[4]);
            round!(e, f, g, h, a, b, c, d, 0x391c0cb3, w[4], w[2], w[13], w[5]);
            round!(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w[5], w[3], w[14], w[6]);
            round!(c, d, e, f, g, h, a, b, 0x5b9cca4f, w[6], w[4], w[15], w[7]);
            round!(b, c, d, e, f, g, h, a, 0x682e6ff3, w[7], w[5], w[0], w[8]);
            round!(a, b, c, d, e, f, g, h, 0x748f82ee, w[8], w[6], w[1], w[9]);
            round!(h, a, b, c, d, e, f, g, 0x78a5636f, w[9], w[7], w[2], w[10]);
            round!(g, h, a, b, c, d, e, f, 0x84c87814, w[10], w[8], w[3], w[11]);
            round!(f, g, h, a, b, c, d, e, 0x8cc70208, w[11], w[9], w[4], w[12]);
            round!(e, f, g, h, a, b, c, d, 0x90befffa, w[12], w[10], w[5], w[13]);
            round!(d, e, f, g, h, a, b, c, 0xa4506ceb, w[13], w[11], w[6], w[14]);
            round!(c, d, e, f, g, h, a, b, 0xbef9a3f7, w[14], w[12], w[7], w[15]);
            round!(b, c, d, e, f, g, h, a, 0xc67178f2, w[15], w[13], w[8], w[0]);

            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
            state[4] = state[4].wrapping_add(e);
            state[5] = state[5].wrapping_add(f);
            state[6] = state[6].wrapping_add(g);
            state[7] = state[7].wrapping_add(h);
        }
        let mut output = [0u8; 32];
        let mut i = 0;
        #[allow(clippy::identity_op)] // more readble
        while i < 8 {
            output[i * 4 + 0] = (state[i + 0] >> 24) as u8;
            output[i * 4 + 1] = (state[i + 0] >> 16) as u8;
            output[i * 4 + 2] = (state[i + 0] >> 8) as u8;
            output[i * 4 + 3] = (state[i + 0] >> 0) as u8;
            i += 1;
        }
        Midstate(output)
    }
}

impl HashEngine {
    /// Create a new [`HashEngine`] from a [`Midstate`].
    ///
    /// # Panics
    ///
    /// If `length` is not a multiple of the block size.
    pub fn from_midstate(midstate: Midstate, length: usize) -> HashEngine {
        assert!(length % BLOCK_SIZE == 0, "length is no multiple of the block size");

        let mut ret = [0; 8];
        for (ret_val, midstate_bytes) in ret.iter_mut().zip(midstate[..].chunks_exact(4)) {
            *ret_val = u32::from_be_bytes(midstate_bytes.try_into().expect("4 byte slice"));
        }

        HashEngine { buffer: [0; BLOCK_SIZE], h: ret, length }
    }

    fn process_block(&mut self) {
        #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
        {
            if is_x86_feature_detected!("sse4.1")
                && is_x86_feature_detected!("sha")
                && is_x86_feature_detected!("sse2")
                && is_x86_feature_detected!("ssse3")
            {
                return unsafe { self.process_block_simd_x86_intrinsics() };
            }
        }

        // fallback implementation without using any intrinsics
        self.software_process_block()
    }

    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn process_block_simd_x86_intrinsics(&mut self) {
        // Code translated and based on from
        // https://github.com/noloader/SHA-Intrinsics/blob/4899efc81d1af159c1fd955936c673139f35aea9/sha256-x86.c

        /* sha256-x86.c - Intel SHA extensions using C intrinsics  */
        /*   Written and place in public domain by Jeffrey Walton  */
        /*   Based on code from Intel, and by Sean Gulley for      */
        /*   the miTLS project.                                    */

        // Variable names are also kept the same as in the original C code for easier comparison.
        let (mut state0, mut state1);
        let (mut msg, mut tmp);

        let (mut msg0, mut msg1, mut msg2, mut msg3);

        let (abef_save, cdgh_save);

        #[allow(non_snake_case)]
        let MASK: __m128i =
            _mm_set_epi64x(0x0c0d_0e0f_0809_0a0bu64 as i64, 0x0405_0607_0001_0203u64 as i64);

        let block_offset = 0;

        // Load initial values
        // CAST SAFETY: loadu_si128 documentation states that mem_addr does not
        // need to be aligned on any particular boundary.
        tmp = _mm_loadu_si128(self.h.as_ptr().add(0) as *const __m128i);
        state1 = _mm_loadu_si128(self.h.as_ptr().add(4) as *const __m128i);

        tmp = _mm_shuffle_epi32(tmp, 0xB1); // CDAB
        state1 = _mm_shuffle_epi32(state1, 0x1B); // EFGH
        state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
        state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

        // Process a single block
        {
            // Save current state
            abef_save = state0;
            cdgh_save = state1;

            // Rounds 0-3
            msg = _mm_loadu_si128(self.buffer.as_ptr().add(block_offset) as *const __m128i);
            msg0 = _mm_shuffle_epi8(msg, MASK);
            msg = _mm_add_epi32(
                msg0,
                _mm_set_epi64x(0xE9B5DBA5B5C0FBCFu64 as i64, 0x71374491428A2F98u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 4-7
            msg1 = _mm_loadu_si128(self.buffer.as_ptr().add(block_offset + 16) as *const __m128i);
            msg1 = _mm_shuffle_epi8(msg1, MASK);
            msg = _mm_add_epi32(
                msg1,
                _mm_set_epi64x(0xAB1C5ED5923F82A4u64 as i64, 0x59F111F13956C25Bu64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 8-11
            msg2 = _mm_loadu_si128(self.buffer.as_ptr().add(block_offset + 32) as *const __m128i);
            msg2 = _mm_shuffle_epi8(msg2, MASK);
            msg = _mm_add_epi32(
                msg2,
                _mm_set_epi64x(0x550C7DC3243185BEu64 as i64, 0x12835B01D807AA98u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 12-15
            msg3 = _mm_loadu_si128(self.buffer.as_ptr().add(block_offset + 48) as *const __m128i);
            msg3 = _mm_shuffle_epi8(msg3, MASK);
            msg = _mm_add_epi32(
                msg3,
                _mm_set_epi64x(0xC19BF1749BDC06A7u64 as i64, 0x80DEB1FE72BE5D74u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg3, msg2, 4);
            msg0 = _mm_add_epi32(msg0, tmp);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 16-19
            msg = _mm_add_epi32(
                msg0,
                _mm_set_epi64x(0x240CA1CC0FC19DC6u64 as i64, 0xEFBE4786E49B69C1u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg0, msg3, 4);
            msg1 = _mm_add_epi32(msg1, tmp);
            msg1 = _mm_sha256msg2_epu32(msg1, msg0);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msg0);

            // Rounds 20-23
            msg = _mm_add_epi32(
                msg1,
                _mm_set_epi64x(0x76F988DA5CB0A9DCu64 as i64, 0x4A7484AA2DE92C6Fu64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg1, msg0, 4);
            msg2 = _mm_add_epi32(msg2, tmp);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 24-27
            msg = _mm_add_epi32(
                msg2,
                _mm_set_epi64x(0xBF597FC7B00327C8u64 as i64, 0xA831C66D983E5152u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 28-31
            msg = _mm_add_epi32(
                msg3,
                _mm_set_epi64x(0x1429296706CA6351u64 as i64, 0xD5A79147C6E00BF3u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg3, msg2, 4);
            msg0 = _mm_add_epi32(msg0, tmp);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 32-35
            msg = _mm_add_epi32(
                msg0,
                _mm_set_epi64x(0x53380D134D2C6DFCu64 as i64, 0x2E1B213827B70A85u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg0, msg3, 4);
            msg1 = _mm_add_epi32(msg1, tmp);
            msg1 = _mm_sha256msg2_epu32(msg1, msg0);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msg0);

            // Rounds 36-39
            msg = _mm_add_epi32(
                msg1,
                _mm_set_epi64x(0x92722C8581C2C92Eu64 as i64, 0x766A0ABB650A7354u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg1, msg0, 4);
            msg2 = _mm_add_epi32(msg2, tmp);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 40-43
            msg = _mm_add_epi32(
                msg2,
                _mm_set_epi64x(0xC76C51A3C24B8B70u64 as i64, 0xA81A664BA2BFE8A1u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 44-47
            msg = _mm_add_epi32(
                msg3,
                _mm_set_epi64x(0x106AA070F40E3585u64 as i64, 0xD6990624D192E819u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg3, msg2, 4);
            msg0 = _mm_add_epi32(msg0, tmp);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 48-51
            msg = _mm_add_epi32(
                msg0,
                _mm_set_epi64x(0x34B0BCB52748774Cu64 as i64, 0x1E376C0819A4C116u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg0, msg3, 4);
            msg1 = _mm_add_epi32(msg1, tmp);
            msg1 = _mm_sha256msg2_epu32(msg1, msg0);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msg0);

            // Rounds 52-55
            msg = _mm_add_epi32(
                msg1,
                _mm_set_epi64x(0x682E6FF35B9CCA4Fu64 as i64, 0x4ED8AA4A391C0CB3u64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg1, msg0, 4);
            msg2 = _mm_add_epi32(msg2, tmp);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 56-59
            msg = _mm_add_epi32(
                msg2,
                _mm_set_epi64x(0x8CC7020884C87814u64 as i64, 0x78A5636F748F82EEu64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 60-63
            msg = _mm_add_epi32(
                msg3,
                _mm_set_epi64x(0xC67178F2BEF9A3F7u64 as i64, 0xA4506CEB90BEFFFAu64 as i64),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Combine state
            state0 = _mm_add_epi32(state0, abef_save);
            state1 = _mm_add_epi32(state1, cdgh_save);
        }

        tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
        state1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
        state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
        state1 = _mm_alignr_epi8(state1, tmp, 8); // ABEF

        // Save state
        // CAST SAFETY: storeu_si128 documentation states that mem_addr does not
        // need to be aligned on any particular boundary.
        _mm_storeu_si128(self.h.as_mut_ptr().add(0) as *mut __m128i, state0);
        _mm_storeu_si128(self.h.as_mut_ptr().add(4) as *mut __m128i, state1);
    }

    // Algorithm copied from libsecp256k1
    fn software_process_block(&mut self) {
        debug_assert_eq!(self.buffer.len(), BLOCK_SIZE);

        let mut w = [0u32; 16];
        for (w_val, buff_bytes) in w.iter_mut().zip(self.buffer.chunks_exact(4)) {
            *w_val = u32::from_be_bytes(buff_bytes.try_into().expect("4 byte slice"));
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        round!(a, b, c, d, e, f, g, h, 0x428a2f98, w[0]);
        round!(h, a, b, c, d, e, f, g, 0x71374491, w[1]);
        round!(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w[2]);
        round!(f, g, h, a, b, c, d, e, 0xe9b5dba5, w[3]);
        round!(e, f, g, h, a, b, c, d, 0x3956c25b, w[4]);
        round!(d, e, f, g, h, a, b, c, 0x59f111f1, w[5]);
        round!(c, d, e, f, g, h, a, b, 0x923f82a4, w[6]);
        round!(b, c, d, e, f, g, h, a, 0xab1c5ed5, w[7]);
        round!(a, b, c, d, e, f, g, h, 0xd807aa98, w[8]);
        round!(h, a, b, c, d, e, f, g, 0x12835b01, w[9]);
        round!(g, h, a, b, c, d, e, f, 0x243185be, w[10]);
        round!(f, g, h, a, b, c, d, e, 0x550c7dc3, w[11]);
        round!(e, f, g, h, a, b, c, d, 0x72be5d74, w[12]);
        round!(d, e, f, g, h, a, b, c, 0x80deb1fe, w[13]);
        round!(c, d, e, f, g, h, a, b, 0x9bdc06a7, w[14]);
        round!(b, c, d, e, f, g, h, a, 0xc19bf174, w[15]);

        round!(a, b, c, d, e, f, g, h, 0xe49b69c1, w[0], w[14], w[9], w[1]);
        round!(h, a, b, c, d, e, f, g, 0xefbe4786, w[1], w[15], w[10], w[2]);
        round!(g, h, a, b, c, d, e, f, 0x0fc19dc6, w[2], w[0], w[11], w[3]);
        round!(f, g, h, a, b, c, d, e, 0x240ca1cc, w[3], w[1], w[12], w[4]);
        round!(e, f, g, h, a, b, c, d, 0x2de92c6f, w[4], w[2], w[13], w[5]);
        round!(d, e, f, g, h, a, b, c, 0x4a7484aa, w[5], w[3], w[14], w[6]);
        round!(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w[6], w[4], w[15], w[7]);
        round!(b, c, d, e, f, g, h, a, 0x76f988da, w[7], w[5], w[0], w[8]);
        round!(a, b, c, d, e, f, g, h, 0x983e5152, w[8], w[6], w[1], w[9]);
        round!(h, a, b, c, d, e, f, g, 0xa831c66d, w[9], w[7], w[2], w[10]);
        round!(g, h, a, b, c, d, e, f, 0xb00327c8, w[10], w[8], w[3], w[11]);
        round!(f, g, h, a, b, c, d, e, 0xbf597fc7, w[11], w[9], w[4], w[12]);
        round!(e, f, g, h, a, b, c, d, 0xc6e00bf3, w[12], w[10], w[5], w[13]);
        round!(d, e, f, g, h, a, b, c, 0xd5a79147, w[13], w[11], w[6], w[14]);
        round!(c, d, e, f, g, h, a, b, 0x06ca6351, w[14], w[12], w[7], w[15]);
        round!(b, c, d, e, f, g, h, a, 0x14292967, w[15], w[13], w[8], w[0]);

        round!(a, b, c, d, e, f, g, h, 0x27b70a85, w[0], w[14], w[9], w[1]);
        round!(h, a, b, c, d, e, f, g, 0x2e1b2138, w[1], w[15], w[10], w[2]);
        round!(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w[2], w[0], w[11], w[3]);
        round!(f, g, h, a, b, c, d, e, 0x53380d13, w[3], w[1], w[12], w[4]);
        round!(e, f, g, h, a, b, c, d, 0x650a7354, w[4], w[2], w[13], w[5]);
        round!(d, e, f, g, h, a, b, c, 0x766a0abb, w[5], w[3], w[14], w[6]);
        round!(c, d, e, f, g, h, a, b, 0x81c2c92e, w[6], w[4], w[15], w[7]);
        round!(b, c, d, e, f, g, h, a, 0x92722c85, w[7], w[5], w[0], w[8]);
        round!(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w[8], w[6], w[1], w[9]);
        round!(h, a, b, c, d, e, f, g, 0xa81a664b, w[9], w[7], w[2], w[10]);
        round!(g, h, a, b, c, d, e, f, 0xc24b8b70, w[10], w[8], w[3], w[11]);
        round!(f, g, h, a, b, c, d, e, 0xc76c51a3, w[11], w[9], w[4], w[12]);
        round!(e, f, g, h, a, b, c, d, 0xd192e819, w[12], w[10], w[5], w[13]);
        round!(d, e, f, g, h, a, b, c, 0xd6990624, w[13], w[11], w[6], w[14]);
        round!(c, d, e, f, g, h, a, b, 0xf40e3585, w[14], w[12], w[7], w[15]);
        round!(b, c, d, e, f, g, h, a, 0x106aa070, w[15], w[13], w[8], w[0]);

        round!(a, b, c, d, e, f, g, h, 0x19a4c116, w[0], w[14], w[9], w[1]);
        round!(h, a, b, c, d, e, f, g, 0x1e376c08, w[1], w[15], w[10], w[2]);
        round!(g, h, a, b, c, d, e, f, 0x2748774c, w[2], w[0], w[11], w[3]);
        round!(f, g, h, a, b, c, d, e, 0x34b0bcb5, w[3], w[1], w[12], w[4]);
        round!(e, f, g, h, a, b, c, d, 0x391c0cb3, w[4], w[2], w[13], w[5]);
        round!(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w[5], w[3], w[14], w[6]);
        round!(c, d, e, f, g, h, a, b, 0x5b9cca4f, w[6], w[4], w[15], w[7]);
        round!(b, c, d, e, f, g, h, a, 0x682e6ff3, w[7], w[5], w[0], w[8]);
        round!(a, b, c, d, e, f, g, h, 0x748f82ee, w[8], w[6], w[1], w[9]);
        round!(h, a, b, c, d, e, f, g, 0x78a5636f, w[9], w[7], w[2], w[10]);
        round!(g, h, a, b, c, d, e, f, 0x84c87814, w[10], w[8], w[3], w[11]);
        round!(f, g, h, a, b, c, d, e, 0x8cc70208, w[11], w[9], w[4], w[12]);
        round!(e, f, g, h, a, b, c, d, 0x90befffa, w[12], w[10], w[5], w[13]);
        round!(d, e, f, g, h, a, b, c, 0xa4506ceb, w[13], w[11], w[6], w[14]);
        round!(c, d, e, f, g, h, a, b, 0xbef9a3f7, w[14], w[12], w[7], w[15]);
        round!(b, c, d, e, f, g, h, a, 0xc67178f2, w[15], w[13], w[8], w[0]);

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use crate::{sha256, Hash, HashEngine};

    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        #[derive(Clone)]
        struct Test {
            input: &'static str,
            output: Vec<u8>,
            output_str: &'static str,
        }

        #[rustfmt::skip]
        let tests = vec![
            // Examples from wikipedia
            Test {
                input: "",
                output: vec![
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                ],
                output_str: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output: vec![
                    0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94,
                    0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f,
                    0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76,
                    0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92,
                ],
                output_str: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output: vec![
                    0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
                    0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97,
                    0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2,
                    0xb7, 0x65, 0x44, 0x8c, 0x86, 0x35, 0xfb, 0x6c,
                ],
                output_str: "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
            },
        ];

        for test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = sha256::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<sha256::Hash>().expect("parse hex"));
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = sha256::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            let manual_hash = sha256::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);
            assert_eq!(hash.to_byte_array()[..].as_ref(), test.output.as_slice());
        }
    }

    #[test]
    #[rustfmt::skip]
    fn midstate() {
        // Test vector obtained by doing an asset issuance on Elements
        let mut engine = sha256::Hash::engine();
        // sha256dhash of outpoint
        // 73828cbc65fd68ab78dc86992b76ae50ae2bf8ceedbe8de0483172f0886219f7:0
        engine.input(&[
            0x9d, 0xd0, 0x1b, 0x56, 0xb1, 0x56, 0x45, 0x14,
            0x3e, 0xad, 0x15, 0x8d, 0xec, 0x19, 0xf8, 0xce,
            0xa9, 0x0b, 0xd0, 0xa9, 0xb2, 0xf8, 0x1d, 0x21,
            0xff, 0xa3, 0xa4, 0xc6, 0x44, 0x81, 0xd4, 0x1c,
        ]);
        // 32 bytes of zeroes representing "new asset"
        engine.input(&[0; 32]);
        assert_eq!(
            engine.midstate(),
            // RPC output
            sha256::Midstate::from_byte_array([
                0x0b, 0xcf, 0xe0, 0xe5, 0x4e, 0x6c, 0xc7, 0xd3,
                0x4f, 0x4f, 0x7c, 0x1d, 0xf0, 0xb0, 0xf5, 0x03,
                0xf2, 0xf7, 0x12, 0x91, 0x2a, 0x06, 0x05, 0xb4,
                0x14, 0xed, 0x33, 0x7f, 0x7f, 0x03, 0x2e, 0x03,
            ])
        );
    }

    #[test]
    fn engine_with_state() {
        let mut engine = sha256::Hash::engine();
        let midstate_engine = sha256::HashEngine::from_midstate(engine.midstate(), 0);
        // Fresh engine and engine initialized with fresh state should have same state
        assert_eq!(engine.h, midstate_engine.h);

        // Midstate changes after writing 64 bytes
        engine.input(&[1; 63]);
        assert_eq!(engine.h, midstate_engine.h);
        engine.input(&[2; 1]);
        assert_ne!(engine.h, midstate_engine.h);

        // Initializing an engine with midstate from another engine should result in
        // both engines producing the same hashes
        let data_vec = vec![vec![3; 1], vec![4; 63], vec![5; 65], vec![6; 66]];
        for data in data_vec {
            let mut engine = engine.clone();
            let mut midstate_engine =
                sha256::HashEngine::from_midstate(engine.midstate(), engine.length);
            assert_eq!(engine.h, midstate_engine.h);
            assert_eq!(engine.length, midstate_engine.length);
            engine.input(&data);
            midstate_engine.input(&data);
            assert_eq!(engine.h, midstate_engine.h);
            let hash1 = sha256::Hash::from_engine(engine);
            let hash2 = sha256::Hash::from_engine(midstate_engine);
            assert_eq!(hash1, hash2);
        }

        // Test that a specific midstate results in a specific hash. Midstate was
        // obtained by applying sha256 to sha256("MuSig coefficient")||sha256("MuSig
        // coefficient").
        #[rustfmt::skip]
        static MIDSTATE: [u8; 32] = [
            0x0f, 0xd0, 0x69, 0x0c, 0xfe, 0xfe, 0xae, 0x97,
            0x99, 0x6e, 0xac, 0x7f, 0x5c, 0x30, 0xd8, 0x64,
            0x8c, 0x4a, 0x05, 0x73, 0xac, 0xa1, 0xa2, 0x2f,
            0x6f, 0x43, 0xb8, 0x01, 0x85, 0xce, 0x27, 0xcd,
        ];
        #[rustfmt::skip]
        static HASH_EXPECTED: [u8; 32] = [
            0x18, 0x84, 0xe4, 0x72, 0x40, 0x4e, 0xf4, 0x5a,
            0xb4, 0x9c, 0x4e, 0xa4, 0x9a, 0xe6, 0x23, 0xa8,
            0x88, 0x52, 0x7f, 0x7d, 0x8a, 0x06, 0x94, 0x20,
            0x8f, 0xf1, 0xf7, 0xa9, 0xd5, 0x69, 0x09, 0x59,
        ];
        let midstate_engine =
            sha256::HashEngine::from_midstate(sha256::Midstate::from_byte_array(MIDSTATE), 64);
        let hash = sha256::Hash::from_engine(midstate_engine);
        assert_eq!(hash, sha256::Hash(HASH_EXPECTED));
    }

    #[test]
    fn const_hash() {
        assert_eq!(super::Hash::hash(&[]), super::Hash::const_hash(&[]));

        let mut bytes = Vec::new();
        for i in 0..256 {
            bytes.push(i as u8);
            assert_eq!(
                super::Hash::hash(&bytes),
                super::Hash::const_hash(&bytes),
                "hashes don't match for length {}",
                i + 1
            );
        }
    }

    #[test]
    fn const_midstate() {
        use super::Midstate;

        assert_eq!(
            Midstate::hash_tag(b"TapLeaf"),
            Midstate([
                156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211,
                243, 147, 108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
            ])
        )
    }

    #[cfg(feature = "serde")]
    #[test]
    fn sha256_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        #[rustfmt::skip]
        static HASH_BYTES: [u8; 32] = [
            0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
            0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97,
            0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2,
            0xb7, 0x65, 0x44, 0x8c, 0x86, 0x35, 0xfb, 0x6c,
        ];

        let hash = sha256::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
        assert_tokens(
            &hash.readable(),
            &[Token::Str("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c")],
        );
    }

    #[cfg(target_arch = "wasm32")]
    mod wasm_tests {
        extern crate wasm_bindgen_test;
        use self::wasm_bindgen_test::*;
        use super::*;
        #[wasm_bindgen_test]
        fn sha256_tests() {
            test();
            midstate();
            engine_with_state();
        }
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{sha256, Hash, HashEngine};

    #[bench]
    pub fn sha256_10(bh: &mut Bencher) {
        let mut engine = sha256::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256_1k(bh: &mut Bencher) {
        let mut engine = sha256::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256_64k(bh: &mut Bencher) {
        let mut engine = sha256::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
