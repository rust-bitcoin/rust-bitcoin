// SPDX-License-Identifier: CC0-1.0

#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_ptr_alignment)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::many_single_char_names)]

#[cfg(target_arch = "aarch64")]
#[cfg(any(feature = "cpufeatures", feature = "std"))]
mod arm_sha2;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(any(feature = "cpufeatures", feature = "std"))]
mod x86_shani;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(any(feature = "cpufeatures", feature = "std"))]
mod sse41;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(any(feature = "cpufeatures", feature = "std"))]
mod avx2;

use internals::slice::SliceExt;

use super::{HashEngine, Midstate, BLOCK_SIZE};

#[cfg(feature = "cpufeatures")]
#[cfg(target_arch = "aarch64")]
// cpufeatures crate internally uses `u8::max_value()` which will be deprecated.
// See: https://docs.rs/cpufeatures/0.2.17/src/cpufeatures/lib.rs.html#161
#[allow(deprecated_in_future)]
mod cpuid_sha256_aarch64 {
    cpufeatures::new!(inner, "sha2");
    pub fn get() -> bool { inner::get() }
}
#[cfg(feature = "cpufeatures")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// cpufeatures crate internally uses `u8::max_value()` which will be deprecated.
// See: https://docs.rs/cpufeatures/0.2.17/src/cpufeatures/lib.rs.html#161
#[allow(deprecated_in_future)]
mod cpuid_sha256_x86 {
    cpufeatures::new!(inner, "sha", "sse2", "ssse3", "sse4.1");
    pub fn get() -> bool { inner::get() }
}
#[cfg(feature = "cpufeatures")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(deprecated_in_future)]
mod cpuid_sse41_x86 {
    cpufeatures::new!(inner, "sse2", "ssse3", "sse4.1");
    pub fn get() -> bool { inner::get() }
}
#[cfg(feature = "cpufeatures")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(deprecated_in_future)]
mod cpuid_avx2_x86 {
    cpufeatures::new!(inner, "avx", "avx2");
    pub fn get() -> bool { inner::get() }
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
    use super::{sigma0, sigma1, Ch, Maj, Sigma0, Sigma1};

    #[rustfmt::skip]
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn round(a: u32, b: u32, c: u32, d: u32, e: u32,
                              f: u32, g: u32, h: u32, k: u32, w: u32) -> (u32, u32) {
        let t1 =
            h.wrapping_add(Sigma1(e)).wrapping_add(Ch(e, f, g)).wrapping_add(k).wrapping_add(w);
        let t2 = Sigma0(a).wrapping_add(Maj(a, b, c));
        (d.wrapping_add(t1), t1.wrapping_add(t2))
    }
    #[rustfmt::skip]
    #[allow(clippy::too_many_arguments)]
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
    #[allow(clippy::identity_op)] // more readable
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

    pub(super) const fn compute_midstate_unoptimized(bytes: &[u8], finalize: bool) -> Self {
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

        let num_chunks = (bytes.len() + 9).div_ceil(64);
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
                #[allow(clippy::identity_op)] // more readable
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
        #[allow(clippy::identity_op)] // more readable
        while i < 8 {
            output[i * 4 + 0] = (state[i + 0] >> 24) as u8;
            output[i * 4 + 1] = (state[i + 0] >> 16) as u8;
            output[i * 4 + 2] = (state[i + 0] >> 8) as u8;
            output[i * 4 + 3] = (state[i + 0] >> 0) as u8;
            i += 1;
        }
        Self { bytes: output, bytes_hashed: bytes.len() as u64 }
    }
}

impl HashEngine {
    pub(super) fn process_blocks(state: &mut [u32; 8], blocks: &[u8]) {
        #[cfg(feature = "std")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("sse4.1")
                && std::is_x86_feature_detected!("sha")
                && std::is_x86_feature_detected!("sse2")
                && std::is_x86_feature_detected!("ssse3")
            {
                unsafe { x86_shani::process_blocks(state, blocks) };
                return;
            }
        }

        #[cfg(feature = "cpufeatures")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if cpuid_sha256_x86::get() {
                unsafe { x86_shani::process_blocks(state, blocks) };
                return;
            }
        }

        #[cfg(feature = "std")]
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("sha2") {
                unsafe { arm_sha2::process_blocks(state, blocks) };
                return;
            }
        }

        #[cfg(feature = "cpufeatures")]
        #[cfg(target_arch = "aarch64")]
        {
            if cpuid_sha256_aarch64::get() {
                unsafe { arm_sha2::process_blocks(state, blocks) };
                return;
            }
        }

        // fallback implementation without using any intrinsics
        Self::software_process_block(state, blocks);
    }

    pub(crate) fn sha256d_64(outputs: &mut [[u8; 32]], inputs: &[[u8; 64]]) {
        assert_eq!(outputs.len(), inputs.len());
        let mut i = 0;
        let count = inputs.len();

        // 2-way x86 SHA-NI
        #[cfg(feature = "std")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("sse4.1")
                && std::is_x86_feature_detected!("sha")
                && std::is_x86_feature_detected!("sse2")
                && std::is_x86_feature_detected!("ssse3")
            {
                while count - i >= 2 {
                    let out = <&mut [[u8; 32]; 2]>::try_from(&mut outputs[i..i + 2]).unwrap();
                    let inp = <&[[u8; 64]; 2]>::try_from(&inputs[i..i + 2]).unwrap();
                    unsafe { x86_shani::sha256d_64_2way(out, inp) };
                    i += 2;
                }
            }
        }

        #[cfg(feature = "cpufeatures")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if cpuid_sha256_x86::get() {
                while count - i >= 2 {
                    let out = <&mut [[u8; 32]; 2]>::try_from(&mut outputs[i..i + 2]).unwrap();
                    let inp = <&[[u8; 64]; 2]>::try_from(&inputs[i..i + 2]).unwrap();
                    unsafe { x86_shani::sha256d_64_2way(out, inp) };
                    i += 2;
                }
            }
        }

        // 2-way ARM SHA2
        #[cfg(feature = "std")]
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("sha2") {
                while count - i >= 2 {
                    let out = <&mut [[u8; 32]; 2]>::try_from(&mut outputs[i..i + 2]).unwrap();
                    let inp = <&[[u8; 64]; 2]>::try_from(&inputs[i..i + 2]).unwrap();
                    unsafe { arm_sha2::sha256d_64_2way(out, inp) };
                    i += 2;
                }
            }
        }

        #[cfg(feature = "cpufeatures")]
        #[cfg(target_arch = "aarch64")]
        {
            if cpuid_sha256_aarch64::get() {
                while count - i >= 2 {
                    let out = <&mut [[u8; 32]; 2]>::try_from(&mut outputs[i..i + 2]).unwrap();
                    let inp = <&[[u8; 64]; 2]>::try_from(&inputs[i..i + 2]).unwrap();
                    unsafe { arm_sha2::sha256d_64_2way(out, inp) };
                    i += 2;
                }
            }
        }

        // 8-way AVX2
        #[cfg(feature = "std")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("avx") && std::is_x86_feature_detected!("avx2") {
                while count - i >= 8 {
                    let out = <&mut [[u8; 32]; 8]>::try_from(&mut outputs[i..i + 8]).unwrap();
                    let inp = <&[[u8; 64]; 8]>::try_from(&inputs[i..i + 8]).unwrap();
                    unsafe { avx2::sha256d_64_8way(out, inp) };
                    i += 8;
                }
            }
        }

        #[cfg(feature = "cpufeatures")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if cpuid_avx2_x86::get() {
                while count - i >= 8 {
                    let out = <&mut [[u8; 32]; 8]>::try_from(&mut outputs[i..i + 8]).unwrap();
                    let inp = <&[[u8; 64]; 8]>::try_from(&inputs[i..i + 8]).unwrap();
                    unsafe { avx2::sha256d_64_8way(out, inp) };
                    i += 8;
                }
            }
        }

        // 4-way SSE4.1
        #[cfg(feature = "std")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("sse4.1")
                && std::is_x86_feature_detected!("sse2")
                && std::is_x86_feature_detected!("ssse3")
            {
                while count - i >= 4 {
                    let out = <&mut [[u8; 32]; 4]>::try_from(&mut outputs[i..i + 4]).unwrap();
                    let inp = <&[[u8; 64]; 4]>::try_from(&inputs[i..i + 4]).unwrap();
                    unsafe { sse41::sha256d_64_4way(out, inp) };
                    i += 4;
                }
            }
        }

        #[cfg(feature = "cpufeatures")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if cpuid_sse41_x86::get() {
                while count - i >= 4 {
                    let out = <&mut [[u8; 32]; 4]>::try_from(&mut outputs[i..i + 4]).unwrap();
                    let inp = <&[[u8; 64]; 4]>::try_from(&inputs[i..i + 4]).unwrap();
                    unsafe { sse41::sha256d_64_4way(out, inp) };
                    i += 4;
                }
            }
        }

        // fallback
        while i < count {
            Self::software_sha256d_64(&mut outputs[i], &inputs[i]);
            i += 1;
        }
    }

    // Algorithm copied from libsecp256k1
    fn software_process_block(state: &mut [u32; 8], blocks: &[u8]) {
        debug_assert!(!blocks.is_empty() && blocks.len() % BLOCK_SIZE == 0);

        for block in blocks.chunks_exact(BLOCK_SIZE) {
            let mut w = [0u32; 16];
            for (w_val, buff_bytes) in w.iter_mut().zip(block.bitcoin_as_chunks().0) {
                *w_val = u32::from_be_bytes(*buff_bytes);
            }

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
            let _ = w[15]; // silence "unnecessary assignment" lint in macro

            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
            state[4] = state[4].wrapping_add(e);
            state[5] = state[5].wrapping_add(f);
            state[6] = state[6].wrapping_add(g);
            state[7] = state[7].wrapping_add(h);
        }
    }

    // Optimized scalar SHA256d of a single 64-byte input.
    #[rustfmt::skip]
    pub(crate) fn software_sha256d_64(out: &mut [u8; 32], input: &[u8; 64]) {
        let mut w = [0u32; 16];
        for (w_val, buff_bytes) in w.iter_mut().zip(input.bitcoin_as_chunks::<4>().0) {
            *w_val = u32::from_be_bytes(*buff_bytes);
        }

        // Transform 1
        let mut a: u32 = 0x6a09e667;
        let mut b: u32 = 0xbb67ae85;
        let mut c: u32 = 0x3c6ef372;
        let mut d: u32 = 0xa54ff53a;
        let mut e: u32 = 0x510e527f;
        let mut f: u32 = 0x9b05688c;
        let mut g: u32 = 0x1f83d9ab;
        let mut h: u32 = 0x5be0cd19;

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

        a = a.wrapping_add(0x6a09e667);
        b = b.wrapping_add(0xbb67ae85);
        c = c.wrapping_add(0x3c6ef372);
        d = d.wrapping_add(0xa54ff53a);
        e = e.wrapping_add(0x510e527f);
        f = f.wrapping_add(0x9b05688c);
        g = g.wrapping_add(0x1f83d9ab);
        h = h.wrapping_add(0x5be0cd19);

        let (t0, t1, t2, t3, t4, t5, t6, t7) = (a, b, c, d, e, f, g, h);

        // ------------------ Transform 2 -------------------
        // W is fully constant here, so we just use pre-computed K[i] + W[i] constant
        round!(a, b, c, d, e, f, g, h, 0xc28a2f98, 0);
        round!(h, a, b, c, d, e, f, g, 0x71374491, 0);
        round!(g, h, a, b, c, d, e, f, 0xb5c0fbcf, 0);
        round!(f, g, h, a, b, c, d, e, 0xe9b5dba5, 0);
        round!(e, f, g, h, a, b, c, d, 0x3956c25b, 0);
        round!(d, e, f, g, h, a, b, c, 0x59f111f1, 0);
        round!(c, d, e, f, g, h, a, b, 0x923f82a4, 0);
        round!(b, c, d, e, f, g, h, a, 0xab1c5ed5, 0);
        round!(a, b, c, d, e, f, g, h, 0xd807aa98, 0);
        round!(h, a, b, c, d, e, f, g, 0x12835b01, 0);
        round!(g, h, a, b, c, d, e, f, 0x243185be, 0);
        round!(f, g, h, a, b, c, d, e, 0x550c7dc3, 0);
        round!(e, f, g, h, a, b, c, d, 0x72be5d74, 0);
        round!(d, e, f, g, h, a, b, c, 0x80deb1fe, 0);
        round!(c, d, e, f, g, h, a, b, 0x9bdc06a7, 0);
        round!(b, c, d, e, f, g, h, a, 0xc19bf374, 0);
        round!(a, b, c, d, e, f, g, h, 0x649b69c1, 0);
        round!(h, a, b, c, d, e, f, g, 0xf0fe4786, 0);
        round!(g, h, a, b, c, d, e, f, 0x0fe1edc6, 0);
        round!(f, g, h, a, b, c, d, e, 0x240cf254, 0);
        round!(e, f, g, h, a, b, c, d, 0x4fe9346f, 0);
        round!(d, e, f, g, h, a, b, c, 0x6cc984be, 0);
        round!(c, d, e, f, g, h, a, b, 0x61b9411e, 0);
        round!(b, c, d, e, f, g, h, a, 0x16f988fa, 0);
        round!(a, b, c, d, e, f, g, h, 0xf2c65152, 0);
        round!(h, a, b, c, d, e, f, g, 0xa88e5a6d, 0);
        round!(g, h, a, b, c, d, e, f, 0xb019fc65, 0);
        round!(f, g, h, a, b, c, d, e, 0xb9d99ec7, 0);
        round!(e, f, g, h, a, b, c, d, 0x9a1231c3, 0);
        round!(d, e, f, g, h, a, b, c, 0xe70eeaa0, 0);
        round!(c, d, e, f, g, h, a, b, 0xfdb1232b, 0);
        round!(b, c, d, e, f, g, h, a, 0xc7353eb0, 0);
        round!(a, b, c, d, e, f, g, h, 0x3069bad5, 0);
        round!(h, a, b, c, d, e, f, g, 0xcb976d5f, 0);
        round!(g, h, a, b, c, d, e, f, 0x5a0f118f, 0);
        round!(f, g, h, a, b, c, d, e, 0xdc1eeefd, 0);
        round!(e, f, g, h, a, b, c, d, 0x0a35b689, 0);
        round!(d, e, f, g, h, a, b, c, 0xde0b7a04, 0);
        round!(c, d, e, f, g, h, a, b, 0x58f4ca9d, 0);
        round!(b, c, d, e, f, g, h, a, 0xe15d5b16, 0);
        round!(a, b, c, d, e, f, g, h, 0x007f3e86, 0);
        round!(h, a, b, c, d, e, f, g, 0x37088980, 0);
        round!(g, h, a, b, c, d, e, f, 0xa507ea32, 0);
        round!(f, g, h, a, b, c, d, e, 0x6fab9537, 0);
        round!(e, f, g, h, a, b, c, d, 0x17406110, 0);
        round!(d, e, f, g, h, a, b, c, 0x0d8cd6f1, 0);
        round!(c, d, e, f, g, h, a, b, 0xcdaa3b6d, 0);
        round!(b, c, d, e, f, g, h, a, 0xc0bbbe37, 0);
        round!(a, b, c, d, e, f, g, h, 0x83613bda, 0);
        round!(h, a, b, c, d, e, f, g, 0xdb48a363, 0);
        round!(g, h, a, b, c, d, e, f, 0x0b02e931, 0);
        round!(f, g, h, a, b, c, d, e, 0x6fd15ca7, 0);
        round!(e, f, g, h, a, b, c, d, 0x521afaca, 0);
        round!(d, e, f, g, h, a, b, c, 0x31338431, 0);
        round!(c, d, e, f, g, h, a, b, 0x6ed41a95, 0);
        round!(b, c, d, e, f, g, h, a, 0x6d437890, 0);
        round!(a, b, c, d, e, f, g, h, 0xc39c91f2, 0);
        round!(h, a, b, c, d, e, f, g, 0x9eccabbd, 0);
        round!(g, h, a, b, c, d, e, f, 0xb5c9a0e6, 0);
        round!(f, g, h, a, b, c, d, e, 0x532fb63c, 0);
        round!(e, f, g, h, a, b, c, d, 0xd2c741c6, 0);
        round!(d, e, f, g, h, a, b, c, 0x07237ea3, 0);
        round!(c, d, e, f, g, h, a, b, 0xa4954b68, 0);
        round!(b, c, d, e, f, g, h, a, 0x4c191d76, 0);

        // Transform 2: Update state
        w[0] = t0.wrapping_add(a);
        w[1] = t1.wrapping_add(b);
        w[2] = t2.wrapping_add(c);
        w[3] = t3.wrapping_add(d);
        w[4] = t4.wrapping_add(e);
        w[5] = t5.wrapping_add(f);
        w[6] = t6.wrapping_add(g);
        w[7] = t7.wrapping_add(h);

        // ------------------ Transform 3 -------------------
        a = 0x6a09e667;
        b = 0xbb67ae85;
        c = 0x3c6ef372;
        d = 0xa54ff53a;
        e = 0x510e527f;
        f = 0x9b05688c;
        g = 0x1f83d9ab;
        h = 0x5be0cd19;

        // Rounds 0-7: feed in the 32 byte message (w0..w7)
        round!(a, b, c, d, e, f, g, h, 0x428a2f98, w[0]);
        round!(h, a, b, c, d, e, f, g, 0x71374491, w[1]);
        round!(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w[2]);
        round!(f, g, h, a, b, c, d, e, 0xe9b5dba5, w[3]);
        round!(e, f, g, h, a, b, c, d, 0x3956c25b, w[4]);
        round!(d, e, f, g, h, a, b, c, 0x59f111f1, w[5]);
        round!(c, d, e, f, g, h, a, b, 0x923f82a4, w[6]);
        round!(b, c, d, e, f, g, h, a, 0xab1c5ed5, w[7]);

        // Rounds 8-15: known padding
        round!(a, b, c, d, e, f, g, h, 0x5807aa98, 0);
        round!(h, a, b, c, d, e, f, g, 0x12835b01, 0);
        round!(g, h, a, b, c, d, e, f, 0x243185be, 0);
        round!(f, g, h, a, b, c, d, e, 0x550c7dc3, 0);
        round!(e, f, g, h, a, b, c, d, 0x72be5d74, 0);
        round!(d, e, f, g, h, a, b, c, 0x80deb1fe, 0);
        round!(c, d, e, f, g, h, a, b, 0x9bdc06a7, 0);
        round!(b, c, d, e, f, g, h, a, 0xc19bf274, 0);

        round!(a, b, c, d, e, f, g, h, 0xe49b69c1, { w[0] = w[0].wrapping_add(sigma0(w[1])); w[0] });
        round!(h, a, b, c, d, e, f, g, 0xefbe4786, { w[1] = w[1].wrapping_add(0x00a00000).wrapping_add(sigma0(w[2])); w[1] });
        round!(g, h, a, b, c, d, e, f, 0x0fc19dc6, { w[2] = w[2].wrapping_add(sigma1(w[0])).wrapping_add(sigma0(w[3])); w[2] });
        round!(f, g, h, a, b, c, d, e, 0x240ca1cc, { w[3] = w[3].wrapping_add(sigma1(w[1])).wrapping_add(sigma0(w[4])); w[3] });
        round!(e, f, g, h, a, b, c, d, 0x2de92c6f, { w[4] = w[4].wrapping_add(sigma1(w[2])).wrapping_add(sigma0(w[5])); w[4] });
        round!(d, e, f, g, h, a, b, c, 0x4a7484aa, { w[5] = w[5].wrapping_add(sigma1(w[3])).wrapping_add(sigma0(w[6])); w[5] });
        round!(c, d, e, f, g, h, a, b, 0x5cb0a9dc, { w[6] = w[6].wrapping_add(sigma1(w[4])).wrapping_add(0x00000100).wrapping_add(sigma0(w[7])); w[6] });
        round!(b, c, d, e, f, g, h, a, 0x76f988da, { w[7] = w[7].wrapping_add(sigma1(w[5])).wrapping_add(w[0]).wrapping_add(0x11002000); w[7] });
        round!(a, b, c, d, e, f, g, h, 0x983e5152, { w[8] = sigma1(w[6]).wrapping_add(w[1]).wrapping_add(0x80000000); w[8] });
        round!(h, a, b, c, d, e, f, g, 0xa831c66d, { w[9] = sigma1(w[7]).wrapping_add(w[2]); w[9] });
        round!(g, h, a, b, c, d, e, f, 0xb00327c8, { w[10] = sigma1(w[8]).wrapping_add(w[3]); w[10] });
        round!(f, g, h, a, b, c, d, e, 0xbf597fc7, { w[11] = sigma1(w[9]).wrapping_add(w[4]); w[11] });
        round!(e, f, g, h, a, b, c, d, 0xc6e00bf3, { w[12] = sigma1(w[10]).wrapping_add(w[5]); w[12] });
        round!(d, e, f, g, h, a, b, c, 0xd5a79147, { w[13] = sigma1(w[11]).wrapping_add(w[6]); w[13] });
        round!(c, d, e, f, g, h, a, b, 0x06ca6351, { w[14] = sigma1(w[12]).wrapping_add(w[7]).wrapping_add(0x00400022); w[14] });
        round!(b, c, d, e, f, g, h, a, 0x14292967, { w[15] = sigma1(w[13]).wrapping_add(w[8]).wrapping_add(sigma0(w[0])).wrapping_add(0x00000100); w[15] });

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
        let _ = w[15];

        // Output
        let out_chunks = out.bitcoin_as_chunks_mut::<4>().0;
        out_chunks[0] = a.wrapping_add(0x6a09e667).to_be_bytes();
        out_chunks[1] = b.wrapping_add(0xbb67ae85).to_be_bytes();
        out_chunks[2] = c.wrapping_add(0x3c6ef372).to_be_bytes();
        out_chunks[3] = d.wrapping_add(0xa54ff53a).to_be_bytes();
        out_chunks[4] = e.wrapping_add(0x510e527f).to_be_bytes();
        out_chunks[5] = f.wrapping_add(0x9b05688c).to_be_bytes();
        out_chunks[6] = g.wrapping_add(0x1f83d9ab).to_be_bytes();
        out_chunks[7] = h.wrapping_add(0x5be0cd19).to_be_bytes();
    }
}
