// SPDX-License-Identifier: CC0-1.0

//! Poly1305 block function using x86 AVX2, processing 4 blocks in parallel.
//!
//! This module follows the Goll–Gueron section of this paper:
//! <https://eprint.iacr.org/2019/842.pdf>
//!
//! Poly1305 treats each 16-byte block as a number and, one block at a time,
//! adds it to an accumulator and multiplies the accumulator by the key `r`.
//! Processing four blocks this way gives the same result as multiplying the
//! first block (plus the accumulator) by `r` four times, the second by `r`
//! three times, and so on, then adding the four products. Those four
//! products do not depend on each other, so they are computed in parallel:
//!
//! 1. Compute the second, third and fourth powers of `r`.
//! 2. Load four blocks, one block per vector lane, split into 26-bit limbs.
//! 3. Add the accumulator to the first block only.
//! 4. Multiply each lane by its power of `r`, the fourth power for the first
//!    block down to `r` itself for the last block.
//! 5. Add the four lanes together.
//! 6. Carry the sum back into 26-bit limbs, reducing modulo 2^130 - 5.
//!
//! Unlike SSE2, AVX2 is not part of the `x86_64` baseline. The functions are
//! annotated with the `target_feature` attribute and are either enabled at
//! compile time or detected at runtime before being called.
#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use super::{carry_and_reduce, mul_mod, BITMASK};

// One 26-bit limb, separated over 4 blocks.
type Word = arch::__m256i;
// A 130-bit number in five 26-bit limbs, separated over 4 blocks.
type Limbs = (Word, Word, Word, Word, Word);

/// The powers of `r` used by step 4, one per lane, from the fourth power in
/// the first lane down to `r` itself in the last.
pub(super) struct RPowers {
    /// The five limbs of each power.
    limbs: Limbs,
    /// Limbs 1 through 4 of each power multiplied by 5. Used to fold the
    /// terms above 2^130 back into the low limbs, as 2^130 = 5 mod p.
    limbs_times5: (Word, Word, Word, Word),
}

// Step 1: compute the powers of `r` and place them in the lanes.
//
// SAFETY: The caller must ensure that AVX2 is available on the current CPU.
#[target_feature(enable = "avx,avx2")]
pub(super) unsafe fn r_powers(r: &[u32; 5]) -> RPowers {
    let r2 = mul_mod(r, r);
    let r3 = mul_mod(&r2, r);
    let r4 = mul_mod(&r3, r);

    // Each vector holds the same limb of every power, with the fourth power
    // in the first lane and `r` in the last. `_mm256_setr_epi64x` sets the
    // lanes in memory order.
    let limb0 = arch::_mm256_setr_epi64x(
        i64::from(r4[0]),
        i64::from(r3[0]),
        i64::from(r2[0]),
        i64::from(r[0]),
    );
    let limb1 = arch::_mm256_setr_epi64x(
        i64::from(r4[1]),
        i64::from(r3[1]),
        i64::from(r2[1]),
        i64::from(r[1]),
    );
    let limb2 = arch::_mm256_setr_epi64x(
        i64::from(r4[2]),
        i64::from(r3[2]),
        i64::from(r2[2]),
        i64::from(r[2]),
    );
    let limb3 = arch::_mm256_setr_epi64x(
        i64::from(r4[3]),
        i64::from(r3[3]),
        i64::from(r2[3]),
        i64::from(r[3]),
    );
    let limb4 = arch::_mm256_setr_epi64x(
        i64::from(r4[4]),
        i64::from(r3[4]),
        i64::from(r2[4]),
        i64::from(r[4]),
    );

    RPowers {
        limbs: (limb0, limb1, limb2, limb3, limb4),
        limbs_times5: (times5(limb1), times5(limb2), times5(limb3), times5(limb4)),
    }
}

// Multiply each lane by 5 via a shift and an add.
//
// SAFETY: AVX2 intrinsics are gated by target feature `avx2`.
#[inline(always)]
unsafe fn times5(x: Word) -> Word { arch::_mm256_add_epi64(arch::_mm256_slli_epi64(x, 2), x) }

// Multiply the low 32 bits of each lane of `a` and `b` pairwise and sum the
// five 64-bit products.
//
// SAFETY: AVX2 intrinsics are gated by target feature `avx2`.
#[inline(always)]
unsafe fn dot5(a: [Word; 5], b: [Word; 5]) -> Word {
    // `_mm256_mul_epu32` multiplies the low 32 bits of each 64-bit lane into
    // a full 64-bit product.
    let mut sum = arch::_mm256_mul_epu32(a[0], b[0]);
    sum = arch::_mm256_add_epi64(sum, arch::_mm256_mul_epu32(a[1], b[1]));
    sum = arch::_mm256_add_epi64(sum, arch::_mm256_mul_epu32(a[2], b[2]));
    sum = arch::_mm256_add_epi64(sum, arch::_mm256_mul_epu32(a[3], b[3]));
    arch::_mm256_add_epi64(sum, arch::_mm256_mul_epu32(a[4], b[4]))
}

// Step 2: load four 16-byte blocks and split them into five 26-bit limbs,
// one block per lane, including the high bit appended to each full block.
//
// SAFETY: AVX2 intrinsics are gated by target feature `avx2`.
#[inline(always)]
#[allow(clippy::cast_ptr_alignment)]
unsafe fn load_blocks(blocks: &[u8; 4 * 16]) -> Limbs {
    let ptr = blocks.as_ptr().cast::<Word>();
    // Each block is two little-endian 64-bit words, `lo` and `hi`.
    // [b0.lo, b0.hi, b1.lo, b1.hi]
    let a = arch::_mm256_loadu_si256(ptr);
    // [b2.lo, b2.hi, b3.lo, b3.hi]
    let b = arch::_mm256_loadu_si256(ptr.add(1));
    // `_mm256_unpacklo_epi64` interleaves within each 128-bit lane, giving
    // [b0.lo, b2.lo, b1.lo, b3.lo]. `_mm256_permute4x64_epi64` then reorders
    // the 64-bit lanes as [0, 2, 1, 3] to give [b0.lo, b1.lo, b2.lo, b3.lo].
    let lo = arch::_mm256_permute4x64_epi64(arch::_mm256_unpacklo_epi64(a, b), 0b11_01_10_00);
    // Similarly [b0.hi, b1.hi, b2.hi, b3.hi].
    let hi = arch::_mm256_permute4x64_epi64(arch::_mm256_unpackhi_epi64(a, b), 0b11_01_10_00);

    let mask = arch::_mm256_set1_epi64x(i64::from(BITMASK));
    // Bits 0..26
    let m0 = arch::_mm256_and_si256(lo, mask);
    // Bits 26..52
    let m1 = arch::_mm256_and_si256(arch::_mm256_srli_epi64(lo, 26), mask);
    // Bits 52..78, which straddle the two 64-bit words.
    let m2 = arch::_mm256_and_si256(
        arch::_mm256_or_si256(arch::_mm256_srli_epi64(lo, 52), arch::_mm256_slli_epi64(hi, 12)),
        mask,
    );
    // Bits 78..104
    let m3 = arch::_mm256_and_si256(arch::_mm256_srli_epi64(hi, 14), mask);
    // Bits 104..128, plus the appended 1 at bit 128.
    let m4 =
        arch::_mm256_or_si256(arch::_mm256_srli_epi64(hi, 40), arch::_mm256_set1_epi64x(1 << 24));
    (m0, m1, m2, m3, m4)
}

// Step 5: add the four 64-bit lanes together.
//
// SAFETY: AVX intrinsics are gated by target feature `avx`.
#[inline(always)]
#[allow(clippy::cast_ptr_alignment)]
unsafe fn horizontal_sum(x: Word) -> u64 {
    let mut lanes = [0u64; 4];
    arch::_mm256_storeu_si256(lanes.as_mut_ptr().cast::<Word>(), x);
    lanes[0] + lanes[1] + lanes[2] + lanes[3]
}

// Add four consecutive full 16-byte blocks into the accumulator, multiplying
// by `r` after each, equivalent to four rounds of the scalar implementation.
//
// SAFETY: The caller must ensure that AVX2 is available on the current CPU.
#[target_feature(enable = "avx,avx2")]
pub(super) unsafe fn process_4_blocks(acc: &mut [u32; 5], powers: &RPowers, blocks: &[u8; 4 * 16]) {
    // Step 2: the message limbs of the four blocks.
    let (m0, m1, m2, m3, m4) = load_blocks(blocks);

    // Step 3: add the accumulator to the first block only, as it is the one
    // multiplied by the most powers of `r`.
    let h0 = arch::_mm256_add_epi64(m0, arch::_mm256_setr_epi64x(i64::from(acc[0]), 0, 0, 0));
    let h1 = arch::_mm256_add_epi64(m1, arch::_mm256_setr_epi64x(i64::from(acc[1]), 0, 0, 0));
    let h2 = arch::_mm256_add_epi64(m2, arch::_mm256_setr_epi64x(i64::from(acc[2]), 0, 0, 0));
    let h3 = arch::_mm256_add_epi64(m3, arch::_mm256_setr_epi64x(i64::from(acc[3]), 0, 0, 0));
    let h4 = arch::_mm256_add_epi64(m4, arch::_mm256_setr_epi64x(i64::from(acc[4]), 0, 0, 0));

    let (pow0, pow1, pow2, pow3, pow4) = powers.limbs;
    let (pow1x5, pow2x5, pow3x5, pow4x5) = powers.limbs_times5;

    // Step 4: multiply each lane by its power of `r`. This is the same
    // schoolbook multiplication as the scalar `mul_mod`, over four lanes.
    // Limbs are below 2^27 and the multiples of 5 below 2^29, so each lane
    // sums to below 2^58.
    let t0 = dot5([h0, h1, h2, h3, h4], [pow0, pow4x5, pow3x5, pow2x5, pow1x5]);
    let t1 = dot5([h0, h1, h2, h3, h4], [pow1, pow0, pow4x5, pow3x5, pow2x5]);
    let t2 = dot5([h0, h1, h2, h3, h4], [pow2, pow1, pow0, pow4x5, pow3x5]);
    let t3 = dot5([h0, h1, h2, h3, h4], [pow3, pow2, pow1, pow0, pow4x5]);
    let t4 = dot5([h0, h1, h2, h3, h4], [pow4, pow3, pow2, pow1, pow0]);

    // Step 5 adds the lanes, to below 2^60, and step 6 carries the sum back
    // into 26-bit limbs.
    *acc = carry_and_reduce([
        horizontal_sum(t0),
        horizontal_sum(t1),
        horizontal_sum(t2),
        horizontal_sum(t3),
        horizontal_sum(t4),
    ]);
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use hex::hex;

    use super::super::{prepare_padded_message_slice, Poly1305};
    use super::{process_4_blocks, r_powers};

    #[test]
    fn matches_single_block_processing_4way() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        let keys = [
            hex!("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
            hex!("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
            [0xff; 32],
        ];
        for key in keys {
            for fill in [0x00u8, 0x5a, 0xff] {
                let mut message = [fill; 3 * 64];
                for (i, b) in message.iter_mut().enumerate() {
                    *b ^= i as u8;
                }

                let mut scalar = Poly1305::new(key);
                for block in message.chunks_exact(16) {
                    let msg = prepare_padded_message_slice(block, false);
                    for (a, m) in scalar.acc.iter_mut().zip(msg.iter()) {
                        *a += *m;
                    }
                    scalar.r_times_a();
                }

                let mut avx2 = Poly1305::new(key);
                // SAFETY: AVX2 support was detected above.
                unsafe {
                    let powers = r_powers(&avx2.r);
                    for chunk in message.chunks_exact(64) {
                        process_4_blocks(&mut avx2.acc, &powers, chunk.try_into().unwrap());
                    }
                }
                assert_eq!(avx2.tag(), scalar.tag(), "mismatch for fill={:#x}", fill);
            }
        }
    }
}
