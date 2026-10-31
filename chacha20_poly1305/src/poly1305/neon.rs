// SPDX-License-Identifier: CC0-1.0

//! Poly1305 block function using aarch64 Neon, processing 4 blocks in parallel.
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
use core::arch::aarch64;

use super::{carry_and_reduce, mul_mod, BITMASK};

// One 26-bit limb, separated over 4 blocks.
type Word = aarch64::uint32x4_t;
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
pub(super) fn r_powers(r: &[u32; 5]) -> RPowers {
    let r2 = mul_mod(r, r);
    let r3 = mul_mod(&r2, r);
    let r4 = mul_mod(&r3, r);

    // SAFETY: Neon intrinsics are gated by target feature `neon`.
    unsafe {
        // Each vector holds the same limb of every power, with the fourth
        // power in the first lane and `r` in the last. `vld1q_u32` loads the
        // lanes in memory order.
        let limb0 = aarch64::vld1q_u32([r4[0], r3[0], r2[0], r[0]].as_ptr());
        let limb1 = aarch64::vld1q_u32([r4[1], r3[1], r2[1], r[1]].as_ptr());
        let limb2 = aarch64::vld1q_u32([r4[2], r3[2], r2[2], r[2]].as_ptr());
        let limb3 = aarch64::vld1q_u32([r4[3], r3[3], r2[3], r[3]].as_ptr());
        let limb4 = aarch64::vld1q_u32([r4[4], r3[4], r2[4], r[4]].as_ptr());

        RPowers {
            limbs: (limb0, limb1, limb2, limb3, limb4),
            limbs_times5: (times5(limb1), times5(limb2), times5(limb3), times5(limb4)),
        }
    }
}

// Multiply each lane by 5 via a shift and an add. The limbs of `r` are at
// most slightly above 2^26, so the result fits in 32 bits.
//
// SAFETY: Neon intrinsics are gated by target feature `neon`.
#[inline(always)]
unsafe fn times5(x: Word) -> Word { aarch64::vaddq_u32(aarch64::vshlq_n_u32::<2>(x), x) }

// Steps 4 and 5: multiply the lanes of `a` and `b` pairwise and sum the
// products over all five limbs and all four lanes.
//
// SAFETY: Neon intrinsics are gated by target feature `neon`.
#[inline(always)]
unsafe fn dot5(a: [Word; 5], b: [Word; 5]) -> u64 {
    // `vmull_u32` multiplies the two low 32-bit lanes into two 64-bit
    // products, and `vmlal_u32` does the same while accumulating. The
    // `_high` variants operate on the two high lanes.
    let mut lo = aarch64::vmull_u32(aarch64::vget_low_u32(a[0]), aarch64::vget_low_u32(b[0]));
    let mut hi = aarch64::vmull_high_u32(a[0], b[0]);
    lo = aarch64::vmlal_u32(lo, aarch64::vget_low_u32(a[1]), aarch64::vget_low_u32(b[1]));
    hi = aarch64::vmlal_high_u32(hi, a[1], b[1]);
    lo = aarch64::vmlal_u32(lo, aarch64::vget_low_u32(a[2]), aarch64::vget_low_u32(b[2]));
    hi = aarch64::vmlal_high_u32(hi, a[2], b[2]);
    lo = aarch64::vmlal_u32(lo, aarch64::vget_low_u32(a[3]), aarch64::vget_low_u32(b[3]));
    hi = aarch64::vmlal_high_u32(hi, a[3], b[3]);
    lo = aarch64::vmlal_u32(lo, aarch64::vget_low_u32(a[4]), aarch64::vget_low_u32(b[4]));
    hi = aarch64::vmlal_high_u32(hi, a[4], b[4]);
    // `vaddvq_u64` adds across the two lanes.
    aarch64::vaddvq_u64(aarch64::vaddq_u64(lo, hi))
}

// Step 2: load four 16-byte blocks and split them into five 26-bit limbs,
// one block per lane, including the high bit appended to each full block.
//
// SAFETY: Neon intrinsics are gated by target feature `neon`.
#[inline(always)]
unsafe fn load_blocks(blocks: &[u8; 4 * 16]) -> Limbs {
    let ptr = blocks.as_ptr();
    // Each block is four little-endian 32-bit words, [w0, w1, w2, w3].
    let b0 = aarch64::vreinterpretq_u32_u8(aarch64::vld1q_u8(ptr));
    let b1 = aarch64::vreinterpretq_u32_u8(aarch64::vld1q_u8(ptr.add(16)));
    let b2 = aarch64::vreinterpretq_u32_u8(aarch64::vld1q_u8(ptr.add(32)));
    let b3 = aarch64::vreinterpretq_u32_u8(aarch64::vld1q_u8(ptr.add(48)));

    // Transpose so that each vector holds the same word across the four
    // blocks. `vtrn1q_u32` takes the even lanes of its inputs interleaved,
    // so [b0.w0, b1.w0, b0.w2, b1.w2], and `vtrn2q_u32` the odd lanes.
    let t0 = aarch64::vreinterpretq_u64_u32(aarch64::vtrn1q_u32(b0, b1));
    let t1 = aarch64::vreinterpretq_u64_u32(aarch64::vtrn2q_u32(b0, b1));
    let t2 = aarch64::vreinterpretq_u64_u32(aarch64::vtrn1q_u32(b2, b3));
    let t3 = aarch64::vreinterpretq_u64_u32(aarch64::vtrn2q_u32(b2, b3));
    // The same over 64-bit lanes gives, for example,
    // [b0.w0, b1.w0, b2.w0, b3.w0].
    let w0 = aarch64::vreinterpretq_u32_u64(aarch64::vtrn1q_u64(t0, t2));
    let w1 = aarch64::vreinterpretq_u32_u64(aarch64::vtrn1q_u64(t1, t3));
    let w2 = aarch64::vreinterpretq_u32_u64(aarch64::vtrn2q_u64(t0, t2));
    let w3 = aarch64::vreinterpretq_u32_u64(aarch64::vtrn2q_u64(t1, t3));

    // Limbs straddling two words use "shift left and insert." `vsliq_n_u32`
    // shifts the second argument left and keeps the low bits of the first,
    // which are the high bits of the previous word shifted down.
    let mask = aarch64::vdupq_n_u32(BITMASK);
    // Bits 0..26
    let m0 = aarch64::vandq_u32(w0, mask);
    // Bits 26..52
    let m1 =
        aarch64::vandq_u32(aarch64::vsliq_n_u32::<6>(aarch64::vshrq_n_u32::<26>(w0), w1), mask);
    // Bits 52..78
    let m2 =
        aarch64::vandq_u32(aarch64::vsliq_n_u32::<12>(aarch64::vshrq_n_u32::<20>(w1), w2), mask);
    // Bits 78..104
    let m3 =
        aarch64::vandq_u32(aarch64::vsliq_n_u32::<18>(aarch64::vshrq_n_u32::<14>(w2), w3), mask);
    // Bits 104..128, plus the appended 1 at bit 128.
    let m4 = aarch64::vorrq_u32(aarch64::vshrq_n_u32::<8>(w3), aarch64::vdupq_n_u32(1 << 24));
    (m0, m1, m2, m3, m4)
}

// Add four consecutive full 16-byte blocks into the accumulator, multiplying
// by `r` after each, equivalent to four rounds of the scalar implementation.
pub(super) fn process_4_blocks(acc: &mut [u32; 5], powers: &RPowers, blocks: &[u8; 4 * 16]) {
    // SAFETY: Neon intrinsics are gated by target feature `neon`.
    unsafe {
        // Step 2: the message limbs of the four blocks.
        let (m0, m1, m2, m3, m4) = load_blocks(blocks);

        // Step 3: add the accumulator to the first block only, as it is the
        // one multiplied by the most powers of `r`. `vsetq_lane_u32` places
        // the limb in the first lane of an otherwise zero vector.
        let zero = aarch64::vdupq_n_u32(0);
        let h0 = aarch64::vaddq_u32(m0, aarch64::vsetq_lane_u32::<0>(acc[0], zero));
        let h1 = aarch64::vaddq_u32(m1, aarch64::vsetq_lane_u32::<0>(acc[1], zero));
        let h2 = aarch64::vaddq_u32(m2, aarch64::vsetq_lane_u32::<0>(acc[2], zero));
        let h3 = aarch64::vaddq_u32(m3, aarch64::vsetq_lane_u32::<0>(acc[3], zero));
        let h4 = aarch64::vaddq_u32(m4, aarch64::vsetq_lane_u32::<0>(acc[4], zero));

        let (pow0, pow1, pow2, pow3, pow4) = powers.limbs;
        let (pow1x5, pow2x5, pow3x5, pow4x5) = powers.limbs_times5;

        // Step 4: multiply each lane by its power of `r`. This is the same
        // schoolbook multiplication as the scalar `mul_mod`, over four lanes.
        // Limbs are below 2^27 and the multiples of 5 below 2^29, so each
        // lane sums to below 2^58. Step 5 adds the lanes, to below 2^60, and
        // step 6 carries the sum back into 26-bit limbs.
        *acc = carry_and_reduce([
            dot5([h0, h1, h2, h3, h4], [pow0, pow4x5, pow3x5, pow2x5, pow1x5]),
            dot5([h0, h1, h2, h3, h4], [pow1, pow0, pow4x5, pow3x5, pow2x5]),
            dot5([h0, h1, h2, h3, h4], [pow2, pow1, pow0, pow4x5, pow3x5]),
            dot5([h0, h1, h2, h3, h4], [pow3, pow2, pow1, pow0, pow4x5]),
            dot5([h0, h1, h2, h3, h4], [pow4, pow3, pow2, pow1, pow0]),
        ]);
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use hex::hex;

    use super::super::{prepare_padded_message_slice, Poly1305};
    use super::{process_4_blocks, r_powers};

    #[test]
    fn matches_single_block_processing_4way() {
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

                let mut neon = Poly1305::new(key);
                let powers = r_powers(&neon.r);
                for chunk in message.chunks_exact(64) {
                    process_4_blocks(&mut neon.acc, &powers, chunk.try_into().unwrap());
                }
                assert_eq!(neon.tag(), scalar.tag(), "mismatch for fill={:#x}", fill);
            }
        }
    }
}
