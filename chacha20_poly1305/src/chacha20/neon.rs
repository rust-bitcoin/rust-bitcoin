// SPDX-License-Identifier: CC0-1.0

//! `ChaCha20` block function using aarch64 Neon, processing 4 or 8 blocks in parallel.
//!
//! This module utilizes SIMD over the `uint32x4_t` type provided by the aarch64
//! Neon intrinsics. The steps are identical to the RFC for processing a single block,
//! however a final matrix transpose is required to properly apply the state to the
//! ciphertext.
use core::arch::aarch64;

use super::{Key, Nonce, WORD_1, WORD_2, WORD_3, WORD_4};

// Byte shuffle table for rotate 8 left bits within each 32-bit lane.
const ROT8_TABLE: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];

// One word of chacha state, separated over 4 blocks.
type Word = aarch64::uint32x4_t;
// One row of chacha state, separated over 4 blocks.
type StateRow = (Word, Word, Word, Word);

// The `ChaCha20` quarter round applied to four independent blocks in parallel.
//
// For a single state, the quarter round is described here:
// https://datatracker.ietf.org/doc/html/rfc7539#section-2.1
//
// Each argument is a `uint32x4_t` holding the same state variable across four blocks.
//
// SAFETY: Neon intrinsics are gated by feature `neon`.
#[inline(always)]
unsafe fn quarter_round(a: &mut Word, b: &mut Word, c: &mut Word, d: &mut Word) {
    // `vaddq` is a vector pair-wise add.
    // `veorq` is a vector bitwise exclusive OR.
    *a = aarch64::vaddq_u32(*a, *b);
    *d = rotl16(aarch64::veorq_u32(*d, *a));

    *c = aarch64::vaddq_u32(*c, *d);
    *b = rotl12(aarch64::veorq_u32(*b, *c));

    *a = aarch64::vaddq_u32(*a, *b);
    *d = rotl8(aarch64::veorq_u32(*d, *a));

    *c = aarch64::vaddq_u32(*c, *d);
    *b = rotl7(aarch64::veorq_u32(*b, *c));
}

/// Rotate left by 16 within each 32-bit lane.
///
/// `vrev32q_u16` swaps 16 high and 16 low bits of x, which is equivalent
/// to a rotate left of 16. The `vreinterpretq` are required to satisfy
/// the function parameters, but do not actually change underlying registers.
///
// SAFETY: Neon intrinsics are gated by feature `neon`.
#[inline(always)]
unsafe fn rotl16(x: Word) -> Word {
    aarch64::vreinterpretq_u32_u16(aarch64::vrev32q_u16(aarch64::vreinterpretq_u16_u32(x)))
}

// Rotate left by 12 within each 32-bit lane, via shift left plus
// "shift right and insert."
//
// The initial left shift leaves 12 low bits zero. The `vsriq_n_u32`
// shifts the original `x` by 20 bits, then copies the 12 low bits
// of the result into the left-shifted value. This is equivalent to
// a rotate left of 12.
//
// SAFETY: Neon intrinsics are gated by feature `neon`.
#[inline(always)]
unsafe fn rotl12(x: Word) -> Word { aarch64::vsriq_n_u32::<20>(aarch64::vshlq_n_u32::<12>(x), x) }

// Rotate left by 8 within each 32-bit lane, via a byte-permute table.
//
// `vqtbl1q_u8` swaps each byte with the one located at the position in
// the table. For example, take the first four bytes of `ROT8_TABLE`,
// which are `3, 0, 1, 2`. Suppose the bytes of the first word in x,
// are [`b0`, `b1`, `b2`, `b3`], then `vqtbl1q_u8` swaps the bytes of
// x such that  the new word is [`b3`, `b0`, `b1`, `b2`]. This looks
// as if it is a rotate right, but since the format is little endian,
// this wraps the MSB to LSB as expected.
//
// SAFETY: Neon intrinsics are gated by feature `neon`.
#[inline(always)]
unsafe fn rotl8(x: Word) -> Word {
    let table = aarch64::vld1q_u8(ROT8_TABLE.as_ptr());
    aarch64::vreinterpretq_u32_u8(aarch64::vqtbl1q_u8(aarch64::vreinterpretq_u8_u32(x), table))
}

// Rotate left by 7 within each 32-bit lane, via shift left plus
// "shift right and insert."
//
// The initial left shift leaves 7 low bits zero. The `vsriq_n_u32`
// shifts the original `x` by 25 bits, then copies the 7 low bits
// of the result into the left-shifted value. This is equivalent to
// a rotate left of 7.
//
// SAFETY: Neon intrinsics are gated by feature `neon`.
#[inline(always)]
unsafe fn rotl7(x: Word) -> Word { aarch64::vsriq_n_u32::<25>(aarch64::vshlq_n_u32::<7>(x), x) }

// Initial chacha state that does not vary by the block counter.
// SAFETY: Neon intrinsics are gated by feature `neon`.
#[inline(always)]
unsafe fn init_three_rows(key: &Key) -> (StateRow, StateRow, StateRow) {
    // Initialize length 4 vectors of 32 bit values.
    //
    // The `vdupq_n_u32` calls duplicate the 32-bit word to a `uint32x4_t`.
    //
    // This is a 4-lane version of the initial chacha state
    // described here: https://datatracker.ietf.org/doc/html/rfc7539#section-2.3
    let init0 = aarch64::vdupq_n_u32(WORD_1);
    let init1 = aarch64::vdupq_n_u32(WORD_2);
    let init2 = aarch64::vdupq_n_u32(WORD_3);
    let init3 = aarch64::vdupq_n_u32(WORD_4);
    let init4 = aarch64::vdupq_n_u32(u32::from_le_bytes([key.0[0], key.0[1], key.0[2], key.0[3]]));
    let init5 = aarch64::vdupq_n_u32(u32::from_le_bytes([key.0[4], key.0[5], key.0[6], key.0[7]]));
    let init6 =
        aarch64::vdupq_n_u32(u32::from_le_bytes([key.0[8], key.0[9], key.0[10], key.0[11]]));
    let init7 =
        aarch64::vdupq_n_u32(u32::from_le_bytes([key.0[12], key.0[13], key.0[14], key.0[15]]));
    let init8 =
        aarch64::vdupq_n_u32(u32::from_le_bytes([key.0[16], key.0[17], key.0[18], key.0[19]]));
    let init9 =
        aarch64::vdupq_n_u32(u32::from_le_bytes([key.0[20], key.0[21], key.0[22], key.0[23]]));
    let init10 =
        aarch64::vdupq_n_u32(u32::from_le_bytes([key.0[24], key.0[25], key.0[26], key.0[27]]));
    let init11 =
        aarch64::vdupq_n_u32(u32::from_le_bytes([key.0[28], key.0[29], key.0[30], key.0[31]]));
    ((init0, init1, init2, init3), (init4, init5, init6, init7), (init8, init9, init10, init11))
}

// Three words of the final block, comprised of the nonce.
// SAFETY: Neon intrinsics are gated by feature `neon`.
unsafe fn init_nonce_words(nonce: &Nonce) -> (Word, Word, Word) {
    let init13 =
        aarch64::vdupq_n_u32(u32::from_le_bytes([nonce.0[0], nonce.0[1], nonce.0[2], nonce.0[3]]));
    let init14 =
        aarch64::vdupq_n_u32(u32::from_le_bytes([nonce.0[4], nonce.0[5], nonce.0[6], nonce.0[7]]));
    let init15 = aarch64::vdupq_n_u32(u32::from_le_bytes([
        nonce.0[8],
        nonce.0[9],
        nonce.0[10],
        nonce.0[11],
    ]));
    (init13, init14, init15)
}

// XOR four consecutive `ChaCha20` blocks of keystream into `chunk`, starting
// at `start_block`.
#[inline]
pub(super) fn apply_4_blocks(chunk: &mut [u8; 4 * 64], key: &Key, nonce: &Nonce, start_block: u32) {
    // SAFETY: Neon intrinsics are gated by feature `neon`.
    unsafe {
        // Initialize length 4 vectors of 32 bit values.
        //
        // The `vdupq_n_u32` calls duplicate the 32-bit word to a `uint32x4_t`.
        //
        // This is a 4-lane version of the initial chacha state
        // described here: https://datatracker.ietf.org/doc/html/rfc7539#section-2.3
        let (
            (init0, init1, init2, init3),
            (init4, init5, init6, init7),
            (init8, init9, init10, init11),
        ) = init_three_rows(key);
        // The only state value that varies between rounds is the block counter.
        // We set the four lanes to [start, start+1, start+2, start+3].
        let (init13, init14, init15) = init_nonce_words(nonce);
        let counter_init: [u32; 4] = [
            start_block,
            start_block.wrapping_add(1),
            start_block.wrapping_add(2),
            start_block.wrapping_add(3),
        ];
        // Load each `u32` into the 4 registers of `uint32x4_t`
        let init12 = aarch64::vld1q_u32(counter_init.as_ptr());

        // The working state that will be mutated by the quarter rounds.
        let (mut w0, mut w1, mut w2, mut w3) = (init0, init1, init2, init3);
        let (mut w4, mut w5, mut w6, mut w7) = (init4, init5, init6, init7);
        let (mut w8, mut w9, mut w10, mut w11) = (init8, init9, init10, init11);
        let (mut w12, mut w13, mut w14, mut w15) = (init12, init13, init14, init15);

        // Apply the column and diagonal rounds
        // https://datatracker.ietf.org/doc/html/rfc7539#section-2.3
        for _ in 0..10 {
            // Column round
            quarter_round(&mut w0, &mut w4, &mut w8, &mut w12);
            quarter_round(&mut w1, &mut w5, &mut w9, &mut w13);
            quarter_round(&mut w2, &mut w6, &mut w10, &mut w14);
            quarter_round(&mut w3, &mut w7, &mut w11, &mut w15);
            // Diagonal round
            quarter_round(&mut w0, &mut w5, &mut w10, &mut w15);
            quarter_round(&mut w1, &mut w6, &mut w11, &mut w12);
            quarter_round(&mut w2, &mut w7, &mut w8, &mut w13);
            quarter_round(&mut w3, &mut w4, &mut w9, &mut w14);
        }

        // " At the end of 20 rounds [...] we add the
        // original input words to the output words."
        // End of section: https://datatracker.ietf.org/doc/html/rfc7539#section-2.3
        w0 = aarch64::vaddq_u32(w0, init0);
        w1 = aarch64::vaddq_u32(w1, init1);
        w2 = aarch64::vaddq_u32(w2, init2);
        w3 = aarch64::vaddq_u32(w3, init3);
        w4 = aarch64::vaddq_u32(w4, init4);
        w5 = aarch64::vaddq_u32(w5, init5);
        w6 = aarch64::vaddq_u32(w6, init6);
        w7 = aarch64::vaddq_u32(w7, init7);
        w8 = aarch64::vaddq_u32(w8, init8);
        w9 = aarch64::vaddq_u32(w9, init9);
        w10 = aarch64::vaddq_u32(w10, init10);
        w11 = aarch64::vaddq_u32(w11, init11);
        w12 = aarch64::vaddq_u32(w12, init12);
        w13 = aarch64::vaddq_u32(w13, init13);
        w14 = aarch64::vaddq_u32(w14, init14);
        w15 = aarch64::vaddq_u32(w15, init15);

        xor_into(chunk, 0, w0, w1, w2, w3); // bytes  0..16 of each block
        xor_into(chunk, 16, w4, w5, w6, w7); // bytes 16..32
        xor_into(chunk, 32, w8, w9, w10, w11); // bytes 32..48
        xor_into(chunk, 48, w12, w13, w14, w15); // bytes 48..64
    }
}

// XOR eight consecutive `ChaCha20` blocks of keystream into `chunk`, starting
// at `start_block`.
#[inline]
pub(super) fn apply_8_blocks(
    chunk_lo: &mut [u8; 4 * 64],
    chunk_hi: &mut [u8; 4 * 64],
    key: &Key,
    nonce: &Nonce,
    start_block: u32,
) {
    // This function is identical to the 4 block case, however two
    // separate working states are mutated. The function calls are
    // interleved so Neon instuctions can execute independly.
    // SAFETY: Neon intrinsics are gated by feature `neon`.
    unsafe {
        // Initial state values shared across all 8 blocks,
        // only the block counter differs.
        let (
            (init0, init1, init2, init3),
            (init4, init5, init6, init7),
            (init8, init9, init10, init11),
        ) = init_three_rows(key);
        let (init13, init14, init15) = init_nonce_words(nonce);
        let counter_init_lo: [u32; 4] = [
            start_block,
            start_block.wrapping_add(1),
            start_block.wrapping_add(2),
            start_block.wrapping_add(3),
        ];
        let init12_lo = aarch64::vld1q_u32(counter_init_lo.as_ptr());
        let counter_init_hi: [u32; 4] = [
            start_block.wrapping_add(4),
            start_block.wrapping_add(5),
            start_block.wrapping_add(6),
            start_block.wrapping_add(7),
        ];
        let init12_hi = aarch64::vld1q_u32(counter_init_hi.as_ptr());

        // Working state for the low group (blocks 0..3).
        let (mut w0, mut w1, mut w2, mut w3) = (init0, init1, init2, init3);
        let (mut w4, mut w5, mut w6, mut w7) = (init4, init5, init6, init7);
        let (mut w8, mut w9, mut w10, mut w11) = (init8, init9, init10, init11);
        let (mut w12, mut w13, mut w14, mut w15) = (init12_lo, init13, init14, init15);
        // Working state for the high group (blocks 4..7).
        let (mut x0, mut x1, mut x2, mut x3) = (init0, init1, init2, init3);
        let (mut x4, mut x5, mut x6, mut x7) = (init4, init5, init6, init7);
        let (mut x8, mut x9, mut x10, mut x11) = (init8, init9, init10, init11);
        let (mut x12, mut x13, mut x14, mut x15) = (init12_hi, init13, init14, init15);

        // 20 rounds. Each quarter-round position is applied to both groups
        // in interleaved order as
        for _ in 0..10 {
            // Column round.
            quarter_round(&mut w0, &mut w4, &mut w8, &mut w12);
            quarter_round(&mut x0, &mut x4, &mut x8, &mut x12);
            quarter_round(&mut w1, &mut w5, &mut w9, &mut w13);
            quarter_round(&mut x1, &mut x5, &mut x9, &mut x13);
            quarter_round(&mut w2, &mut w6, &mut w10, &mut w14);
            quarter_round(&mut x2, &mut x6, &mut x10, &mut x14);
            quarter_round(&mut w3, &mut w7, &mut w11, &mut w15);
            quarter_round(&mut x3, &mut x7, &mut x11, &mut x15);
            // Diagonal round.
            quarter_round(&mut w0, &mut w5, &mut w10, &mut w15);
            quarter_round(&mut x0, &mut x5, &mut x10, &mut x15);
            quarter_round(&mut w1, &mut w6, &mut w11, &mut w12);
            quarter_round(&mut x1, &mut x6, &mut x11, &mut x12);
            quarter_round(&mut w2, &mut w7, &mut w8, &mut w13);
            quarter_round(&mut x2, &mut x7, &mut x8, &mut x13);
            quarter_round(&mut w3, &mut w4, &mut w9, &mut w14);
            quarter_round(&mut x3, &mut x4, &mut x9, &mut x14);
        }

        // Add the initial state back in for both groups.
        w0 = aarch64::vaddq_u32(w0, init0);
        x0 = aarch64::vaddq_u32(x0, init0);
        w1 = aarch64::vaddq_u32(w1, init1);
        x1 = aarch64::vaddq_u32(x1, init1);
        w2 = aarch64::vaddq_u32(w2, init2);
        x2 = aarch64::vaddq_u32(x2, init2);
        w3 = aarch64::vaddq_u32(w3, init3);
        x3 = aarch64::vaddq_u32(x3, init3);
        w4 = aarch64::vaddq_u32(w4, init4);
        x4 = aarch64::vaddq_u32(x4, init4);
        w5 = aarch64::vaddq_u32(w5, init5);
        x5 = aarch64::vaddq_u32(x5, init5);
        w6 = aarch64::vaddq_u32(w6, init6);
        x6 = aarch64::vaddq_u32(x6, init6);
        w7 = aarch64::vaddq_u32(w7, init7);
        x7 = aarch64::vaddq_u32(x7, init7);
        w8 = aarch64::vaddq_u32(w8, init8);
        x8 = aarch64::vaddq_u32(x8, init8);
        w9 = aarch64::vaddq_u32(w9, init9);
        x9 = aarch64::vaddq_u32(x9, init9);
        w10 = aarch64::vaddq_u32(w10, init10);
        x10 = aarch64::vaddq_u32(x10, init10);
        w11 = aarch64::vaddq_u32(w11, init11);
        x11 = aarch64::vaddq_u32(x11, init11);
        w12 = aarch64::vaddq_u32(w12, init12_lo);
        x12 = aarch64::vaddq_u32(x12, init12_hi);
        w13 = aarch64::vaddq_u32(w13, init13);
        x13 = aarch64::vaddq_u32(x13, init13);
        w14 = aarch64::vaddq_u32(w14, init14);
        x14 = aarch64::vaddq_u32(x14, init14);
        w15 = aarch64::vaddq_u32(w15, init15);
        x15 = aarch64::vaddq_u32(x15, init15);

        // XOR the keystream into both halves.
        xor_into(chunk_lo, 0, w0, w1, w2, w3);
        xor_into(chunk_hi, 0, x0, x1, x2, x3);
        xor_into(chunk_lo, 16, w4, w5, w6, w7);
        xor_into(chunk_hi, 16, x4, x5, x6, x7);
        xor_into(chunk_lo, 32, w8, w9, w10, w11);
        xor_into(chunk_hi, 32, x8, x9, x10, x11);
        xor_into(chunk_lo, 48, w12, w13, w14, w15);
        xor_into(chunk_hi, 48, x12, x13, x14, x15);
    }
}

// This function handles the final step of applying the keystream to the
// ciphertext as outlined in the RFC: https://datatracker.ietf.org/doc/html/rfc7539#section-2.4.1
//
// The memory layout is not yet in the correct format when using the
// vector representations. So there is an additional transpose step.
//
// Suppose a chacha state is made up of words [w0,..., w15].
// We are processing 4 blocks, [b0, b1, b2, b3].
//
// In the current state, each `uint32x4_t` contains the word
// at an index `i`: [b0.w_i, b1.w_i, b2.w_i, b3.w_i].
//
// We want: [b0.w0, b0.w1, b0.w2, b0.w3] so we can XOR into the
// ciphertext.
//
// SAFETY: Neon intrinsics are gated by feature `neon`.
#[inline(always)]
unsafe fn xor_into(
    chunk: &mut [u8; 4 * 64],
    offset: usize,
    w0: Word,
    w1: Word,
    w2: Word,
    w3: Word,
) {
    // `vzip1q_u32` interleaves the lower halves of its inputs:
    // [a, b, c, d] and [e, f, g, h] become [a, e, b, f].
    //
    // Here, it transforms
    // [b0.w0, b1.w0, b2.w0, b3.w0] and
    // [b0.w1, b1.w1, b2.w1, b3.w1]
    // into [b0.w0, b0.w1, b1.w0, b1.w1].
    let a = aarch64::vzip1q_u32(w0, w1);
    // `vzip2q_u32` is similar except it takes the high bits,
    // so we are left with: [b2.w0, b2.w1, b3.w0, b3.w1]
    let b = aarch64::vzip2q_u32(w0, w1);
    let c = aarch64::vzip1q_u32(w2, w3);
    let d = aarch64::vzip2q_u32(w2, w3);
    // `vcombine_u32` simply takes two `uint32x2_t` and concatenates them.
    // Now combine [b0.w0, b0.w1] from the low part of `a` and [b0.w2, b0.w3] from the low part of `c`,
    // which is exactly the ordering required, [b0.w0, b0.w1, b0.w2, b0.w3].
    let words0 = aarch64::vcombine_u32(aarch64::vget_low_u32(a), aarch64::vget_low_u32(c));
    let words1 = aarch64::vcombine_u32(aarch64::vget_high_u32(a), aarch64::vget_high_u32(c));
    let words2 = aarch64::vcombine_u32(aarch64::vget_low_u32(b), aarch64::vget_low_u32(d));
    let words3 = aarch64::vcombine_u32(aarch64::vget_high_u32(b), aarch64::vget_high_u32(d));

    let base = chunk.as_mut_ptr();
    let words = [words0, words1, words2, words3];
    for (j, keystream) in words.iter().enumerate() {
        let ptr = base.add(j * 64 + offset);
        // Load 16 bytes of plaintext
        let plaintext = aarch64::vld1q_u8(ptr);
        let keystream_bytes = aarch64::vreinterpretq_u8_u32(*keystream);
        // Exclusive OR the keystream into the plaintext
        let xored = aarch64::veorq_u8(plaintext, keystream_bytes);
        // Write the XOR back to the buffer
        aarch64::vst1q_u8(ptr, xored);
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use hex::hex;

    use super::super::{ChaCha20, Key, Nonce};
    use super::{apply_4_blocks, apply_8_blocks};

    #[test]
    fn matches_single_block_processing_4way() {
        let key =
            Key::new(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Nonce::new(hex!("000000090000004a00000000"));
        let cipher = ChaCha20::new_from_block(key, nonce, 0);

        // Compares the neon 4-block processing with the single block processing.
        for start in [0u32, 1, 42, 1_000, u32::MAX - 3] {
            let mut neon_ks = [0u8; 4 * 64];
            apply_4_blocks(&mut neon_ks, &key, &nonce, start);

            let mut scalar_ks = [0u8; 4 * 64];
            for i in 0u32..4 {
                let ks = cipher.get_keystream(start + i);
                let base = i as usize * 64;
                scalar_ks[base..base + 64].copy_from_slice(&ks);
            }
            assert_eq!(neon_ks, scalar_ks, "mismatch at start_block={}", start);
        }
    }

    #[test]
    fn matches_single_block_processing_8way() {
        let key =
            Key::new(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Nonce::new(hex!("000000090000004a00000000"));
        let cipher = ChaCha20::new_from_block(key, nonce, 0);

        // Compares the neon 8-block processing with the single block processing.
        for start in [0u32, 1, 42, 1_000, u32::MAX - 7] {
            let mut neon_ks = [0u8; 8 * 64];
            let (lo, hi) = neon_ks.split_at_mut(4 * 64);
            let chunk_lo = <&mut [u8; 4 * 64]>::try_from(lo).unwrap();
            let chunk_hi = <&mut [u8; 4 * 64]>::try_from(hi).unwrap();
            apply_8_blocks(chunk_lo, chunk_hi, &key, &nonce, start);
            let mut scalar_ks = [0u8; 8 * 64];
            for i in 0u32..8 {
                let ks = cipher.get_keystream(start + i);
                let base = i as usize * 64;
                scalar_ks[base..base + 64].copy_from_slice(&ks);
            }
            assert_eq!(neon_ks, scalar_ks, "mismatch at start_block={}", start);
        }
    }
}
