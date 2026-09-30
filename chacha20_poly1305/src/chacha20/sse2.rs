// SPDX-License-Identifier: CC0-1.0

//! `ChaCha20` block function using x86 SSE2, processing 4 blocks in parallel.
//!
//! This module utilizes SIMD over the `__m128i` type provided by the x86
//! SSE2 intrinsics. The steps are identical to the RFC for processing a single
//! block, however a final matrix transpose is required to properly apply the
//! state to the ciphertext.
#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use super::{Key, Nonce, WORD_1, WORD_2, WORD_3, WORD_4};

// One word of chacha state, separated over 4 blocks.
type Word = arch::__m128i;
// One row of chacha state, separated over 4 blocks.
type StateRow = (Word, Word, Word, Word);

// The `ChaCha20` quarter round applied to four independent blocks in parallel.
//
// For a single state, the quarter round is described here:
// https://datatracker.ietf.org/doc/html/rfc7539#section-2.1
//
// Each argument is a `__m128i` holding the same state variable across four blocks.
//
// SAFETY: SSE2 intrinsics are gated by target feature `sse2`.
#[inline(always)]
unsafe fn quarter_round(a: &mut Word, b: &mut Word, c: &mut Word, d: &mut Word) {
    // `_mm_add_epi32` is a vector pairwise add.
    // `_mm_xor_si128` is a vector bitwise exclusive OR.
    *a = arch::_mm_add_epi32(*a, *b);
    *d = rotl16(arch::_mm_xor_si128(*d, *a));

    *c = arch::_mm_add_epi32(*c, *d);
    *b = rotl12(arch::_mm_xor_si128(*b, *c));

    *a = arch::_mm_add_epi32(*a, *b);
    *d = rotl8(arch::_mm_xor_si128(*d, *a));

    *c = arch::_mm_add_epi32(*c, *d);
    *b = rotl7(arch::_mm_xor_si128(*b, *c));
}

// Rotate left by 16 within each 32-bit lane via two shifts and an OR.
//
// SAFETY: SSE2 intrinsics are gated by target feature `sse2`.
#[inline(always)]
unsafe fn rotl16(x: Word) -> Word {
    arch::_mm_or_si128(arch::_mm_slli_epi32(x, 16), arch::_mm_srli_epi32(x, 16))
}

// Rotate left by 12 within each 32-bit lane via two shifts and an OR.
//
// SAFETY: SSE2 intrinsics are gated by target feature `sse2`.
#[inline(always)]
unsafe fn rotl12(x: Word) -> Word {
    arch::_mm_or_si128(arch::_mm_slli_epi32(x, 12), arch::_mm_srli_epi32(x, 20))
}

// Rotate left by 8 within each 32-bit lane via two shifts and an OR.
//
// SAFETY: SSE2 intrinsics are gated by target feature `sse2`.
#[inline(always)]
unsafe fn rotl8(x: Word) -> Word {
    arch::_mm_or_si128(arch::_mm_slli_epi32(x, 8), arch::_mm_srli_epi32(x, 24))
}

// Rotate left by 7 within each 32-bit lane via two shifts and an OR.
//
// SAFETY: SSE2 intrinsics are gated by target feature `sse2`.
#[inline(always)]
unsafe fn rotl7(x: Word) -> Word {
    arch::_mm_or_si128(arch::_mm_slli_epi32(x, 7), arch::_mm_srli_epi32(x, 25))
}

// Initial chacha state that does not vary by the block counter.
//
// SAFETY: SSE2 intrinsics are gated by target feature `sse2`.
#[inline(always)]
unsafe fn init_three_rows(key: &Key) -> (StateRow, StateRow, StateRow) {
    // Initialize length 4 vectors of 32 bit values.
    //
    // The `_mm_set1_epi32` calls duplicate the 32-bit word to a `__m128i`.
    //
    // The `as` casts simply reinterpret the bits and are not lossy.
    //
    // This is a 4-lane version of the initial chacha state
    // described here: https://datatracker.ietf.org/doc/html/rfc7539#section-2.3
    let init0 = arch::_mm_set1_epi32(WORD_1 as i32);
    let init1 = arch::_mm_set1_epi32(WORD_2 as i32);
    let init2 = arch::_mm_set1_epi32(WORD_3 as i32);
    let init3 = arch::_mm_set1_epi32(WORD_4 as i32);
    let init4 =
        arch::_mm_set1_epi32(u32::from_le_bytes([key.0[0], key.0[1], key.0[2], key.0[3]]) as i32);
    let init5 =
        arch::_mm_set1_epi32(u32::from_le_bytes([key.0[4], key.0[5], key.0[6], key.0[7]]) as i32);
    let init6 =
        arch::_mm_set1_epi32(u32::from_le_bytes([key.0[8], key.0[9], key.0[10], key.0[11]]) as i32);
    let init7 =
        arch::_mm_set1_epi32(
            u32::from_le_bytes([key.0[12], key.0[13], key.0[14], key.0[15]]) as i32
        );
    let init8 =
        arch::_mm_set1_epi32(
            u32::from_le_bytes([key.0[16], key.0[17], key.0[18], key.0[19]]) as i32
        );
    let init9 =
        arch::_mm_set1_epi32(
            u32::from_le_bytes([key.0[20], key.0[21], key.0[22], key.0[23]]) as i32
        );
    let init10 =
        arch::_mm_set1_epi32(
            u32::from_le_bytes([key.0[24], key.0[25], key.0[26], key.0[27]]) as i32
        );
    let init11 =
        arch::_mm_set1_epi32(
            u32::from_le_bytes([key.0[28], key.0[29], key.0[30], key.0[31]]) as i32
        );
    ((init0, init1, init2, init3), (init4, init5, init6, init7), (init8, init9, init10, init11))
}

// Three words of the final block, comprised of the nonce.
//
// SAFETY: SSE2 intrinsics are gated by target feature `sse2`.
#[inline(always)]
unsafe fn init_nonce_words(nonce: &Nonce) -> (Word, Word, Word) {
    let init13 =
        arch::_mm_set1_epi32(
            u32::from_le_bytes([nonce.0[0], nonce.0[1], nonce.0[2], nonce.0[3]]) as i32
        );
    let init14 =
        arch::_mm_set1_epi32(
            u32::from_le_bytes([nonce.0[4], nonce.0[5], nonce.0[6], nonce.0[7]]) as i32
        );
    let init15 =
        arch::_mm_set1_epi32(
            u32::from_le_bytes([nonce.0[8], nonce.0[9], nonce.0[10], nonce.0[11]]) as i32,
        );
    (init13, init14, init15)
}

// XOR four consecutive `ChaCha20` blocks of keystream into `chunk`, starting
// at `start_block`.
#[inline]
pub(super) fn apply_4_blocks(chunk: &mut [u8; 4 * 64], key: &Key, nonce: &Nonce, start_block: u32) {
    // SAFETY: SSE2 intrinsics are gated by target feature `sse2`.
    unsafe {
        // Initialize length 4 vectors of 32 bit values.
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
        let init12 = arch::_mm_set_epi32(
            start_block.wrapping_add(3) as i32,
            start_block.wrapping_add(2) as i32,
            start_block.wrapping_add(1) as i32,
            start_block as i32,
        );

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
        w0 = arch::_mm_add_epi32(w0, init0);
        w1 = arch::_mm_add_epi32(w1, init1);
        w2 = arch::_mm_add_epi32(w2, init2);
        w3 = arch::_mm_add_epi32(w3, init3);
        w4 = arch::_mm_add_epi32(w4, init4);
        w5 = arch::_mm_add_epi32(w5, init5);
        w6 = arch::_mm_add_epi32(w6, init6);
        w7 = arch::_mm_add_epi32(w7, init7);
        w8 = arch::_mm_add_epi32(w8, init8);
        w9 = arch::_mm_add_epi32(w9, init9);
        w10 = arch::_mm_add_epi32(w10, init10);
        w11 = arch::_mm_add_epi32(w11, init11);
        w12 = arch::_mm_add_epi32(w12, init12);
        w13 = arch::_mm_add_epi32(w13, init13);
        w14 = arch::_mm_add_epi32(w14, init14);
        w15 = arch::_mm_add_epi32(w15, init15);

        xor_into(chunk, 0, w0, w1, w2, w3); // bytes  0..16 of each block
        xor_into(chunk, 16, w4, w5, w6, w7); // bytes 16..32
        xor_into(chunk, 32, w8, w9, w10, w11); // bytes 32..48
        xor_into(chunk, 48, w12, w13, w14, w15); // bytes 48..64
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
// In the current state, each `__m128i` contains the word
// at an index `i`: [b0.w_i, b1.w_i, b2.w_i, b3.w_i].
//
// We want: [b0.w0, b0.w1, b0.w2, b0.w3] so we can XOR into the
// ciphertext.
//
// SAFETY: SSE2 intrinsics are gated by target feature `sse2`.
// The buffer is not guaranteed to be 16-byte aligned, hence the unaligned
// `loadu`/`storeu` intrinsics and the pointer cast below.
#[allow(clippy::cast_ptr_alignment)]
#[inline(always)]
unsafe fn xor_into(
    chunk: &mut [u8; 4 * 64],
    offset: usize,
    w0: Word,
    w1: Word,
    w2: Word,
    w3: Word,
) {
    // `_mm_unpacklo_epi32` interleaves the lower halves of its inputs:
    // [a, b, c, d] and [e, f, g, h] become [a, e, b, f].
    //
    // Here, it transforms
    // [b0.w0, b1.w0, b2.w0, b3.w0] and
    // [b0.w1, b1.w1, b2.w1, b3.w1]
    // into [b0.w0, b0.w1, b1.w0, b1.w1].
    let a = arch::_mm_unpacklo_epi32(w0, w1);
    // `_mm_unpackhi_epi32` is similar except it takes the high halves,
    // so we are left with: [b2.w0, b2.w1, b3.w0, b3.w1].
    let b = arch::_mm_unpackhi_epi32(w0, w1);
    let c = arch::_mm_unpacklo_epi32(w2, w3);
    let d = arch::_mm_unpackhi_epi32(w2, w3);
    // `_mm_unpacklo_epi64` takes the low 64 bits of each input and
    // concatenates them. Combining the low part of `a` ([b0.w0, b0.w1])
    // with the low part of `c` ([b0.w2, b0.w3]) gives the ordering
    // required for the first block: [b0.w0, b0.w1, b0.w2, b0.w3].
    let words0 = arch::_mm_unpacklo_epi64(a, c);
    let words1 = arch::_mm_unpackhi_epi64(a, c);
    let words2 = arch::_mm_unpacklo_epi64(b, d);
    let words3 = arch::_mm_unpackhi_epi64(b, d);

    let base = chunk.as_mut_ptr();
    let words = [words0, words1, words2, words3];
    for (j, keystream) in words.iter().enumerate() {
        let ptr = base.add(j * 64 + offset).cast::<Word>();
        // Load 16 bytes of plaintext
        let plaintext = arch::_mm_loadu_si128(ptr);
        // Exclusive OR the keystream into the plaintext
        let xored = arch::_mm_xor_si128(plaintext, *keystream);
        // Write the XOR back to the buffer
        arch::_mm_storeu_si128(ptr, xored);
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use hex::hex;

    use super::super::{ChaCha20, Key, Nonce};
    use super::apply_4_blocks;

    #[test]
    fn matches_single_block_processing_4way() {
        let key =
            Key::new(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Nonce::new(hex!("000000090000004a00000000"));
        let cipher = ChaCha20::new_from_block(key, nonce, 0);

        // Compares the SSE2 4-block processing with the single block processing.
        for start in [0u32, 1, 42, 1_000, u32::MAX - 3] {
            let mut sse2_ks = [0u8; 4 * 64];
            apply_4_blocks(&mut sse2_ks, &key, &nonce, start);

            let mut scalar_ks = [0u8; 4 * 64];
            for i in 0u32..4 {
                let ks = cipher.get_keystream(start + i);
                let base = i as usize * 64;
                scalar_ks[base..base + 64].copy_from_slice(&ks);
            }
            assert_eq!(sse2_ks, scalar_ks, "mismatch at start_block={}", start);
        }
    }
}
