// SPDX-License-Identifier: CC0-1.0

//! x86 SHA-NI intrinsics for SHA256.

#![allow(clippy::cast_ptr_alignment)]

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi32,
    _mm_shuffle_epi8, _mm_storeu_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi32,
    _mm_shuffle_epi8, _mm_storeu_si128,
};

/// Processes SHA256 blocks using x86 SHA-NI intrinsics.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub(super) unsafe fn process_blocks(state: &mut [u32; 8], blocks: &[u8]) {
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

    let (mut abef_save, mut cdgh_save);

    #[allow(non_snake_case)]
    let MASK: __m128i =
        _mm_set_epi64x(0x0c0d_0e0f_0809_0a0bu64 as i64, 0x0405_0607_0001_0203u64 as i64);

    // Load initial values
    // CAST SAFETY: loadu_si128 documentation states that mem_addr does not
    // need to be aligned on any particular boundary.
    tmp = _mm_loadu_si128(state.as_ptr().add(0).cast::<__m128i>());
    state1 = _mm_loadu_si128(state.as_ptr().add(4).cast::<__m128i>());

    tmp = _mm_shuffle_epi32(tmp, 0xB1); // CDAB
    state1 = _mm_shuffle_epi32(state1, 0x1B); // EFGH
    state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
    state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

    let mut block_offset = 0;
    while block_offset < blocks.len() {
        // Save current state
        abef_save = state0;
        cdgh_save = state1;

        // Rounds 1-4
        msg = _mm_loadu_si128(blocks.as_ptr().add(block_offset).cast::<__m128i>());
        msg0 = _mm_shuffle_epi8(msg, MASK);
        msg = _mm_add_epi32(
            msg0,
            _mm_set_epi64x(0xE9B5DBA5B5C0FBCFu64 as i64, 0x71374491428A2F98u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 5-8
        msg1 = _mm_loadu_si128(blocks.as_ptr().add(block_offset + 16).cast::<__m128i>());
        msg1 = _mm_shuffle_epi8(msg1, MASK);
        msg = _mm_add_epi32(
            msg1,
            _mm_set_epi64x(0xAB1C5ED5923F82A4u64 as i64, 0x59F111F13956C25Bu64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 9-12
        msg2 = _mm_loadu_si128(blocks.as_ptr().add(block_offset + 32).cast::<__m128i>());
        msg2 = _mm_shuffle_epi8(msg2, MASK);
        msg = _mm_add_epi32(
            msg2,
            _mm_set_epi64x(0x550C7DC3243185BEu64 as i64, 0x12835B01D807AA98u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 13-16
        msg3 = _mm_loadu_si128(blocks.as_ptr().add(block_offset + 48).cast::<__m128i>());
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

        // Rounds 17-20
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

        // Rounds 21-24
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

        // Rounds 25-28
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

        // Rounds 29-32
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

        // Rounds 33-36
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

        // Rounds 37-40
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

        // Rounds 41-44
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

        // Rounds 45-48
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

        // Rounds 49-52
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

        // Rounds 53-56
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

        // Rounds 57-60
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

        // Rounds 61-64
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

        block_offset += 64;
    }

    tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
    state1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
    state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
    state1 = _mm_alignr_epi8(state1, tmp, 8); // ABEF

    // Save state
    // CAST SAFETY: storeu_si128 documentation states that mem_addr does not
    // need to be aligned on any particular boundary.
    _mm_storeu_si128(state.as_mut_ptr().add(0).cast::<__m128i>(), state0);
    _mm_storeu_si128(state.as_mut_ptr().add(4).cast::<__m128i>(), state1);
}

/// Computes `SHA256d` of two 64-byte inputs in parallel using x86 SHA-NI intrinsics.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub(super) unsafe fn sha256d_64_2way(output: &mut [[u8; 32]; 2], input: &[[u8; 64]; 2]) {
    // SHA256 round constants
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ];

    // Precomputed W[i] + K[i] for the 2nd transform (padding block).
    #[rustfmt::skip]
    const MIDS: [u32; 64] = [
        0xc28a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf374,
        0x649b69c1, 0xf0fe4786, 0x0fe1edc6, 0x240cf254,
        0x4fe9346f, 0x6cc984be, 0x61b9411e, 0x16f988fa,
        0xf2c65152, 0xa88e5a6d, 0xb019fc65, 0xb9d99ec7,
        0x9a1231c3, 0xe70eeaa0, 0xfdb1232b, 0xc7353eb0,
        0x3069bad5, 0xcb976d5f, 0x5a0f118f, 0xdc1eeefd,
        0x0a35b689, 0xde0b7a04, 0x58f4ca9d, 0xe15d5b16,
        0x007f3e86, 0x37088980, 0xa507ea32, 0x6fab9537,
        0x17406110, 0x0d8cd6f1, 0xcdaa3b6d, 0xc0bbbe37,
        0x83613bda, 0xdb48a363, 0x0b02e931, 0x6fd15ca7,
        0x521afaca, 0x31338431, 0x6ed41a95, 0x6d437890,
        0xc39c91f2, 0x9eccabbd, 0xb5c9a0e6, 0x532fb63c,
        0xd2c741c6, 0x07237ea3, 0xa4954b68, 0x4c191d76
    ];

    // Precomputed values for Transform 3 rounds 9-16.
    // FINS[0..3]: msg2 + K[8..11]
    // FINS[4..7]: _mm_sha256msg1_epu32(msg2, msg3)
    // FINS[8..11]: msg2 + K[12..15]
    #[rustfmt::skip]
    const FINS: [u32; 12] = [
        0x5807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x80000000, 0x00000000, 0x00000000, 0x00000000,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf274,
    ];

    // Padding processed in the 3rd transform (byteswapped).
    const FINAL: [u32; 8] = [0x80000000, 0, 0, 0, 0, 0, 0, 0x100];

    #[allow(non_snake_case)]
    let MASK: __m128i =
        _mm_set_epi64x(0x0c0d_0e0f_0809_0a0bu64 as i64, 0x0405_0607_0001_0203u64 as i64);

    // Preshuffled SHA256 initial hash values for x86 SHA-NI.
    let init0: __m128i = _mm_set_epi64x(0x6a09e667bb67ae85u64 as i64, 0x510e527f9b05688cu64 as i64);
    let init1: __m128i = _mm_set_epi64x(0x3c6ef372a54ff53au64 as i64, 0x1f83d9ab5be0cd19u64 as i64);

    let (mut state0_a, mut state0_b, mut state1_a, mut state1_b);
    let (abef_save_a, abef_save_b, cdgh_save_a, cdgh_save_b);
    let (mut msg_a, mut msg_b, mut tmp_a, mut tmp_b);
    let (mut msg0_a, mut msg0_b, mut msg1_a, mut msg1_b);
    let (mut msg2_a, mut msg2_b, mut msg3_a, mut msg3_b);

    // ------------------ Transform 1 -------------------

    // Load state
    state0_a = init0;
    state0_b = init0;
    state1_a = init1;
    state1_b = init1;

    // Rounds 0-3
    let k = _mm_loadu_si128(K.as_ptr().add(0).cast::<__m128i>());
    msg_a = _mm_loadu_si128(input[0].as_ptr().add(0).cast::<__m128i>());
    msg_b = _mm_loadu_si128(input[1].as_ptr().add(0).cast::<__m128i>());
    msg0_a = _mm_shuffle_epi8(msg_a, MASK);
    msg0_b = _mm_shuffle_epi8(msg_b, MASK);
    msg_a = _mm_add_epi32(msg0_a, k);
    msg_b = _mm_add_epi32(msg0_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);

    // Rounds 4-7
    let k = _mm_loadu_si128(K.as_ptr().add(4).cast::<__m128i>());
    msg_a = _mm_loadu_si128(input[0].as_ptr().add(16).cast::<__m128i>());
    msg_b = _mm_loadu_si128(input[1].as_ptr().add(16).cast::<__m128i>());
    msg1_a = _mm_shuffle_epi8(msg_a, MASK);
    msg1_b = _mm_shuffle_epi8(msg_b, MASK);
    msg_a = _mm_add_epi32(msg1_a, k);
    msg_b = _mm_add_epi32(msg1_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg0_a = _mm_sha256msg1_epu32(msg0_a, msg1_a);
    msg0_b = _mm_sha256msg1_epu32(msg0_b, msg1_b);

    // Rounds 8-11
    let k = _mm_loadu_si128(K.as_ptr().add(8).cast::<__m128i>());
    msg_a = _mm_loadu_si128(input[0].as_ptr().add(32).cast::<__m128i>());
    msg_b = _mm_loadu_si128(input[1].as_ptr().add(32).cast::<__m128i>());
    msg2_a = _mm_shuffle_epi8(msg_a, MASK);
    msg2_b = _mm_shuffle_epi8(msg_b, MASK);
    msg_a = _mm_add_epi32(msg2_a, k);
    msg_b = _mm_add_epi32(msg2_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg1_a = _mm_sha256msg1_epu32(msg1_a, msg2_a);
    msg1_b = _mm_sha256msg1_epu32(msg1_b, msg2_b);

    // Rounds 12-15
    let k = _mm_loadu_si128(K.as_ptr().add(12).cast::<__m128i>());
    msg_a = _mm_loadu_si128(input[0].as_ptr().add(48).cast::<__m128i>());
    msg_b = _mm_loadu_si128(input[1].as_ptr().add(48).cast::<__m128i>());
    msg3_a = _mm_shuffle_epi8(msg_a, MASK);
    msg3_b = _mm_shuffle_epi8(msg_b, MASK);
    msg_a = _mm_add_epi32(msg3_a, k);
    msg_b = _mm_add_epi32(msg3_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg3_a, msg2_a, 4);
    tmp_b = _mm_alignr_epi8(msg3_b, msg2_b, 4);
    msg0_a = _mm_add_epi32(msg0_a, tmp_a);
    msg0_b = _mm_add_epi32(msg0_b, tmp_b);
    msg0_a = _mm_sha256msg2_epu32(msg0_a, msg3_a);
    msg0_b = _mm_sha256msg2_epu32(msg0_b, msg3_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg2_a = _mm_sha256msg1_epu32(msg2_a, msg3_a);
    msg2_b = _mm_sha256msg1_epu32(msg2_b, msg3_b);

    // Rounds 16-19
    let k = _mm_loadu_si128(K.as_ptr().add(16).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg0_a, k);
    msg_b = _mm_add_epi32(msg0_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg0_a, msg3_a, 4);
    tmp_b = _mm_alignr_epi8(msg0_b, msg3_b, 4);
    msg1_a = _mm_add_epi32(msg1_a, tmp_a);
    msg1_b = _mm_add_epi32(msg1_b, tmp_b);
    msg1_a = _mm_sha256msg2_epu32(msg1_a, msg0_a);
    msg1_b = _mm_sha256msg2_epu32(msg1_b, msg0_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg3_a = _mm_sha256msg1_epu32(msg3_a, msg0_a);
    msg3_b = _mm_sha256msg1_epu32(msg3_b, msg0_b);

    // Rounds 20-23
    let k = _mm_loadu_si128(K.as_ptr().add(20).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg1_a, k);
    msg_b = _mm_add_epi32(msg1_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg1_a, msg0_a, 4);
    tmp_b = _mm_alignr_epi8(msg1_b, msg0_b, 4);
    msg2_a = _mm_add_epi32(msg2_a, tmp_a);
    msg2_b = _mm_add_epi32(msg2_b, tmp_b);
    msg2_a = _mm_sha256msg2_epu32(msg2_a, msg1_a);
    msg2_b = _mm_sha256msg2_epu32(msg2_b, msg1_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg0_a = _mm_sha256msg1_epu32(msg0_a, msg1_a);
    msg0_b = _mm_sha256msg1_epu32(msg0_b, msg1_b);

    // Rounds 24-27
    let k = _mm_loadu_si128(K.as_ptr().add(24).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg2_a, k);
    msg_b = _mm_add_epi32(msg2_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg2_a, msg1_a, 4);
    tmp_b = _mm_alignr_epi8(msg2_b, msg1_b, 4);
    msg3_a = _mm_add_epi32(msg3_a, tmp_a);
    msg3_b = _mm_add_epi32(msg3_b, tmp_b);
    msg3_a = _mm_sha256msg2_epu32(msg3_a, msg2_a);
    msg3_b = _mm_sha256msg2_epu32(msg3_b, msg2_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg1_a = _mm_sha256msg1_epu32(msg1_a, msg2_a);
    msg1_b = _mm_sha256msg1_epu32(msg1_b, msg2_b);

    // Rounds 28-31
    let k = _mm_loadu_si128(K.as_ptr().add(28).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg3_a, k);
    msg_b = _mm_add_epi32(msg3_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg3_a, msg2_a, 4);
    tmp_b = _mm_alignr_epi8(msg3_b, msg2_b, 4);
    msg0_a = _mm_add_epi32(msg0_a, tmp_a);
    msg0_b = _mm_add_epi32(msg0_b, tmp_b);
    msg0_a = _mm_sha256msg2_epu32(msg0_a, msg3_a);
    msg0_b = _mm_sha256msg2_epu32(msg0_b, msg3_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg2_a = _mm_sha256msg1_epu32(msg2_a, msg3_a);
    msg2_b = _mm_sha256msg1_epu32(msg2_b, msg3_b);

    // Rounds 32-35
    let k = _mm_loadu_si128(K.as_ptr().add(32).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg0_a, k);
    msg_b = _mm_add_epi32(msg0_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg0_a, msg3_a, 4);
    tmp_b = _mm_alignr_epi8(msg0_b, msg3_b, 4);
    msg1_a = _mm_add_epi32(msg1_a, tmp_a);
    msg1_b = _mm_add_epi32(msg1_b, tmp_b);
    msg1_a = _mm_sha256msg2_epu32(msg1_a, msg0_a);
    msg1_b = _mm_sha256msg2_epu32(msg1_b, msg0_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg3_a = _mm_sha256msg1_epu32(msg3_a, msg0_a);
    msg3_b = _mm_sha256msg1_epu32(msg3_b, msg0_b);

    // Rounds 36-39
    let k = _mm_loadu_si128(K.as_ptr().add(36).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg1_a, k);
    msg_b = _mm_add_epi32(msg1_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg1_a, msg0_a, 4);
    tmp_b = _mm_alignr_epi8(msg1_b, msg0_b, 4);
    msg2_a = _mm_add_epi32(msg2_a, tmp_a);
    msg2_b = _mm_add_epi32(msg2_b, tmp_b);
    msg2_a = _mm_sha256msg2_epu32(msg2_a, msg1_a);
    msg2_b = _mm_sha256msg2_epu32(msg2_b, msg1_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg0_a = _mm_sha256msg1_epu32(msg0_a, msg1_a);
    msg0_b = _mm_sha256msg1_epu32(msg0_b, msg1_b);

    // Rounds 40-43
    let k = _mm_loadu_si128(K.as_ptr().add(40).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg2_a, k);
    msg_b = _mm_add_epi32(msg2_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg2_a, msg1_a, 4);
    tmp_b = _mm_alignr_epi8(msg2_b, msg1_b, 4);
    msg3_a = _mm_add_epi32(msg3_a, tmp_a);
    msg3_b = _mm_add_epi32(msg3_b, tmp_b);
    msg3_a = _mm_sha256msg2_epu32(msg3_a, msg2_a);
    msg3_b = _mm_sha256msg2_epu32(msg3_b, msg2_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg1_a = _mm_sha256msg1_epu32(msg1_a, msg2_a);
    msg1_b = _mm_sha256msg1_epu32(msg1_b, msg2_b);

    // Rounds 44-47
    let k = _mm_loadu_si128(K.as_ptr().add(44).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg3_a, k);
    msg_b = _mm_add_epi32(msg3_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg3_a, msg2_a, 4);
    tmp_b = _mm_alignr_epi8(msg3_b, msg2_b, 4);
    msg0_a = _mm_add_epi32(msg0_a, tmp_a);
    msg0_b = _mm_add_epi32(msg0_b, tmp_b);
    msg0_a = _mm_sha256msg2_epu32(msg0_a, msg3_a);
    msg0_b = _mm_sha256msg2_epu32(msg0_b, msg3_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg2_a = _mm_sha256msg1_epu32(msg2_a, msg3_a);
    msg2_b = _mm_sha256msg1_epu32(msg2_b, msg3_b);

    // Rounds 48-51
    let k = _mm_loadu_si128(K.as_ptr().add(48).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg0_a, k);
    msg_b = _mm_add_epi32(msg0_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg0_a, msg3_a, 4);
    tmp_b = _mm_alignr_epi8(msg0_b, msg3_b, 4);
    msg1_a = _mm_add_epi32(msg1_a, tmp_a);
    msg1_b = _mm_add_epi32(msg1_b, tmp_b);
    msg1_a = _mm_sha256msg2_epu32(msg1_a, msg0_a);
    msg1_b = _mm_sha256msg2_epu32(msg1_b, msg0_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg3_a = _mm_sha256msg1_epu32(msg3_a, msg0_a);
    msg3_b = _mm_sha256msg1_epu32(msg3_b, msg0_b);

    // Rounds 52-55
    let k = _mm_loadu_si128(K.as_ptr().add(52).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg1_a, k);
    msg_b = _mm_add_epi32(msg1_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg1_a, msg0_a, 4);
    tmp_b = _mm_alignr_epi8(msg1_b, msg0_b, 4);
    msg2_a = _mm_add_epi32(msg2_a, tmp_a);
    msg2_b = _mm_add_epi32(msg2_b, tmp_b);
    msg2_a = _mm_sha256msg2_epu32(msg2_a, msg1_a);
    msg2_b = _mm_sha256msg2_epu32(msg2_b, msg1_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);

    // Rounds 56-59
    let k = _mm_loadu_si128(K.as_ptr().add(56).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg2_a, k);
    msg_b = _mm_add_epi32(msg2_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg2_a, msg1_a, 4);
    tmp_b = _mm_alignr_epi8(msg2_b, msg1_b, 4);
    msg3_a = _mm_add_epi32(msg3_a, tmp_a);
    msg3_b = _mm_add_epi32(msg3_b, tmp_b);
    msg3_a = _mm_sha256msg2_epu32(msg3_a, msg2_a);
    msg3_b = _mm_sha256msg2_epu32(msg3_b, msg2_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);

    // Rounds 60-63
    let k = _mm_loadu_si128(K.as_ptr().add(60).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg3_a, k);
    msg_b = _mm_add_epi32(msg3_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);

    // Transform 1: Update state
    state0_a = _mm_add_epi32(state0_a, init0);
    state0_b = _mm_add_epi32(state0_b, init0);
    state1_a = _mm_add_epi32(state1_a, init1);
    state1_b = _mm_add_epi32(state1_b, init1);

    // ------------------ Transform 2 -------------------

    // Save state
    abef_save_a = state0_a;
    abef_save_b = state0_b;
    cdgh_save_a = state1_a;
    cdgh_save_b = state1_b;

    // Rounds 0-3
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(0).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 4-7
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(4).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 8-11
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(8).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 12-15
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(12).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 16-19
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(16).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 20-23
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(20).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 24-27
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(24).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 28-31
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(28).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 32-35
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(32).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 36-39
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(36).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 40-43
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(40).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 44-47
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(44).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 48-51
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(48).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 52-55
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(52).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 56-59
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(56).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Rounds 60-63
    msg_a = _mm_loadu_si128(MIDS.as_ptr().add(60).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);

    // Transform 2: Update state
    state0_a = _mm_add_epi32(state0_a, abef_save_a);
    state0_b = _mm_add_epi32(state0_b, abef_save_b);
    state1_a = _mm_add_epi32(state1_a, cdgh_save_a);
    state1_b = _mm_add_epi32(state1_b, cdgh_save_b);

    // Unshuffle to extract hash
    tmp_a = _mm_shuffle_epi32(state0_a, 0x1B);
    tmp_b = _mm_shuffle_epi32(state0_b, 0x1B);
    state1_a = _mm_shuffle_epi32(state1_a, 0xB1);
    state1_b = _mm_shuffle_epi32(state1_b, 0xB1);
    msg0_a = _mm_blend_epi16(tmp_a, state1_a, 0xF0);
    msg0_b = _mm_blend_epi16(tmp_b, state1_b, 0xF0);
    msg1_a = _mm_alignr_epi8(state1_a, tmp_a, 8);
    msg1_b = _mm_alignr_epi8(state1_b, tmp_b, 8);

    // ------------------ Transform 3 -------------------

    // Load state
    state0_a = init0;
    state0_b = init0;
    state1_a = init1;
    state1_b = init1;

    // Rounds 0-3
    let k = _mm_loadu_si128(K.as_ptr().add(0).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg0_a, k);
    msg_b = _mm_add_epi32(msg0_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);

    // Rounds 4-7
    let k = _mm_loadu_si128(K.as_ptr().add(4).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg1_a, k);
    msg_b = _mm_add_epi32(msg1_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg0_a = _mm_sha256msg1_epu32(msg0_a, msg1_a);
    msg0_b = _mm_sha256msg1_epu32(msg0_b, msg1_b);

    // Rounds 8-11
    msg2_a = _mm_loadu_si128(FINS.as_ptr().add(4).cast::<__m128i>());
    msg2_b = msg2_a;
    msg_a = _mm_loadu_si128(FINS.as_ptr().add(0).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);
    msg1_a = _mm_sha256msg1_epu32(msg1_a, msg2_a);
    msg1_b = _mm_sha256msg1_epu32(msg1_b, msg2_b);

    // Rounds 12-15
    msg3_a = _mm_loadu_si128(FINAL.as_ptr().add(4).cast::<__m128i>());
    msg3_b = msg3_a;
    msg_a = _mm_loadu_si128(FINS.as_ptr().add(8).cast::<__m128i>());
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_a);
    tmp_a = _mm_alignr_epi8(msg3_a, msg2_a, 4);
    tmp_b = _mm_alignr_epi8(msg3_b, msg2_b, 4);
    msg0_a = _mm_add_epi32(msg0_a, tmp_a);
    msg0_b = _mm_add_epi32(msg0_b, tmp_b);
    msg0_a = _mm_sha256msg2_epu32(msg0_a, msg3_a);
    msg0_b = _mm_sha256msg2_epu32(msg0_b, msg3_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_a);
    msg2_a = _mm_sha256msg1_epu32(msg2_a, msg3_a);
    msg2_b = _mm_sha256msg1_epu32(msg2_b, msg3_b);

    // Rounds 16-19
    let k = _mm_loadu_si128(K.as_ptr().add(16).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg0_a, k);
    msg_b = _mm_add_epi32(msg0_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg0_a, msg3_a, 4);
    tmp_b = _mm_alignr_epi8(msg0_b, msg3_b, 4);
    msg1_a = _mm_add_epi32(msg1_a, tmp_a);
    msg1_b = _mm_add_epi32(msg1_b, tmp_b);
    msg1_a = _mm_sha256msg2_epu32(msg1_a, msg0_a);
    msg1_b = _mm_sha256msg2_epu32(msg1_b, msg0_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg3_a = _mm_sha256msg1_epu32(msg3_a, msg0_a);
    msg3_b = _mm_sha256msg1_epu32(msg3_b, msg0_b);

    // Rounds 20-23
    let k = _mm_loadu_si128(K.as_ptr().add(20).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg1_a, k);
    msg_b = _mm_add_epi32(msg1_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg1_a, msg0_a, 4);
    tmp_b = _mm_alignr_epi8(msg1_b, msg0_b, 4);
    msg2_a = _mm_add_epi32(msg2_a, tmp_a);
    msg2_b = _mm_add_epi32(msg2_b, tmp_b);
    msg2_a = _mm_sha256msg2_epu32(msg2_a, msg1_a);
    msg2_b = _mm_sha256msg2_epu32(msg2_b, msg1_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg0_a = _mm_sha256msg1_epu32(msg0_a, msg1_a);
    msg0_b = _mm_sha256msg1_epu32(msg0_b, msg1_b);

    // Rounds 24-27
    let k = _mm_loadu_si128(K.as_ptr().add(24).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg2_a, k);
    msg_b = _mm_add_epi32(msg2_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg2_a, msg1_a, 4);
    tmp_b = _mm_alignr_epi8(msg2_b, msg1_b, 4);
    msg3_a = _mm_add_epi32(msg3_a, tmp_a);
    msg3_b = _mm_add_epi32(msg3_b, tmp_b);
    msg3_a = _mm_sha256msg2_epu32(msg3_a, msg2_a);
    msg3_b = _mm_sha256msg2_epu32(msg3_b, msg2_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg1_a = _mm_sha256msg1_epu32(msg1_a, msg2_a);
    msg1_b = _mm_sha256msg1_epu32(msg1_b, msg2_b);

    // Rounds 28-31
    let k = _mm_loadu_si128(K.as_ptr().add(28).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg3_a, k);
    msg_b = _mm_add_epi32(msg3_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg3_a, msg2_a, 4);
    tmp_b = _mm_alignr_epi8(msg3_b, msg2_b, 4);
    msg0_a = _mm_add_epi32(msg0_a, tmp_a);
    msg0_b = _mm_add_epi32(msg0_b, tmp_b);
    msg0_a = _mm_sha256msg2_epu32(msg0_a, msg3_a);
    msg0_b = _mm_sha256msg2_epu32(msg0_b, msg3_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg2_a = _mm_sha256msg1_epu32(msg2_a, msg3_a);
    msg2_b = _mm_sha256msg1_epu32(msg2_b, msg3_b);

    // Rounds 32-35
    let k = _mm_loadu_si128(K.as_ptr().add(32).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg0_a, k);
    msg_b = _mm_add_epi32(msg0_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg0_a, msg3_a, 4);
    tmp_b = _mm_alignr_epi8(msg0_b, msg3_b, 4);
    msg1_a = _mm_add_epi32(msg1_a, tmp_a);
    msg1_b = _mm_add_epi32(msg1_b, tmp_b);
    msg1_a = _mm_sha256msg2_epu32(msg1_a, msg0_a);
    msg1_b = _mm_sha256msg2_epu32(msg1_b, msg0_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg3_a = _mm_sha256msg1_epu32(msg3_a, msg0_a);
    msg3_b = _mm_sha256msg1_epu32(msg3_b, msg0_b);

    // Rounds 36-39
    let k = _mm_loadu_si128(K.as_ptr().add(36).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg1_a, k);
    msg_b = _mm_add_epi32(msg1_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg1_a, msg0_a, 4);
    tmp_b = _mm_alignr_epi8(msg1_b, msg0_b, 4);
    msg2_a = _mm_add_epi32(msg2_a, tmp_a);
    msg2_b = _mm_add_epi32(msg2_b, tmp_b);
    msg2_a = _mm_sha256msg2_epu32(msg2_a, msg1_a);
    msg2_b = _mm_sha256msg2_epu32(msg2_b, msg1_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg0_a = _mm_sha256msg1_epu32(msg0_a, msg1_a);
    msg0_b = _mm_sha256msg1_epu32(msg0_b, msg1_b);

    // Rounds 40-43
    let k = _mm_loadu_si128(K.as_ptr().add(40).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg2_a, k);
    msg_b = _mm_add_epi32(msg2_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg2_a, msg1_a, 4);
    tmp_b = _mm_alignr_epi8(msg2_b, msg1_b, 4);
    msg3_a = _mm_add_epi32(msg3_a, tmp_a);
    msg3_b = _mm_add_epi32(msg3_b, tmp_b);
    msg3_a = _mm_sha256msg2_epu32(msg3_a, msg2_a);
    msg3_b = _mm_sha256msg2_epu32(msg3_b, msg2_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg1_a = _mm_sha256msg1_epu32(msg1_a, msg2_a);
    msg1_b = _mm_sha256msg1_epu32(msg1_b, msg2_b);

    // Rounds 44-47
    let k = _mm_loadu_si128(K.as_ptr().add(44).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg3_a, k);
    msg_b = _mm_add_epi32(msg3_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg3_a, msg2_a, 4);
    tmp_b = _mm_alignr_epi8(msg3_b, msg2_b, 4);
    msg0_a = _mm_add_epi32(msg0_a, tmp_a);
    msg0_b = _mm_add_epi32(msg0_b, tmp_b);
    msg0_a = _mm_sha256msg2_epu32(msg0_a, msg3_a);
    msg0_b = _mm_sha256msg2_epu32(msg0_b, msg3_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg2_a = _mm_sha256msg1_epu32(msg2_a, msg3_a);
    msg2_b = _mm_sha256msg1_epu32(msg2_b, msg3_b);

    // Rounds 48-51
    let k = _mm_loadu_si128(K.as_ptr().add(48).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg0_a, k);
    msg_b = _mm_add_epi32(msg0_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg0_a, msg3_a, 4);
    tmp_b = _mm_alignr_epi8(msg0_b, msg3_b, 4);
    msg1_a = _mm_add_epi32(msg1_a, tmp_a);
    msg1_b = _mm_add_epi32(msg1_b, tmp_b);
    msg1_a = _mm_sha256msg2_epu32(msg1_a, msg0_a);
    msg1_b = _mm_sha256msg2_epu32(msg1_b, msg0_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);
    msg3_a = _mm_sha256msg1_epu32(msg3_a, msg0_a);
    msg3_b = _mm_sha256msg1_epu32(msg3_b, msg0_b);

    // Rounds 52-55
    let k = _mm_loadu_si128(K.as_ptr().add(52).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg1_a, k);
    msg_b = _mm_add_epi32(msg1_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg1_a, msg0_a, 4);
    tmp_b = _mm_alignr_epi8(msg1_b, msg0_b, 4);
    msg2_a = _mm_add_epi32(msg2_a, tmp_a);
    msg2_b = _mm_add_epi32(msg2_b, tmp_b);
    msg2_a = _mm_sha256msg2_epu32(msg2_a, msg1_a);
    msg2_b = _mm_sha256msg2_epu32(msg2_b, msg1_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);

    // Rounds 56-59
    let k = _mm_loadu_si128(K.as_ptr().add(56).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg2_a, k);
    msg_b = _mm_add_epi32(msg2_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    tmp_a = _mm_alignr_epi8(msg2_a, msg1_a, 4);
    tmp_b = _mm_alignr_epi8(msg2_b, msg1_b, 4);
    msg3_a = _mm_add_epi32(msg3_a, tmp_a);
    msg3_b = _mm_add_epi32(msg3_b, tmp_b);
    msg3_a = _mm_sha256msg2_epu32(msg3_a, msg2_a);
    msg3_b = _mm_sha256msg2_epu32(msg3_b, msg2_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);

    // Rounds 60-63
    let k = _mm_loadu_si128(K.as_ptr().add(60).cast::<__m128i>());
    msg_a = _mm_add_epi32(msg3_a, k);
    msg_b = _mm_add_epi32(msg3_b, k);
    state1_a = _mm_sha256rnds2_epu32(state1_a, state0_a, msg_a);
    state1_b = _mm_sha256rnds2_epu32(state1_b, state0_b, msg_b);
    msg_a = _mm_shuffle_epi32(msg_a, 0x0E);
    msg_b = _mm_shuffle_epi32(msg_b, 0x0E);
    state0_a = _mm_sha256rnds2_epu32(state0_a, state1_a, msg_a);
    state0_b = _mm_sha256rnds2_epu32(state0_b, state1_b, msg_b);

    // Transform 3: Update state
    state0_a = _mm_add_epi32(state0_a, init0);
    state0_b = _mm_add_epi32(state0_b, init0);
    state1_a = _mm_add_epi32(state1_a, init1);
    state1_b = _mm_add_epi32(state1_b, init1);

    // Unshuffle
    tmp_a = _mm_shuffle_epi32(state0_a, 0x1B);
    tmp_b = _mm_shuffle_epi32(state0_b, 0x1B);
    state1_a = _mm_shuffle_epi32(state1_a, 0xB1);
    state1_b = _mm_shuffle_epi32(state1_b, 0xB1);
    state0_a = _mm_blend_epi16(tmp_a, state1_a, 0xF0);
    state0_b = _mm_blend_epi16(tmp_b, state1_b, 0xF0);
    state1_a = _mm_alignr_epi8(state1_a, tmp_a, 8);
    state1_b = _mm_alignr_epi8(state1_b, tmp_b, 8);

    // Store results (byte-swap to big-endian)
    // CAST SAFETY: storeu_si128 does not require alignment.
    _mm_storeu_si128(
        output[0].as_mut_ptr().add(0).cast::<__m128i>(),
        _mm_shuffle_epi8(state0_a, MASK),
    );
    _mm_storeu_si128(
        output[0].as_mut_ptr().add(16).cast::<__m128i>(),
        _mm_shuffle_epi8(state1_a, MASK),
    );
    _mm_storeu_si128(
        output[1].as_mut_ptr().add(0).cast::<__m128i>(),
        _mm_shuffle_epi8(state0_b, MASK),
    );
    _mm_storeu_si128(
        output[1].as_mut_ptr().add(16).cast::<__m128i>(),
        _mm_shuffle_epi8(state1_b, MASK),
    );
}
