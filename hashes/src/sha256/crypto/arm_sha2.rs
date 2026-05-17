// SPDX-License-Identifier: CC0-1.0

//! ARM sha2 intrinsics for sha256.

#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_ptr_alignment)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::many_single_char_names)]

use core::arch::aarch64::{
    vaddq_u32, vld1q_u32, vreinterpretq_u32_u8, vreinterpretq_u8_u32, vrev32q_u8, vsha256h2q_u32,
    vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
};

/// Processes sha256 blocks using ARM SHA2 intrinsics.
#[target_feature(enable = "sha2")]
pub(super) unsafe fn process_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    // Code translated and based on from
    // https://github.com/noloader/SHA-Intrinsics/blob/4e754bec921a9f281b69bd681ca0065763aa911c/sha256-arm.c

    /* sha256-arm.c - ARMv8 SHA extensions using C intrinsics     */
    /*   Written and placed in public domain by Jeffrey Walton    */
    /*   Based on code from ARM, and by Johannes Schneiders, Skip */
    /*   Hovsmith and Barry O'Rourke for the mbedTLS project.     */

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

    let (mut state0, mut state1);
    let (mut abcd_save, mut efgh_save);

    let (mut msg0, mut msg1, mut msg2, mut msg3);
    let (mut tmp0, mut tmp1, mut tmp2);

    // Load state
    state0 = vld1q_u32(state.as_ptr().add(0));
    state1 = vld1q_u32(state.as_ptr().add(4));

    let mut block_offset = 0;
    while block_offset < blocks.len() {
        // Save state
        abcd_save = state0;
        efgh_save = state1;

        // Load message
        msg0 = vld1q_u32(blocks.as_ptr().add(block_offset).cast::<u32>());
        msg1 = vld1q_u32(blocks.as_ptr().add(block_offset + 16).cast::<u32>());
        msg2 = vld1q_u32(blocks.as_ptr().add(block_offset + 32).cast::<u32>());
        msg3 = vld1q_u32(blocks.as_ptr().add(block_offset + 48).cast::<u32>());

        // Reverse for little endian
        msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
        msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
        msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
        msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));

        tmp0 = vaddq_u32(msg0, vld1q_u32(K.as_ptr().add(0x00)));

        // Rounds 1-4
        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, vld1q_u32(K.as_ptr().add(0x04)));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        // Rounds 5-8
        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, vld1q_u32(K.as_ptr().add(0x08)));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        // Rounds 9-12
        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, vld1q_u32(K.as_ptr().add(0x0c)));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        // Rounds 13-16
        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, vld1q_u32(K.as_ptr().add(0x10)));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 17-20
        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, vld1q_u32(K.as_ptr().add(0x14)));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        // Rounds 21-24
        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, vld1q_u32(K.as_ptr().add(0x18)));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        // Rounds 25-28
        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, vld1q_u32(K.as_ptr().add(0x1c)));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        // Rounds 29-32
        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, vld1q_u32(K.as_ptr().add(0x20)));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 33-36
        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, vld1q_u32(K.as_ptr().add(0x24)));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        // Rounds 37-40
        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, vld1q_u32(K.as_ptr().add(0x28)));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        // Rounds 41-44
        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, vld1q_u32(K.as_ptr().add(0x2c)));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        // Rounds 45-48
        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, vld1q_u32(K.as_ptr().add(0x30)));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 49-52
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, vld1q_u32(K.as_ptr().add(0x34)));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);

        // Rounds 53-56
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, vld1q_u32(K.as_ptr().add(0x38)));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);

        // Rounds 57-60
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, vld1q_u32(K.as_ptr().add(0x3c)));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);

        // Rounds 61-64
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);

        // Combine state
        state0 = vaddq_u32(state0, abcd_save);
        state1 = vaddq_u32(state1, efgh_save);

        block_offset += 64;
    }

    // Save state
    vst1q_u32(state.as_mut_ptr().add(0), state0);
    vst1q_u32(state.as_mut_ptr().add(4), state1);
}

/// computes `SHA256d` of two 64-byte inputs in parallel using ARM SHA2 intrinsics.
#[target_feature(enable = "sha2")]
pub(super) unsafe fn sha256d_64_2way(output: &mut [[u8; 32]; 2], input: &[[u8; 64]; 2]) {
    // Based on Bitcoin Core's sha256d64_arm_shani::Transform_2way
    // https://github.com/bitcoin/bitcoin/blob/master/src/crypto/sha256_arm_shani.cpp#L200-L895
    use core::arch::aarch64::vst1q_u8;

    // initial state
    #[rustfmt::skip]
    const INIT: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

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
    // FINS[4..7]: vsha256su0q_u32(msg2, msg3)
    // FINS[8..11]: msg2 + K[12..15]
    #[rustfmt::skip]
    const FINS: [u32; 12] = [
        0x5807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x80000000, 0x00000000, 0x00000000, 0x00000000,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf274,
    ];

    // Padding processed in the 3rd transform (byteswapped).
    const FINAL: [u32; 8] = [0x80000000, 0, 0, 0, 0, 0, 0, 0x100];

    let (mut state0_a, mut state0_b, mut state1_a, mut state1_b);
    let (abcd_save_a, abcd_save_b, efgh_save_a, efgh_save_b);

    #[rustfmt::skip]
    let (mut msg0_a, mut msg0_b, mut msg1_a, mut msg1_b, mut msg2_a, mut msg2_b, mut msg3_a, mut msg3_b);
    let (mut tmp0_a, mut tmp0_b, mut tmp2_a, mut tmp2_b, mut tmp);

    // Load state
    state0_a = vld1q_u32(INIT.as_ptr().add(0));
    state0_b = state0_a;
    state1_a = vld1q_u32(INIT.as_ptr().add(4));
    state1_b = state1_a;

    // Load message
    msg0_a = vld1q_u32(input[0].as_ptr().add(0).cast::<u32>());
    msg1_a = vld1q_u32(input[0].as_ptr().add(16).cast::<u32>());
    msg2_a = vld1q_u32(input[0].as_ptr().add(32).cast::<u32>());
    msg3_a = vld1q_u32(input[0].as_ptr().add(48).cast::<u32>());
    msg0_b = vld1q_u32(input[1].as_ptr().add(0).cast::<u32>());
    msg1_b = vld1q_u32(input[1].as_ptr().add(16).cast::<u32>());
    msg2_b = vld1q_u32(input[1].as_ptr().add(32).cast::<u32>());
    msg3_b = vld1q_u32(input[1].as_ptr().add(48).cast::<u32>());

    // Reverse for little endian
    msg0_a = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0_a)));
    msg1_a = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1_a)));
    msg2_a = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2_a)));
    msg3_a = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3_a)));
    msg0_b = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0_b)));
    msg1_b = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1_b)));
    msg2_b = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2_b)));
    msg3_b = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3_b)));

    // Transform 1: Rounds 1-4
    tmp = vld1q_u32(K.as_ptr().add(0));
    tmp0_a = vaddq_u32(msg0_a, tmp);
    tmp0_b = vaddq_u32(msg0_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg0_a = vsha256su0q_u32(msg0_a, msg1_a);
    msg0_b = vsha256su0q_u32(msg0_b, msg1_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg0_a = vsha256su1q_u32(msg0_a, msg2_a, msg3_a);
    msg0_b = vsha256su1q_u32(msg0_b, msg2_b, msg3_b);

    // Transform 1: Rounds 5-8
    tmp = vld1q_u32(K.as_ptr().add(4));
    tmp0_a = vaddq_u32(msg1_a, tmp);
    tmp0_b = vaddq_u32(msg1_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg1_a = vsha256su0q_u32(msg1_a, msg2_a);
    msg1_b = vsha256su0q_u32(msg1_b, msg2_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg1_a = vsha256su1q_u32(msg1_a, msg3_a, msg0_a);
    msg1_b = vsha256su1q_u32(msg1_b, msg3_b, msg0_b);

    // Transform 1: Rounds 9-12
    tmp = vld1q_u32(K.as_ptr().add(8));
    tmp0_a = vaddq_u32(msg2_a, tmp);
    tmp0_b = vaddq_u32(msg2_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg2_a = vsha256su0q_u32(msg2_a, msg3_a);
    msg2_b = vsha256su0q_u32(msg2_b, msg3_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg2_a = vsha256su1q_u32(msg2_a, msg0_a, msg1_a);
    msg2_b = vsha256su1q_u32(msg2_b, msg0_b, msg1_b);

    // Transform 1: Rounds 13-16
    tmp = vld1q_u32(K.as_ptr().add(12));
    tmp0_a = vaddq_u32(msg3_a, tmp);
    tmp0_b = vaddq_u32(msg3_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg3_a = vsha256su0q_u32(msg3_a, msg0_a);
    msg3_b = vsha256su0q_u32(msg3_b, msg0_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg3_a = vsha256su1q_u32(msg3_a, msg1_a, msg2_a);
    msg3_b = vsha256su1q_u32(msg3_b, msg1_b, msg2_b);

    // Transform 1: Rounds 17-20
    tmp = vld1q_u32(K.as_ptr().add(16));
    tmp0_a = vaddq_u32(msg0_a, tmp);
    tmp0_b = vaddq_u32(msg0_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg0_a = vsha256su0q_u32(msg0_a, msg1_a);
    msg0_b = vsha256su0q_u32(msg0_b, msg1_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg0_a = vsha256su1q_u32(msg0_a, msg2_a, msg3_a);
    msg0_b = vsha256su1q_u32(msg0_b, msg2_b, msg3_b);

    // Transform 1: Rounds 21-24
    tmp = vld1q_u32(K.as_ptr().add(20));
    tmp0_a = vaddq_u32(msg1_a, tmp);
    tmp0_b = vaddq_u32(msg1_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg1_a = vsha256su0q_u32(msg1_a, msg2_a);
    msg1_b = vsha256su0q_u32(msg1_b, msg2_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg1_a = vsha256su1q_u32(msg1_a, msg3_a, msg0_a);
    msg1_b = vsha256su1q_u32(msg1_b, msg3_b, msg0_b);

    // Transform 1: Rounds 25-28
    tmp = vld1q_u32(K.as_ptr().add(24));
    tmp0_a = vaddq_u32(msg2_a, tmp);
    tmp0_b = vaddq_u32(msg2_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg2_a = vsha256su0q_u32(msg2_a, msg3_a);
    msg2_b = vsha256su0q_u32(msg2_b, msg3_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg2_a = vsha256su1q_u32(msg2_a, msg0_a, msg1_a);
    msg2_b = vsha256su1q_u32(msg2_b, msg0_b, msg1_b);

    // Transform 1: Rounds 29-32
    tmp = vld1q_u32(K.as_ptr().add(28));
    tmp0_a = vaddq_u32(msg3_a, tmp);
    tmp0_b = vaddq_u32(msg3_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg3_a = vsha256su0q_u32(msg3_a, msg0_a);
    msg3_b = vsha256su0q_u32(msg3_b, msg0_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg3_a = vsha256su1q_u32(msg3_a, msg1_a, msg2_a);
    msg3_b = vsha256su1q_u32(msg3_b, msg1_b, msg2_b);

    // Transform 1: Rounds 33-36
    tmp = vld1q_u32(K.as_ptr().add(32));
    tmp0_a = vaddq_u32(msg0_a, tmp);
    tmp0_b = vaddq_u32(msg0_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg0_a = vsha256su0q_u32(msg0_a, msg1_a);
    msg0_b = vsha256su0q_u32(msg0_b, msg1_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg0_a = vsha256su1q_u32(msg0_a, msg2_a, msg3_a);
    msg0_b = vsha256su1q_u32(msg0_b, msg2_b, msg3_b);

    // Transform 1: Rounds 37-40
    tmp = vld1q_u32(K.as_ptr().add(36));
    tmp0_a = vaddq_u32(msg1_a, tmp);
    tmp0_b = vaddq_u32(msg1_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg1_a = vsha256su0q_u32(msg1_a, msg2_a);
    msg1_b = vsha256su0q_u32(msg1_b, msg2_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg1_a = vsha256su1q_u32(msg1_a, msg3_a, msg0_a);
    msg1_b = vsha256su1q_u32(msg1_b, msg3_b, msg0_b);

    // Transform 1: Rounds 41-44
    tmp = vld1q_u32(K.as_ptr().add(40));
    tmp0_a = vaddq_u32(msg2_a, tmp);
    tmp0_b = vaddq_u32(msg2_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg2_a = vsha256su0q_u32(msg2_a, msg3_a);
    msg2_b = vsha256su0q_u32(msg2_b, msg3_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg2_a = vsha256su1q_u32(msg2_a, msg0_a, msg1_a);
    msg2_b = vsha256su1q_u32(msg2_b, msg0_b, msg1_b);

    // Transform 1: Rounds 45-48
    tmp = vld1q_u32(K.as_ptr().add(44));
    tmp0_a = vaddq_u32(msg3_a, tmp);
    tmp0_b = vaddq_u32(msg3_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg3_a = vsha256su0q_u32(msg3_a, msg0_a);
    msg3_b = vsha256su0q_u32(msg3_b, msg0_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg3_a = vsha256su1q_u32(msg3_a, msg1_a, msg2_a);
    msg3_b = vsha256su1q_u32(msg3_b, msg1_b, msg2_b);

    // Transform 1: Rounds 49-52
    tmp = vld1q_u32(K.as_ptr().add(48));
    tmp0_a = vaddq_u32(msg0_a, tmp);
    tmp0_b = vaddq_u32(msg0_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);

    // Transform 1: Rounds 53-56
    tmp = vld1q_u32(K.as_ptr().add(52));
    tmp0_a = vaddq_u32(msg1_a, tmp);
    tmp0_b = vaddq_u32(msg1_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);

    // Transform 1: Rounds 57-60
    tmp = vld1q_u32(K.as_ptr().add(56));
    tmp0_a = vaddq_u32(msg2_a, tmp);
    tmp0_b = vaddq_u32(msg2_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);

    // Transform 1: Rounds 61-64
    tmp = vld1q_u32(K.as_ptr().add(60));
    tmp0_a = vaddq_u32(msg3_a, tmp);
    tmp0_b = vaddq_u32(msg3_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);

    // Transform 1: Update state
    tmp = vld1q_u32(&INIT[0]);
    state0_a = vaddq_u32(state0_a, tmp);
    state0_b = vaddq_u32(state0_b, tmp);
    tmp = vld1q_u32(&INIT[4]);
    state1_a = vaddq_u32(state1_a, tmp);
    state1_b = vaddq_u32(state1_b, tmp);

    // ------------------ Transform 2 -------------------

    // Transform 2: Save state
    abcd_save_a = state0_a;
    abcd_save_b = state0_b;
    efgh_save_a = state1_a;
    efgh_save_b = state1_b;

    // Transform 2: Rounds 1-4
    tmp = vld1q_u32(MIDS.as_ptr().add(0));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 5-8
    tmp = vld1q_u32(MIDS.as_ptr().add(4));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 9-12
    tmp = vld1q_u32(MIDS.as_ptr().add(8));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 13-16
    tmp = vld1q_u32(MIDS.as_ptr().add(12));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 17-20
    tmp = vld1q_u32(MIDS.as_ptr().add(16));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 21-24
    tmp = vld1q_u32(MIDS.as_ptr().add(20));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 25-28
    tmp = vld1q_u32(MIDS.as_ptr().add(24));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 29-32
    tmp = vld1q_u32(MIDS.as_ptr().add(28));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 33-36
    tmp = vld1q_u32(MIDS.as_ptr().add(32));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 37-40
    tmp = vld1q_u32(MIDS.as_ptr().add(36));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 41-44
    tmp = vld1q_u32(MIDS.as_ptr().add(40));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 45-48
    tmp = vld1q_u32(MIDS.as_ptr().add(44));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 49-52
    tmp = vld1q_u32(MIDS.as_ptr().add(48));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 53-56
    tmp = vld1q_u32(MIDS.as_ptr().add(52));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 57-60
    tmp = vld1q_u32(MIDS.as_ptr().add(56));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Rounds 61-64
    tmp = vld1q_u32(MIDS.as_ptr().add(60));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);

    // Transform 2: Update state
    state0_a = vaddq_u32(state0_a, abcd_save_a);
    state0_b = vaddq_u32(state0_b, abcd_save_b);
    state1_a = vaddq_u32(state1_a, efgh_save_a);
    state1_b = vaddq_u32(state1_b, efgh_save_b);

    // ------------------ Transform 3 -------------------

    msg0_a = state0_a;
    msg0_b = state0_b;
    msg1_a = state1_a;
    msg1_b = state1_b;
    msg2_a = vld1q_u32(FINAL.as_ptr().add(0));
    msg2_b = msg2_a;
    msg3_a = vld1q_u32(FINAL.as_ptr().add(4));
    msg3_b = msg3_a;

    // Transform 3: Load state
    state0_a = vld1q_u32(INIT.as_ptr());
    state0_b = state0_a;
    state1_a = vld1q_u32(INIT.as_ptr().add(4));
    state1_b = state1_a;

    // Transform 3: Rounds 1-4
    tmp = vld1q_u32(K.as_ptr().add(0));
    tmp0_a = vaddq_u32(msg0_a, tmp);
    tmp0_b = vaddq_u32(msg0_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg0_a = vsha256su0q_u32(msg0_a, msg1_a);
    msg0_b = vsha256su0q_u32(msg0_b, msg1_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg0_a = vsha256su1q_u32(msg0_a, msg2_a, msg3_a);
    msg0_b = vsha256su1q_u32(msg0_b, msg2_b, msg3_b);

    // Transform 3: Rounds 5-8
    tmp = vld1q_u32(K.as_ptr().add(4));
    tmp0_a = vaddq_u32(msg1_a, tmp);
    tmp0_b = vaddq_u32(msg1_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg1_a = vsha256su0q_u32(msg1_a, msg2_a);
    msg1_b = vsha256su0q_u32(msg1_b, msg2_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg1_a = vsha256su1q_u32(msg1_a, msg3_a, msg0_a);
    msg1_b = vsha256su1q_u32(msg1_b, msg3_b, msg0_b);

    // Transform 3: Rounds 9-12
    tmp = vld1q_u32(FINS.as_ptr().add(0));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg2_a = vld1q_u32(FINS.as_ptr().add(4));
    msg2_b = msg2_a;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);
    msg2_a = vsha256su1q_u32(msg2_a, msg0_a, msg1_a);
    msg2_b = vsha256su1q_u32(msg2_b, msg0_b, msg1_b);

    // Transform 3: Rounds 13-16
    tmp = vld1q_u32(FINS.as_ptr().add(8));
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg3_a = vsha256su0q_u32(msg3_a, msg0_a);
    msg3_b = vsha256su0q_u32(msg3_b, msg0_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp);
    msg3_a = vsha256su1q_u32(msg3_a, msg1_a, msg2_a);
    msg3_b = vsha256su1q_u32(msg3_b, msg1_b, msg2_b);

    // Transform 3: Rounds 17-20
    tmp = vld1q_u32(K.as_ptr().add(16));
    tmp0_a = vaddq_u32(msg0_a, tmp);
    tmp0_b = vaddq_u32(msg0_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg0_a = vsha256su0q_u32(msg0_a, msg1_a);
    msg0_b = vsha256su0q_u32(msg0_b, msg1_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg0_a = vsha256su1q_u32(msg0_a, msg2_a, msg3_a);
    msg0_b = vsha256su1q_u32(msg0_b, msg2_b, msg3_b);

    // Transform 3: Rounds 21-24
    tmp = vld1q_u32(K.as_ptr().add(20));
    tmp0_a = vaddq_u32(msg1_a, tmp);
    tmp0_b = vaddq_u32(msg1_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg1_a = vsha256su0q_u32(msg1_a, msg2_a);
    msg1_b = vsha256su0q_u32(msg1_b, msg2_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg1_a = vsha256su1q_u32(msg1_a, msg3_a, msg0_a);
    msg1_b = vsha256su1q_u32(msg1_b, msg3_b, msg0_b);

    // Transform 3: Rounds 25-28
    tmp = vld1q_u32(K.as_ptr().add(24));
    tmp0_a = vaddq_u32(msg2_a, tmp);
    tmp0_b = vaddq_u32(msg2_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg2_a = vsha256su0q_u32(msg2_a, msg3_a);
    msg2_b = vsha256su0q_u32(msg2_b, msg3_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg2_a = vsha256su1q_u32(msg2_a, msg0_a, msg1_a);
    msg2_b = vsha256su1q_u32(msg2_b, msg0_b, msg1_b);

    // Transform 3: Rounds 29-32
    tmp = vld1q_u32(K.as_ptr().add(28));
    tmp0_a = vaddq_u32(msg3_a, tmp);
    tmp0_b = vaddq_u32(msg3_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg3_a = vsha256su0q_u32(msg3_a, msg0_a);
    msg3_b = vsha256su0q_u32(msg3_b, msg0_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg3_a = vsha256su1q_u32(msg3_a, msg1_a, msg2_a);
    msg3_b = vsha256su1q_u32(msg3_b, msg1_b, msg2_b);

    // Transform 3: Rounds 33-36
    tmp = vld1q_u32(K.as_ptr().add(32));
    tmp0_a = vaddq_u32(msg0_a, tmp);
    tmp0_b = vaddq_u32(msg0_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg0_a = vsha256su0q_u32(msg0_a, msg1_a);
    msg0_b = vsha256su0q_u32(msg0_b, msg1_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg0_a = vsha256su1q_u32(msg0_a, msg2_a, msg3_a);
    msg0_b = vsha256su1q_u32(msg0_b, msg2_b, msg3_b);

    // Transform 3: Rounds 37-40
    tmp = vld1q_u32(K.as_ptr().add(36));
    tmp0_a = vaddq_u32(msg1_a, tmp);
    tmp0_b = vaddq_u32(msg1_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg1_a = vsha256su0q_u32(msg1_a, msg2_a);
    msg1_b = vsha256su0q_u32(msg1_b, msg2_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg1_a = vsha256su1q_u32(msg1_a, msg3_a, msg0_a);
    msg1_b = vsha256su1q_u32(msg1_b, msg3_b, msg0_b);

    // Transform 3: Rounds 41-44
    tmp = vld1q_u32(K.as_ptr().add(40));
    tmp0_a = vaddq_u32(msg2_a, tmp);
    tmp0_b = vaddq_u32(msg2_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg2_a = vsha256su0q_u32(msg2_a, msg3_a);
    msg2_b = vsha256su0q_u32(msg2_b, msg3_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg2_a = vsha256su1q_u32(msg2_a, msg0_a, msg1_a);
    msg2_b = vsha256su1q_u32(msg2_b, msg0_b, msg1_b);

    // Transform 3: Rounds 45-48
    tmp = vld1q_u32(K.as_ptr().add(44));
    tmp0_a = vaddq_u32(msg3_a, tmp);
    tmp0_b = vaddq_u32(msg3_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    msg3_a = vsha256su0q_u32(msg3_a, msg0_a);
    msg3_b = vsha256su0q_u32(msg3_b, msg0_b);
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);
    msg3_a = vsha256su1q_u32(msg3_a, msg1_a, msg2_a);
    msg3_b = vsha256su1q_u32(msg3_b, msg1_b, msg2_b);

    // Transform 3: Rounds 49-52
    tmp = vld1q_u32(K.as_ptr().add(48));
    tmp0_a = vaddq_u32(msg0_a, tmp);
    tmp0_b = vaddq_u32(msg0_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);

    // Transform 3: Rounds 53-56
    tmp = vld1q_u32(K.as_ptr().add(52));
    tmp0_a = vaddq_u32(msg1_a, tmp);
    tmp0_b = vaddq_u32(msg1_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);

    // Transform 3: Rounds 57-60
    tmp = vld1q_u32(K.as_ptr().add(56));
    tmp0_a = vaddq_u32(msg2_a, tmp);
    tmp0_b = vaddq_u32(msg2_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);

    // Transform 3: Rounds 61-64
    tmp = vld1q_u32(K.as_ptr().add(60));
    tmp0_a = vaddq_u32(msg3_a, tmp);
    tmp0_b = vaddq_u32(msg3_b, tmp);
    tmp2_a = state0_a;
    tmp2_b = state0_b;
    state0_a = vsha256hq_u32(state0_a, state1_a, tmp0_a);
    state0_b = vsha256hq_u32(state0_b, state1_b, tmp0_b);
    state1_a = vsha256h2q_u32(state1_a, tmp2_a, tmp0_a);
    state1_b = vsha256h2q_u32(state1_b, tmp2_b, tmp0_b);

    // Transform 3: Update state
    tmp = vld1q_u32(INIT.as_ptr().add(0));
    state0_a = vaddq_u32(state0_a, tmp);
    state0_b = vaddq_u32(state0_b, tmp);
    tmp = vld1q_u32(INIT.as_ptr().add(4));
    state1_a = vaddq_u32(state1_a, tmp);
    state1_b = vaddq_u32(state1_b, tmp);

    // Store result
    vst1q_u8(output[0].as_mut_ptr().add(0), vrev32q_u8(vreinterpretq_u8_u32(state0_a)));
    vst1q_u8(output[0].as_mut_ptr().add(16), vrev32q_u8(vreinterpretq_u8_u32(state1_a)));
    vst1q_u8(output[1].as_mut_ptr().add(0), vrev32q_u8(vreinterpretq_u8_u32(state0_b)));
    vst1q_u8(output[1].as_mut_ptr().add(16), vrev32q_u8(vreinterpretq_u8_u32(state1_b)));
}
