// SPDX-License-Identifier: CC0-1.0

use internals::slice::SliceExt;

use super::{HashEngine, BLOCK_SIZE};

impl HashEngine {
    // Basic unoptimized algorithm from Wikipedia
    pub(super) fn process_block(state: &mut[u32; 5], block: &[u8; BLOCK_SIZE]) {
        debug_assert_eq!(block.len(), BLOCK_SIZE);

        let mut w = [0u32; 80];
        for (w_val, buff_bytes) in w.iter_mut().zip(block.bitcoin_as_chunks().0) {
            *w_val = u32::from_be_bytes(*buff_bytes)
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                60..=79 => (b ^ c ^ d, 0xca62c1d6),
                _ => unreachable!(),
            };

            let new_a =
                a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = new_a;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
}
