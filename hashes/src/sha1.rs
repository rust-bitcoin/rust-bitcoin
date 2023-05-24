// SPDX-License-Identifier: CC0-1.0

//! SHA1 implementation.
//!

use core::convert::TryInto;
use core::ops::Index;
use core::slice::SliceIndex;
use core::{cmp, str};

use crate::{FromSliceError, HashEngine as _};

crate::internal_macros::hash_type! {
    160,
    false,
    "Output of the SHA1 hash function.",
    "crate::util::json_hex_string::len_20"
}

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

    Hash(e.midstate())
}

const BLOCK_SIZE: usize = 64;

/// Engine to compute SHA1 hash function.
#[derive(Clone)]
pub struct HashEngine {
    buffer: [u8; BLOCK_SIZE],
    h: [u32; 5],
    length: usize,
}

impl Default for HashEngine {
    fn default() -> Self {
        HashEngine {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            length: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }
}

impl crate::HashEngine for HashEngine {
    type MidState = [u8; 20];

    #[cfg(not(hashes_fuzz))]
    fn midstate(&self) -> [u8; 20] {
        let mut ret = [0; 20];
        for (val, ret_bytes) in self.h.iter().zip(ret.chunks_exact_mut(4)) {
            ret_bytes.copy_from_slice(&val.to_be_bytes())
        }
        ret
    }

    #[cfg(hashes_fuzz)]
    fn midstate(&self) -> [u8; 20] {
        let mut ret = [0; 20];
        ret.copy_from_slice(&self.buffer[..20]);
        ret
    }

    const BLOCK_SIZE: usize = 64;

    fn n_bytes_hashed(&self) -> usize { self.length }

    engine_input_impl!();
}

impl HashEngine {
    // Basic unoptimized algorithm from Wikipedia
    fn process_block(&mut self) {
        debug_assert_eq!(self.buffer.len(), BLOCK_SIZE);

        let mut w = [0u32; 80];
        for (w_val, buff_bytes) in w.iter_mut().zip(self.buffer.chunks_exact(4)) {
            *w_val = u32::from_be_bytes(buff_bytes.try_into().expect("4 bytes slice"))
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0...19 => ((b & c) | (!b & d), 0x5a827999),
                20...39 => (b ^ c ^ d, 0x6ed9eba1),
                40...59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                60...79 => (b ^ c ^ d, 0xca62c1d6),
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

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        use crate::{sha1, Hash, HashEngine};

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
                    0xda, 0x39, 0xa3, 0xee,
                    0x5e, 0x6b, 0x4b, 0x0d,
                    0x32, 0x55, 0xbf, 0xef,
                    0x95, 0x60, 0x18, 0x90,
                    0xaf, 0xd8, 0x07, 0x09,
                ],
                output_str: "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output: vec![
                    0x2f, 0xd4, 0xe1, 0xc6,
                    0x7a, 0x2d, 0x28, 0xfc,
                    0xed, 0x84, 0x9e, 0xe1,
                    0xbb, 0x76, 0xe7, 0x39,
                    0x1b, 0x93, 0xeb, 0x12,
                ],
                output_str: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            },
            Test {
                input: "The quick brown fox jumps over the lazy cog",
                output: vec![
                    0xde, 0x9f, 0x2c, 0x7f,
                    0xd2, 0x5e, 0x1b, 0x3a,
                    0xfa, 0xd3, 0xe8, 0x5a,
                    0x0b, 0xd1, 0x7d, 0x9b,
                    0x10, 0x0d, 0xb4, 0xb3,
                ],
                output_str: "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
            },
        ];

        for test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = sha1::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<sha1::Hash>().expect("parse hex"));
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = sha1::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            let manual_hash = sha1::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);
            assert_eq!(hash.as_byte_array(), test.output.as_slice());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn sha1_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        use crate::{sha1, Hash};

        #[rustfmt::skip]
        static HASH_BYTES: [u8; 20] = [
            0x13, 0x20, 0x72, 0xdf,
            0x69, 0x09, 0x33, 0x83,
            0x5e, 0xb8, 0xb6, 0xad,
            0x0b, 0x77, 0xe7, 0xb6,
            0xf1, 0x4a, 0xca, 0xd7,
        ];

        let hash = sha1::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
        assert_tokens(&hash.readable(), &[Token::Str("132072df690933835eb8b6ad0b77e7b6f14acad7")]);
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{sha1, Hash, HashEngine};

    #[bench]
    pub fn sha1_10(bh: &mut Bencher) {
        let mut engine = sha1::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha1_1k(bh: &mut Bencher) {
        let mut engine = sha1::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha1_64k(bh: &mut Bencher) {
        let mut engine = sha1::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
