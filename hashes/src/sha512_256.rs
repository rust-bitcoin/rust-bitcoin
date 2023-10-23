// SPDX-License-Identifier: CC0-1.0

//! SHA512_256 implementation.
//!
//! SHA512/256 is a hash function that uses the sha512 alogrithm but it truncates
//! the output to 256 bits. It has different initial constants than sha512 so it
//! produces an entirely different hash compared to sha512. More information at
//! <https://eprint.iacr.org/2010/548.pdf>.

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use crate::{sha512, FromSliceError};

crate::internal_macros::hash_type! {
    256,
    false,
    "Output of the SHA512/256 hash function.\n\nSHA512/256 is a hash function that uses the sha512 alogrithm but it truncates the output to 256 bits. It has different initial constants than sha512 so it produces an entirely different hash compared to sha512. More information at <https://eprint.iacr.org/2010/548.pdf>. ",
    "crate::util::json_hex_string::len_32"
}

fn from_engine(e: HashEngine) -> Hash {
    let mut ret = [0; 32];
    ret.copy_from_slice(&sha512::from_engine(e.0)[..32]);
    Hash(ret)
}

/// Engine to compute SHA512/256 hash function.
///
/// SHA512/256 is a hash function that uses the sha512 alogrithm but it truncates
/// the output to 256 bits. It has different initial constants than sha512 so it
/// produces an entirely different hash compared to sha512. More information at
/// <https://eprint.iacr.org/2010/548.pdf>.
#[derive(Clone)]
pub struct HashEngine(sha512::HashEngine);

impl Default for HashEngine {
    #[rustfmt::skip]
    fn default() -> Self {
        HashEngine(sha512::HashEngine::sha512_256())
    }
}

impl crate::HashEngine for HashEngine {
    type MidState = [u8; 64];

    fn midstate(&self) -> [u8; 64] { self.0.midstate() }

    const BLOCK_SIZE: usize = sha512::BLOCK_SIZE;

    fn n_bytes_hashed(&self) -> usize { self.0.n_bytes_hashed() }

    fn input(&mut self, inp: &[u8]) { self.0.input(inp); }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        use crate::{sha512_256, Hash, HashEngine};

        #[derive(Clone)]
        struct Test {
            input: &'static str,
            output: Vec<u8>,
            output_str: &'static str,
        }

        #[rustfmt::skip]
        let tests = vec![
            // Examples from go sha512/256 tests.
            Test {
                input: "",
                output: vec![
                    0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28,
                    0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51, 0x14, 0x06,
                    0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74,
                    0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a,
                ],
                output_str: "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
            },
            Test {
                input: "abcdef",
                output: vec![
                    0xe4, 0xfd, 0xcb, 0x11, 0xd1, 0xac, 0x14, 0xe6,
                    0x98, 0x74, 0x3a, 0xcd, 0x88, 0x05, 0x17, 0x4c,
                    0xea, 0x5d, 0xdc, 0x0d, 0x31, 0x2e, 0x3e, 0x47,
                    0xf6, 0x37, 0x20, 0x32, 0x57, 0x1b, 0xad, 0x84,
                ],
                output_str: "e4fdcb11d1ac14e698743acd8805174cea5ddc0d312e3e47f6372032571bad84",
            },
            Test {
                input: "Discard medicine more than two years old.",
                output: vec![
                    0x69, 0x0c, 0x8a, 0xd3, 0x91, 0x6c, 0xef, 0xd3,
                    0xad, 0x29, 0x22, 0x6d, 0x98, 0x75, 0x96, 0x5e,
                    0x3e, 0xe9, 0xec, 0x0d, 0x44, 0x82, 0xea, 0xcc,
                    0x24, 0x8f, 0x2f, 0xf4, 0xaa, 0x0d, 0x8e, 0x5b,
                ],
                output_str: "690c8ad3916cefd3ad29226d9875965e3ee9ec0d4482eacc248f2ff4aa0d8e5b",
            },
            Test {
                input: "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
                output: vec![
                    0xb5, 0xba, 0xf7, 0x47, 0xc3, 0x07, 0xf9, 0x88,
                    0x49, 0xec, 0x88, 0x1c, 0xf0, 0xd4, 0x86, 0x05,
                    0xae, 0x4e, 0xdd, 0x38, 0x63, 0x72, 0xae, 0xa9,
                    0xb2, 0x6e, 0x71, 0xdb, 0x51, 0x7e, 0x65, 0x0b,
                ],
                output_str: "b5baf747c307f98849ec881cf0d48605ae4edd386372aea9b26e71db517e650b",
            },
            Test {
                input: "The major problem is with sendmail.  -Mark Horton",
                output: vec![
                    0x53, 0xed, 0x5f, 0x9b, 0x5c, 0x0b, 0x67, 0x4a,
                    0xc0, 0xf3, 0x42, 0x5d, 0x9f, 0x9a, 0x5d, 0x46,
                    0x26, 0x55, 0xb0, 0x7c, 0xc9, 0x0f, 0x5d, 0x0f,
                    0x69, 0x2e, 0xec, 0x09, 0x38, 0x84, 0xa6, 0x07,
                ],
                output_str: "53ed5f9b5c0b674ac0f3425d9f9a5d462655b07cc90f5d0f692eec093884a607",
            },
        ];

        for test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = sha512_256::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<sha512_256::Hash>().expect("parse hex"));
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = sha512_256::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.0.input(&[*ch]);
            }
            let manual_hash = sha512_256::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);
            assert_eq!(hash.to_byte_array()[..].as_ref(), test.output.as_slice());
        }
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{sha512_256, Hash, HashEngine};

    #[bench]
    pub fn sha512_256_10(bh: &mut Bencher) {
        let mut engine = sha512_256::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_256_1k(bh: &mut Bencher) {
        let mut engine = sha512_256::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_256_64k(bh: &mut Bencher) {
        let mut engine = sha512_256::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
