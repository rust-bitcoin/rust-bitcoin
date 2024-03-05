// SPDX-License-Identifier: CC0-1.0

//! SHA384 implementation.

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use crate::{sha512, FromSliceError};

crate::internal_macros::hash_type! {
    384,
    false,
    "Output of the SHA384 hash function."
}

fn from_engine(e: HashEngine) -> Hash {
    let mut ret = [0; 48];
    ret.copy_from_slice(&sha512::from_engine(e.0)[..48]);
    Hash(ret)
}

/// Engine to compute SHA384 hash function.
#[derive(Clone)]
pub struct HashEngine(sha512::HashEngine);

impl Default for HashEngine {
    #[rustfmt::skip]
    fn default() -> Self {
        HashEngine(sha512::HashEngine::sha384())
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
        use crate::{sha384, Hash, HashEngine};

        #[derive(Clone)]
        struct Test {
            input: &'static str,
            output: Vec<u8>,
            output_str: &'static str,
        }

        #[rustfmt::skip]
        let tests = vec![
            // Examples from go sha384 tests.
            Test {
                input: "",
                output: vec![
                    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
                    0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
                    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
                    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
                    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
                    0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
                ],
                output_str: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            },
            Test {
                input: "abcdef",
                output: vec![
                    0xc6, 0xa4, 0xc6, 0x5b, 0x22, 0x7e, 0x73, 0x87,
                    0xb9, 0xc3, 0xe8, 0x39, 0xd4, 0x48, 0x69, 0xc4,
                    0xcf, 0xca, 0x3e, 0xf5, 0x83, 0xde, 0xa6, 0x41,
                    0x17, 0x85, 0x9b, 0x80, 0x8c, 0x1e, 0x3d, 0x8a,
                    0xe6, 0x89, 0xe1, 0xe3, 0x14, 0xee, 0xef, 0x52,
                    0xa6, 0xff, 0xe2, 0x26, 0x81, 0xaa, 0x11, 0xf5,
                ],
                output_str: "c6a4c65b227e7387b9c3e839d44869c4cfca3ef583dea64117859b808c1e3d8ae689e1e314eeef52a6ffe22681aa11f5",
            },
            Test {
                input: "Discard medicine more than two years old.",
                output: vec![
                    0x86, 0xf5, 0x8e, 0xc2, 0xd7, 0x4d, 0x1b, 0x7f,
                    0x8e, 0xb0, 0xc2, 0xff, 0x09, 0x67, 0x31, 0x66,
                    0x99, 0x63, 0x9e, 0x8d, 0x4e, 0xb1, 0x29, 0xde,
                    0x54, 0xbd, 0xf3, 0x4c, 0x96, 0xcd, 0xba, 0xbe,
                    0x20, 0x0d, 0x05, 0x21, 0x49, 0xf2, 0xdd, 0x78,
                    0x7f, 0x43, 0x57, 0x1b, 0xa7, 0x46, 0x70, 0xd4,
                ],
                output_str: "86f58ec2d74d1b7f8eb0c2ff0967316699639e8d4eb129de54bdf34c96cdbabe200d052149f2dd787f43571ba74670d4",
            },
            Test {
                input: "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
                output: vec![
                    0x72, 0x2d, 0x10, 0xc5, 0xde, 0x37, 0x1e, 0xc0,
                    0xc8, 0xc4, 0xb5, 0x24, 0x7a, 0xc8, 0xa5, 0xf1,
                    0xd2, 0x40, 0xd6, 0x8c, 0x73, 0xf8, 0xda, 0x13,
                    0xd8, 0xb2, 0x5f, 0x01, 0x66, 0xd6, 0xf3, 0x09,
                    0xbf, 0x95, 0x61, 0x97, 0x9a, 0x11, 0x1a, 0x00,
                    0x49, 0x40, 0x57, 0x71, 0xd2, 0x01, 0x94, 0x1a,
                ],
                output_str: "722d10c5de371ec0c8c4b5247ac8a5f1d240d68c73f8da13d8b25f0166d6f309bf9561979a111a0049405771d201941a",
            },
            Test {
                input: "The major problem is with sendmail.  -Mark Horton",
                output: vec![
                    0x5f, 0xf8, 0xe0, 0x75, 0xe4, 0x65, 0x64, 0x6e,
                    0x7b, 0x73, 0xef, 0x36, 0xd8, 0x12, 0xc6, 0xe9,
                    0xf7, 0xd6, 0x0f, 0xa6, 0xea, 0x0e, 0x53, 0x3e,
                    0x55, 0x69, 0xb4, 0xf7, 0x3c, 0xde, 0x53, 0xcd,
                    0xd2, 0xcc, 0x78, 0x7f, 0x33, 0x54, 0x0a, 0xf5,
                    0x7c, 0xca, 0x3f, 0xe4, 0x67, 0xd3, 0x2f, 0xe0,
                ],
                output_str: "5ff8e075e465646e7b73ef36d812c6e9f7d60fa6ea0e533e5569b4f73cde53cdd2cc787f33540af57cca3fe467d32fe0",
            },
        ];

        for test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = sha384::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<sha384::Hash>().expect("parse hex"));
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = sha384::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.0.input(&[*ch]);
            }
            let manual_hash = sha384::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);
            assert_eq!(hash.to_byte_array()[..].as_ref(), test.output.as_slice());
        }
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{sha384, Hash, HashEngine};

    #[bench]
    pub fn sha384_10(bh: &mut Bencher) {
        let mut engine = sha384::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha384_1k(bh: &mut Bencher) {
        let mut engine = sha384::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha384_64k(bh: &mut Bencher) {
        let mut engine = sha384::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
