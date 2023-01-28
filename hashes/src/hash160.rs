// Bitcoin Hashes Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

// This module is largely copied from the rust-crypto ripemd.rs file;
// while rust-crypto is licensed under Apache, that file specifically
// was written entirely by Andrew Poelstra, who is re-licensing its
// contents here as CC0.

//! HASH160 (SHA256 then RIPEMD160) implementation.
//!

use core::str;
use core::ops::Index;
use core::slice::SliceIndex;

use crate::{Error, ripemd160, sha256};

crate::internal_macros::hash_type! {
    160,
    false,
    "Output of the Bitcoin HASH160 hash function. (RIPEMD160(SHA256))",
    "crate::util::json_hex_string::len_20"
}

type HashEngine = sha256::HashEngine;

fn from_engine(e: HashEngine) -> Hash {
    use crate::Hash as _;

    let sha2 = sha256::Hash::from_engine(e);
    let rmd = ripemd160::Hash::hash(&sha2[..]);

    let mut ret = [0; 20];
    ret.copy_from_slice(&rmd[..]);
    Hash(ret)
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        use crate::{hash160, Hash, HashEngine};

        #[derive(Clone)]
        #[cfg(feature = "alloc")]
        struct Test {
            input: Vec<u8>,
            output: Vec<u8>,
            output_str: &'static str,
        }

        let tests = vec![
            // Uncompressed pubkey obtained from Bitcoin key; data from validateaddress
            Test {
                input: vec![
                    0x04, 0xa1, 0x49, 0xd7, 0x6c, 0x5d, 0xe2, 0x7a, 0x2d,
                    0xdb, 0xfa, 0xa1, 0x24, 0x6c, 0x4a, 0xdc, 0xd2, 0xb6,
                    0xf7, 0xaa, 0x29, 0x54, 0xc2, 0xe2, 0x53, 0x03, 0xf5,
                    0x51, 0x54, 0xca, 0xad, 0x91, 0x52, 0xe4, 0xf7, 0xe4,
                    0xb8, 0x5d, 0xf1, 0x69, 0xc1, 0x8a, 0x3c, 0x69, 0x7f,
                    0xbb, 0x2d, 0xc4, 0xec, 0xef, 0x94, 0xac, 0x55, 0xfe,
                    0x81, 0x64, 0xcc, 0xf9, 0x82, 0xa1, 0x38, 0x69, 0x1a,
                    0x55, 0x19,
                ],
                output: vec![
                    0xda, 0x0b, 0x34, 0x52, 0xb0, 0x6f, 0xe3, 0x41,
                    0x62, 0x6a, 0xd0, 0x94, 0x9c, 0x18, 0x3f, 0xbd,
                    0xa5, 0x67, 0x68, 0x26,
                ],
                output_str: "da0b3452b06fe341626ad0949c183fbda5676826",
            },
        ];

        for test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = hash160::Hash::hash(&test.input[..]);
            assert_eq!(hash, test.output_str.parse::<hash160::Hash>().expect("parse hex"));
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = hash160::Hash::engine();
            for ch in test.input {
                engine.input(&[ch]);
            }
            let manual_hash = Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);
            assert_eq!(hash.to_byte_array()[..].as_ref(), test.output.as_slice());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn ripemd_serde() {
        use serde_test::{Configure, Token, assert_tokens};
        use crate::{hash160, Hash};

        static HASH_BYTES: [u8; 20] = [
            0x13, 0x20, 0x72, 0xdf,
            0x69, 0x09, 0x33, 0x83,
            0x5e, 0xb8, 0xb6, 0xad,
            0x0b, 0x77, 0xe7, 0xb6,
            0xf1, 0x4a, 0xca, 0xd7,
        ];

        let hash = hash160::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
        assert_tokens(&hash.readable(), &[Token::Str("132072df690933835eb8b6ad0b77e7b6f14acad7")]);
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{Hash, HashEngine, hash160};

    #[bench]
    pub fn hash160_10(bh: &mut Bencher) {
        let mut engine = hash160::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter( || {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn hash160_1k(bh: &mut Bencher) {
        let mut engine = hash160::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter( || {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn hash160_64k(bh: &mut Bencher) {
        let mut engine = hash160::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter( || {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
