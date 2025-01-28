// SPDX-License-Identifier: CC0-1.0

//! SHA256d implementation (double SHA256).

use crate::sha256;

crate::internal_macros::general_hash_type! {
    256,
    true,
    "Output of the SHA256d hash function."
}

/// Engine to compute SHA256d hash function.
#[derive(Clone)]
pub struct HashEngine(sha256::HashEngine);

impl HashEngine {
    /// Constructs a new SHA256d hash engine.
    pub const fn new() -> Self { Self(sha256::HashEngine::new()) }
}

impl Default for HashEngine {
    fn default() -> Self { Self::new() }
}

impl crate::HashEngine for HashEngine {
    const BLOCK_SIZE: usize = 64; // Same as sha256::HashEngine::BLOCK_SIZE;
    fn input(&mut self, data: &[u8]) { self.0.input(data) }
    fn n_bytes_hashed(&self) -> u64 { self.0.n_bytes_hashed() }
}

fn from_engine(e: HashEngine) -> Hash {
    let sha2 = sha256::Hash::from_engine(e.0);
    let sha2d = sha256::Hash::hash(sha2.as_byte_array());

    let mut ret = [0; 32];
    ret.copy_from_slice(sha2d.as_byte_array());
    Hash(ret)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)] // whether this is used depends on features
    use crate::sha256d;

    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        use alloc::string::ToString;

        use crate::{sha256, HashEngine};

        #[derive(Clone)]
        struct Test {
            input: &'static str,
            output: [u8; 32],
            output_str: &'static str,
        }

        #[rustfmt::skip]
        let tests = [
            // Test vector copied out of rust-bitcoin
            Test {
                input: "",
                output: [
                    0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
                    0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
                    0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
                    0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
                ],
                output_str: "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
            },
        ];

        for test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = sha256d::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<sha256d::Hash>().expect("parse hex"));
            assert_eq!(hash.as_byte_array(), &test.output);
            assert_eq!(hash.to_string(), test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = sha256d::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            let manual_hash = sha256d::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);

            // Hash by computing a sha256 then `hash_again`ing it
            let sha2_hash = sha256::Hash::hash(test.input.as_bytes());
            let sha2d_hash = sha2_hash.hash_again();
            assert_eq!(hash, sha2d_hash);

            assert_eq!(hash.to_byte_array(), test.output);
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn fmt_roundtrips() {
        use alloc::format;

        let hash = sha256d::Hash::hash(b"some arbitrary bytes");
        let hex = format!("{}", hash);
        let rinsed = hex.parse::<sha256d::Hash>().expect("failed to parse hex");
        assert_eq!(rinsed, hash)
    }

    #[test]
    #[cfg(feature = "serde")]
    fn sha256_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        #[rustfmt::skip]
        static HASH_BYTES: [u8; 32] = [
            0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
            0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97,
            0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2,
            0xb7, 0x65, 0x44, 0x8c, 0x86, 0x35, 0xfb, 0x6c,
        ];

        let hash = sha256d::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
        assert_tokens(
            &hash.readable(),
            &[Token::Str("6cfb35868c4465b7c289d7d5641563aa973db6a929655282a7bf95c8257f53ef")],
        );
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{sha256d, Hash, HashEngine};

    #[bench]
    pub fn sha256d_10(bh: &mut Bencher) {
        let mut engine = sha256d::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256d_1k(bh: &mut Bencher) {
        let mut engine = sha256d::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256d_64k(bh: &mut Bencher) {
        let mut engine = sha256d::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
