// SPDX-License-Identifier: CC0-1.0

//! SHA256d implementation (double SHA256).

use crate::{sha256, FromSliceError, HashEngine};

/// Engine to compute double SHA-256 hash function.
#[derive(Clone)]
pub struct Engine(sha256::Engine);

impl Default for Engine {
    fn default() -> Self {
        let inner = sha256::Engine::default();
        Self(inner)
    }
}

impl HashEngine for Engine {
    type Digest = [u8; 32];
    type Midstate = sha256::Midstate;
    const BLOCK_SIZE: usize = sha256::BLOCK_SIZE;

    #[inline]
    fn n_bytes_hashed(&self) -> usize { self.0.n_bytes_hashed() }

    #[inline]
    fn input(&mut self, data: &[u8]) { self.0.input(data) }

    #[inline]
    fn finalize(self) -> Self::Digest {
        let sha2 = sha256::Hash::from_engine(self.0);
        let sha2d = sha256::Hash::hash(&sha2[..]);

        let mut ret = [0; 32];
        ret.copy_from_slice(&sha2d[..]);
        ret
    }

    #[inline]
    fn midstate(&self) -> Self::Midstate { self.0.midstate() }

    #[inline]
    fn from_midstate(midstate: Self::Midstate, length: usize) -> Engine {
        let inner = sha256::Engine::from_midstate(midstate, length);
        Self(inner)
    }
}

/// Output of the SHA256d hash function.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Flag indicating whether user-visible serializations of this hash
    /// should be backward. For some reason Satoshi decided this should be
    /// true for `Sha256dHash`, so here we are.
    pub const DISPLAY_BACKWARD: bool = true;

    /// Length of the hash, in bytes.
    pub const LEN: usize = 32;

    /// Iterate the sha256 algorithm to turn a sha256 hash into a sha256d hash
    pub fn from_hash(sha256: sha256::Hash) -> Self {
        Self::from_byte_array(sha256::Hash::hash(sha256.as_ref()).to_byte_array())
    }

    /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
    ///
    /// # Returns
    ///
    /// The digest created by hashing `bytes` with engine's hashing algorithm.
    #[allow(clippy::self_named_constructors)] // `hash` is a verb but `Hash` is a noun.
    pub fn hash(bytes: &[u8]) -> Self {
        let mut engine = Self::engine();
        engine.input(bytes);
        Self::from_engine(engine)
    }

    /// Constructs a new engine.
    pub fn engine() -> Engine { Engine::new() }

    /// Produces a hash from the current state of a given engine.
    pub fn from_engine(engine: Engine) -> Hash {
        let digest = engine.finalize();
        Self(digest)
    }

    /// Copies a byte slice into a hash object.
    pub fn from_slice(sl: &[u8]) -> Result<Hash, FromSliceError> {
        if sl.len() != 32 {
            Err(FromSliceError::new(sl.len(), Self::LEN))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Self(ret))
        }
    }

    /// Constructs a hash from the underlying byte array.
    pub fn from_byte_array(bytes: [u8; 32]) -> Self { Self(bytes) }

    /// Returns the underlying byte array.
    pub fn to_byte_array(self) -> [u8; 32] { self.0 }

    /// Returns a reference to the underlying byte array.
    pub fn as_byte_array(&self) -> &[u8; 32] { &self.0 }

    /// Returns an all zero hash.
    ///
    /// An all zeros hash is a made up construct because there is not a known input that can create
    /// it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis block's
    /// previous blockhash and the coinbase transaction's outpoint txid.
    pub fn all_zeros() -> Self { Self([0x00; 32]) }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for Hash {
    fn schema_name() -> String { "Hash".to_owned() }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema: schemars::schema::SchemaObject = <String>::json_schema(gen).into();
        schema.string = Some(Box::new(schemars::schema::StringValidation {
            max_length: Some(32 * 2),
            min_length: Some(32 * 2),
            pattern: Some("[0-9a-fA-F]+".to_owned()),
        }));
        schema.into()
    }
}

// Double SHA-256 is displayed backwards.
crate::impl_bytelike_traits!(Hash, 32, true);

#[cfg(test)]
mod tests {
    use crate::sha256d;

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn test() {
        use super::*;
        use crate::sha256;

        #[derive(Clone)]
        struct Test {
            input: &'static str,
            output: Vec<u8>,
            output_str: &'static str,
        }

        #[rustfmt::skip]
        let tests = vec![
            // Test vector copied out of rust-bitcoin
            Test {
                input: "",
                output: vec![
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
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = sha256d::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            let manual_hash = sha256d::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);

            // Hash by computing a sha256 then `hash_again`ing it
            let sha2_hash = sha256::Hash::hash(test.input.as_bytes());
            let sha2d_hash = sha256d::Hash::from_byte_array(
                sha256::Hash::hash(sha2_hash.as_byte_array()).to_byte_array(),
            );
            assert_eq!(hash, sha2d_hash);

            assert_eq!(hash.to_byte_array()[..].as_ref(), test.output.as_slice());
        }
    }

    #[test]
    fn fmt_roundtrips() {
        let hash = sha256d::Hash::hash(b"some arbitrary bytes");
        let hex = format!("{}", hash);
        let rinsed = hex.parse::<sha256d::Hash>().expect("failed to parse hex");
        assert_eq!(rinsed, hash)
    }

    #[cfg(feature = "serde")]
    #[test]
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

    use crate::{sha256d, HashEngine};

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
