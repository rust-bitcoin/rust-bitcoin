// SPDX-License-Identifier: CC0-1.0

//! Non-public macros

/// Creates a type called `Hash` and implements the standard interface for it.
///
/// The created type has a single private field, an array that is the digest bytes. The digest bytes
/// can be accessed using the expected API for a byte array and includes all standard derives.
///
/// Arguments:
///
/// * `$bytes` - the number of bytes of the hash type
/// * `$doc` - doc string to put on the type
macro_rules! hash_type {
    ($bytes:expr, $doc:literal) => {
        #[cfg(all(feature = "alloc", not(feature = "std")))]
        use $crate::alloc::vec::Vec;

        #[doc = $doc]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct Hash([u8; $bytes]);

        impl Hash {
            /// Length of the hash, in bytes.
            pub const LEN: usize = $bytes;

            /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
            ///
            /// # Returns
            ///
            /// The digest created by hashing `bytes` with engine's hashing algorithm.
            #[allow(clippy::self_named_constructors)] // `hash` is a verb but `Hash` is a noun.
            pub fn hash(bytes: &[u8]) -> Self {
                let mut engine = Self::engine();
                engine.input(bytes);
                Self(engine.finalize())
            }

            /// Returns a hash engine that is ready to be used for data.
            pub fn engine() -> Engine { Engine::new() }

            /// Creates a `Hash` from an `engine`.
            ///
            /// This is equivalent to calling `Hash::from_byte_array(engine.finalize())`.
            pub fn from_engine(engine: Engine) -> Self {
                let digest = engine.finalize();
                Self(digest)
            }

            /// Zero cost conversion between a fixed length byte array shared reference and
            /// a shared reference to this Hash type.
            pub fn from_bytes_ref(bytes: &[u8; $bytes]) -> &Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; Self::LEN]
                unsafe { &*(bytes as *const _ as *const Self) }
            }

            /// Zero cost conversion between a fixed length byte array exclusive reference and
            /// an exclusive reference to this Hash type.
            pub fn from_bytes_mut(bytes: &mut [u8; $bytes]) -> &mut Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; $bytes]
                unsafe { &mut *(bytes as *mut _ as *mut Self) }
            }

            /// Copies a byte slice into a hash object.
            pub fn from_slice(sl: &[u8]) -> Result<Self, $crate::FromSliceError> {
                if sl.len() != $bytes {
                    Err(crate::FromSliceError { expected: $bytes, got: sl.len() })
                } else {
                    let mut ret = [0; $bytes];
                    ret.copy_from_slice(sl);
                    Ok(Self::from_byte_array(ret))
                }
            }

            /// Constructs a hash from the underlying byte array.
            pub fn from_byte_array(bytes: [u8; $bytes]) -> Self { Self(bytes) }

            /// Returns the underlying byte array.
            pub fn to_byte_array(self) -> [u8; $bytes] { self.0 }

            /// Returns a reference to the underlying byte array.
            pub fn as_byte_array(&self) -> &[u8; $bytes] { &self.0 }

            /// Returns a reference to the underlying byte array as a slice.
            #[inline]
            pub fn as_bytes(&self) -> &[u8] { &self.0 }

            /// Copies the underlying bytes into a new `Vec`.
            #[cfg(feature = "alloc")]
            #[inline]
            pub fn to_bytes(&self) -> Vec<u8> { self.0.to_vec() }

            /// Returns an all zero hash.
            ///
            /// An all zeros hash is a made up construct because there is not a known input that can
            /// create it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis
            /// block's previous blockhash and the coinbase transaction's outpoint txid.
            pub fn all_zeros() -> Self { Self([0x00; $bytes]) }
        }

        #[cfg(feature = "schemars")]
        impl schemars::JsonSchema for Hash {
            fn schema_name() -> String { "Hash".to_owned() }

            fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
                let len = $bytes;
                let mut schema: schemars::schema::SchemaObject = <String>::json_schema(gen).into();
                schema.string = Some(Box::new(schemars::schema::StringValidation {
                    max_length: Some(len * 2),
                    min_length: Some(len * 2),
                    pattern: Some("[0-9a-fA-F]+".to_owned()),
                }));
                schema.into()
            }
        }

        // Always forwards, sha256d does not call the `hash_type` macro.
        $crate::impl_bytelike_traits!(Hash, $bytes, false);
    };
}
pub(crate) use hash_type;

/// Adds an implementation of the `HashEngine::input` method.
macro_rules! engine_input_impl(
    ($n:literal) => (
        #[cfg(not(hashes_fuzz))]
        fn input(&mut self, mut inp: &[u8]) {
            while !inp.is_empty() {
                let buf_idx = self.length % <Self as $crate::HashEngine>::BLOCK_SIZE;
                let rem_len = <Self as $crate::HashEngine>::BLOCK_SIZE - buf_idx;
                let write_len = $crate::_export::_core::cmp::min(rem_len, inp.len());

                self.buffer[buf_idx..buf_idx + write_len]
                    .copy_from_slice(&inp[..write_len]);
                self.length += write_len;
                if self.length % <Self as $crate::HashEngine>::BLOCK_SIZE == 0 {
                    self.process_block();
                }
                inp = &inp[write_len..];
            }
        }

        #[cfg(hashes_fuzz)]
        fn input(&mut self, inp: &[u8]) {
            for c in inp {
                self.buffer[0] ^= *c;
            }
            self.length += inp.len();
        }
    )
);
pub(crate) use engine_input_impl;
