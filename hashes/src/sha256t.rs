// SPDX-License-Identifier: CC0-1.0

//! SHA-256t implementation (tagged SHA-256).

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;
use core::cmp;
use core::marker::PhantomData;

use crate::{sha256, HashEngine};

/// Length of digest created by SHA-256t hash algorithm, in bytes.
pub const DIGEST_SIZE: usize = sha256::DIGEST_SIZE;

/// Engine to compute tagged SHA-256 hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Engine<T>(sha256::Engine, PhantomData<T>);

impl<T: Tag> Engine<T> {
    /// Creates a new tagged hash engine.
    pub fn new() -> Self { <T as Tag>::engine() }
}

impl<T: Tag> Default for Engine<T> {
    fn default() -> Self { Self::new() }
}

impl<T: Tag> HashEngine for Engine<T> {
    type Digest = [u8; 32];
    type Midstate = sha256::Midstate;
    const BLOCK_SIZE: usize = sha256::BLOCK_SIZE;

    #[inline]
    fn input(&mut self, data: &[u8]) { self.0.input(data) }

    #[inline]
    fn n_bytes_hashed(&self) -> usize { self.0.n_bytes_hashed() }

    #[inline]
    fn finalize(self) -> Self::Digest { self.0.finalize() }

    #[inline]
    fn midstate(&self) -> Self::Midstate { self.0.midstate() }

    #[inline]
    fn from_midstate(midstate: sha256::Midstate, length: usize) -> Engine<T> {
        let inner = sha256::Engine::from_midstate(midstate, length);
        Self(inner, PhantomData)
    }
}

/// Trait representing a tag that can be used as a context for SHA-256t hashes.
pub trait Tag: Clone {
    /// Returns a hash engine that is pre-tagged and is ready to be used for the data.
    fn engine() -> Engine<Self>;
}

/// Output of the SHA-256t hash function.
#[repr(transparent)]
pub struct Hash<T: Tag>([u8; 32], PhantomData<T>);

impl<T: Tag> Hash<T> {
    /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
    ///
    /// # Returns
    ///
    /// The digest created by hashing `bytes` with engine's hashing algorithm.
    #[allow(clippy::self_named_constructors)] // `hash` is a verb but `Hash` is a noun.
    pub fn hash(bytes: &[u8]) -> Self {
        let mut engine = Self::engine();
        engine.input(bytes);
        Self(engine.finalize(), PhantomData)
    }

    /// Returns a hash engine that is ready to be used for data.
    pub fn engine() -> Engine<T> { <T as Tag>::engine() }

    /// Creates a `Hash` from an `engine`.
    ///
    /// This is equivalent to calling `Hash::from_byte_array(engine.finalize())`.
    pub fn from_engine(engine: Engine<T>) -> Self {
        let digest = engine.finalize();
        Self(digest, PhantomData)
    }

    /// Zero cost conversion between a fixed length byte array shared reference and
    /// a shared reference to this hash type.
    pub fn from_bytes_ref(bytes: &[u8; 32]) -> &Self {
        // Safety: Sound because Self is #[repr(transparent)] containing [u8; Self::LEN]
        unsafe { &*(bytes as *const _ as *const Self) }
    }

    /// Zero cost conversion between a fixed length byte array exclusive reference and
    /// an exclusive reference to this hash type.
    pub fn from_bytes_mut(bytes: &mut [u8; 32]) -> &mut Self {
        // Safety: Sound because Self is #[repr(transparent)] containing [u8; 32]
        unsafe { &mut *(bytes as *mut _ as *mut Self) }
    }

    /// Copies a byte slice into a hash object.
    pub fn from_slice(sl: &[u8]) -> Result<Self, crate::FromSliceError> {
        if sl.len() != 32 {
            Err(crate::FromSliceError { expected: 32, got: sl.len() })
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Self::from_byte_array(ret))
        }
    }

    /// Constructs a hash from the underlying byte array.
    pub fn from_byte_array(bytes: [u8; 32]) -> Self { Self(bytes, PhantomData) }

    /// Returns the underlying byte array.
    pub fn to_byte_array(self) -> [u8; 32] { self.0 }

    /// Returns a reference to the underlying byte array.
    pub fn as_byte_array(&self) -> &[u8; 32] { &self.0 }

    /// Returns a reference to the underlying byte array as a slice.
    pub fn as_bytes(&self) -> &[u8] { &self.0 }

    /// Copies the underlying bytes into a new `Vec`.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Vec<u8> { self.0.to_vec() }

    /// Returns an all zero hash.
    ///
    /// An all zeros hash is a made up construct because there is not a known input that can
    /// create it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis
    /// block's previous blockhash and the coinbase transaction's outpoint txid.
    pub fn all_zeros() -> Self { Self([0x00; 32], PhantomData) }
}

#[cfg(feature = "schemars")]
impl<T: Tag> schemars::JsonSchema for Hash<T> {
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

impl<T: Tag> Copy for Hash<T> {}
impl<T: Tag> Clone for Hash<T> {
    fn clone(&self) -> Self { *self }
}
impl<T: Tag> PartialEq for Hash<T> {
    fn eq(&self, other: &Hash<T>) -> bool { self.0 == other.0 }
}
impl<T: Tag> Eq for Hash<T> {}
impl<T: Tag> Default for Hash<T> {
    fn default() -> Self { Hash([0; 32], PhantomData) }
}
impl<T: Tag> PartialOrd for Hash<T> {
    fn partial_cmp(&self, other: &Hash<T>) -> Option<cmp::Ordering> {
        Some(cmp::Ord::cmp(self, other))
    }
}
impl<T: Tag> Ord for Hash<T> {
    fn cmp(&self, other: &Hash<T>) -> cmp::Ordering { cmp::Ord::cmp(&self.0, &other.0) }
}
impl<T: Tag> core::hash::Hash for Hash<T> {
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) { self.0.hash(h) }
}

crate::impl_bytelike_traits!(Hash, 32, false, T: Tag);

/// Creates a new wrapper type - a hash type that wraps `sha256t::Hash` type.
///
/// This macro creates two types:
///
/// * a tag struct
/// * a hash wrapper
///
/// The syntax is:
///
/// ```
/// use bitcoin_hashes::{sha256t_hash_newtype, Tag, HashEngine};
/// sha256t_hash_newtype! {
///     /// Optional documentation details here.
///     /// Summary is always generated.
///     pub struct FooTag = hash_str("foo");
///
///     /// A foo hash.
///     pub struct FooHash(_);
/// }
/// ```
///
/// The structs must be defined in this order - tag first, then hash type. `hash_str` marker
/// says the midstate should be generated by hashing the supplied string in a way described in
/// BIP-341. Alternatively, you can supply `hash_bytes` to hash raw bytes. If you have the midstate
/// already pre-computed and prefer **compiler** performance to readability you may use
/// `raw(MIDSTATE_BYTES, HASHED_BYTES_LENGTH)` instead.
///
/// Both visibility modifiers and attributes are optional and passed to inner structs (excluding
/// `#[hash_newtype(...)]`). The attributes suffer the same compiler performance limitations as in
/// [`hash_newtype`] macro.
///
/// Contrary to `hash_newtype` the `sha256t_hash_newtype` macro does not allow defining multiple
/// hash newtypes in a single call because we found doing it to be overly difficult to read.
///
/// [`hash_newtype`]: crate::hash_newtype
#[macro_export]
macro_rules! sha256t_hash_newtype {
    (
        $(#[$($tag_attrs:tt)*])* $tag_vis:vis struct $tag:ident = $constructor:tt($($tag_value:tt)+);
        $(#[$($newtype_attrs:tt)*])* $newtype_vis:vis struct $newtype:ident($field_vis:vis _);
    ) => {
        $crate::sha256t_hash_newtype_tag!($tag_vis, $tag, stringify!($newtype), $(#[$($tag_attrs)*])*);

        impl $crate::sha256t::Tag for $tag {
            #[inline]
            fn engine() -> $crate::sha256t::Engine<Self> {
                use $crate::HashEngine;

                const MIDSTATE: ($crate::sha256::Midstate, usize) = $crate::tagged_midstate!($constructor, $($tag_value)+);
                #[allow(unused)]
                const _LENGTH_CHECK: () = [(); 1][MIDSTATE.1 % 64];

                $crate::sha256t::Engine::from_midstate(MIDSTATE.0, MIDSTATE.1)
            }
        }

        $crate::hash_newtype_struct! {
            #[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            $newtype_vis struct $newtype($field_vis $crate::sha256t::Hash<$tag>);

            $({ $($newtype_attrs)* })*
        }

        #[allow(unused)] // Not all functions are used by all hash types.
        impl $newtype {
            const DISPLAY_BACKWARD: bool = false; // Never display backwards for tagged hashes.

            /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
            ///
            /// # Returns
            ///
            /// The digest created by hashing `bytes` with engine's hashing algorithm.
            #[allow(clippy::self_named_constructors)] // `hash` is a verb but `Hash` is a noun.
            $field_vis fn hash(bytes: &[u8]) -> Self {
                let inner = $crate::sha256t::Hash::<$tag>::hash(bytes);
                Self(inner)
            }

            /// Returns a hash engine that is ready to be used for data.
            $field_vis fn engine() -> $crate::sha256t::Engine<$tag> { $tag::engine() }

            /// Creates a `Hash` from an `engine`.
            ///
            /// This is equivalent to calling `Hash::from_byte_array(engine.finalize())`.
            $field_vis fn from_engine(engine: $crate::sha256t::Engine<$tag>) -> Self {
                let inner = $crate::sha256t::Hash::<$tag>::from_engine(engine);
                Self(inner)
            }

            /// Zero cost conversion between a fixed length byte array shared reference and
            /// a shared reference to this hash type.
            pub fn from_bytes_ref(bytes: &[u8; 32]) -> &Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; Self::LEN]
                unsafe { &*(bytes as *const _ as *const Self) }
            }

            /// Zero cost conversion between a fixed length byte array exclusive reference and
            /// an exclusive reference to this hash type.
            pub fn from_bytes_mut(bytes: &mut [u8; 32]) -> &mut Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; 32]
                unsafe { &mut *(bytes as *mut _ as *mut Self) }
            }

            /// Copies a byte slice into a hash object.
            pub fn from_slice(sl: &[u8]) -> Result<Self, $crate::FromSliceError> {
                let inner = $crate::sha256t::Hash::<$tag>::from_slice(sl)?;
                Ok(Self(inner))
            }

            /// Constructs a hash from the underlying byte array.
            pub fn from_byte_array(bytes: [u8; 32]) -> Self {
                let inner = $crate::sha256t::Hash::<$tag>::from_byte_array(bytes);
                Self(inner)
            }

            /// Returns the underlying byte array.
            pub fn to_byte_array(self) -> [u8; 32] { self.0.to_byte_array() }

            /// Returns a reference to the underlying byte array.
            pub fn as_byte_array(&self) -> &[u8; 32] { self.0.as_byte_array() }

            /// Returns an all zero hash.
            ///
            /// An all zeros hash is a made up construct because there is not a known input that can
            /// create it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis
            /// block's previous blockhash and the coinbase transaction's outpoint txid.
            pub fn all_zeros() -> Self {
                let inner = $crate::sha256t::Hash::<$tag>::all_zeros();
                Self(inner)
            }
        }

        // Always display tagged hashes forwards.
        $crate::impl_bytelike_traits!($newtype, 32, false);
    };
}

// Workaround macros being unavailable in attributes.
#[doc(hidden)]
#[macro_export]
macro_rules! sha256t_hash_newtype_tag {
    ($vis:vis, $tag:ident, $name:expr, $(#[$($attr:meta)*])*) => {
        #[doc = "The tag used for [`"]
        #[doc = $name]
        #[doc = "`].\n\n"]
        $(#[$($attr)*])*
        #[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
        $vis struct $tag;
    };
}

/// Creates a const midstate used to instantiate a SHA-256 pre-tagged engine.
///
/// Requires `hashes::sha256` to be in scope.
#[doc(hidden)]
#[macro_export]
macro_rules! tagged_midstate {
    (hash_str, $value:expr) => {
        ($crate::sha256::Midstate::hash_tag($value.as_bytes()), 64)
    };
    (hash_bytes, $value:expr) => {
        ($crate::sha256::Midstate::hash_tag($value), 64)
    };
    (raw, $bytes:expr, $len:expr) => {
        ($crate::sha256::Midstate::from_byte_array($bytes), $len)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MIDSTATE: [u8; 32] = [
        156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147,
        108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
    ];

    // The digest created by sha256 hashing `&[0]` starting with `TEST_MIDSTATE`.
    #[cfg(feature = "alloc")]
    const HASH_ZERO: &str = "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829";

    // We provide a mechanism for manually creating tagged hashes.
    #[derive(Clone)]
    pub struct TestTag;

    impl Tag for TestTag {
        fn engine() -> Engine<Self> {
            let midstate = sha256::Midstate::from_byte_array(TEST_MIDSTATE);
            let inner = sha256::Engine::from_midstate(midstate, 64);
            Engine(inner, PhantomData)
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn manually_created_sha256t_hash_type() {
        assert_eq!(Hash::<TestTag>::hash(&[0]).to_string(), HASH_ZERO);
    }

    // We also provide a macro to create the tag and the hash type.
    sha256t_hash_newtype! {
        /// Test detailed explanation.
        struct NewTag = raw(TEST_MIDSTATE, 64);

        /// A test hash.
        struct NewTaggedHash(_);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn hash_engine() {
        let mut engine = Engine::<NewTag>::default();
        engine.input(&[0]);
        let digest = engine.finalize();
        let hash = Hash::<NewTag>::from_byte_array(digest);

        let got = hash.to_string();
        assert_eq!(got, HASH_ZERO);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn hash_type() {
        let got = Hash::<NewTag>::hash(&[0]).to_string();
        assert_eq!(got, HASH_ZERO);
    }

    // We want to test the macro here but specifically as its used in `rust-bitcoin`.
    sha256t_hash_newtype! {
        pub struct TapLeafTag = hash_str("TapLeaf");

        /// Taproot-tagged hash with tag \"TapLeaf\".
        ///
        /// This is used for computing tapscript script spend hash.
        pub struct TapLeafHash(_);
    }

    fn manually_tagged_sha256_engine() -> sha256::Engine {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash("TapLeaf".as_bytes());
        engine.input(tag_hash.as_ref());
        engine.input(tag_hash.as_ref());
        engine
    }

    // Check that manually creating the pre-tagged hash midsate is the same as
    // doing so using the new hash type.
    #[test]
    fn midstates() {
        let sha256_engine = manually_tagged_sha256_engine();
        let engine = TapLeafTag::engine();

        let sha256_midstate = sha256_engine.midstate();
        let engine_midstate = engine.midstate();
        assert_eq!(engine_midstate, sha256_midstate);
    }

    // Check that manually creating the pre-tagged hash engine then hashing the
    // empty byte slice is the same as doing so using the new hash type.
    #[test]
    fn digest() {
        let mut e = manually_tagged_sha256_engine();
        e.input(&[]);
        let sha256_hash = sha256::Hash::from_engine(e);

        let hash = TapLeafHash::hash(&[]);

        let sha256_bytes = sha256_hash.to_byte_array();
        let engine_bytes = hash.to_byte_array();
        assert_eq!(engine_bytes, sha256_bytes);
    }
}
