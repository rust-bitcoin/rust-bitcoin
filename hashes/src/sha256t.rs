// SPDX-License-Identifier: CC0-1.0

//! SHA256t implementation (tagged SHA256).

use core::cmp;
use core::marker::PhantomData;
use core::ops::Index;
use core::slice::SliceIndex;

use crate::{sha256, FromSliceError, HashEngine as _};

type HashEngine = sha256::HashEngine;

/// Trait representing a tag that can be used as a context for SHA256t hashes.
pub trait Tag {
    /// Returns a hash engine that is pre-tagged and is ready to be used for the data.
    fn engine() -> sha256::HashEngine;
}

/// Output of the SHA256t hash function.
#[repr(transparent)]
pub struct Hash<T>([u8; 32], PhantomData<T>);

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

impl<T> Hash<T>
where
    T: Tag,
{
    const fn internal_new(arr: [u8; 32]) -> Self { Hash(arr, PhantomData) }

    /// Zero cost conversion between a fixed length byte array shared reference and
    /// a shared reference to this Hash type.
    pub fn from_bytes_ref(bytes: &[u8; 32]) -> &Self {
        // Safety: Sound because Self is #[repr(transparent)] containing [u8; 32]
        unsafe { &*(bytes as *const _ as *const Self) }
    }

    /// Zero cost conversion between a fixed length byte array exclusive reference and
    /// an exclusive reference to this Hash type.
    pub fn from_bytes_mut(bytes: &mut [u8; 32]) -> &mut Self {
        // Safety: Sound because Self is #[repr(transparent)] containing [u8; 32]
        unsafe { &mut *(bytes as *mut _ as *mut Self) }
    }

    /// Constructs a new engine.
    pub fn engine() -> HashEngine { T::engine() }

    /// Produces a hash from the current state of a given engine.
    pub fn from_engine(e: HashEngine) -> Hash<T> { from_engine(e) }

    /// Copies a byte slice into a hash object.
    pub fn from_slice(sl: &[u8]) -> Result<Hash<T>, FromSliceError> {
        if sl.len() != 32 {
            Err(FromSliceError { expected: 32, got: sl.len() })
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Self::internal_new(ret))
        }
    }

    /// Hashes some bytes.
    #[allow(clippy::self_named_constructors)] // Hash is a noun and a verb.
    pub fn hash(data: &[u8]) -> Self {
        use crate::HashEngine;

        let mut engine = Self::engine();
        engine.input(data);
        Self::from_engine(engine)
    }

    /// Hashes all the byte slices retrieved from the iterator together.
    pub fn hash_byte_chunks<B, I>(byte_slices: I) -> Self
    where
        B: AsRef<[u8]>,
        I: IntoIterator<Item = B>,
    {
        let mut engine = Self::engine();
        for slice in byte_slices {
            engine.input(slice.as_ref());
        }
        Self::from_engine(engine)
    }

    /// Returns the underlying byte array.
    pub const fn to_byte_array(self) -> [u8; 32] { self.0 }

    /// Returns a reference to the underlying byte array.
    pub const fn as_byte_array(&self) -> &[u8; 32] { &self.0 }

    /// Constructs a hash from the underlying byte array.
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self { Self::internal_new(bytes) }
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

crate::internal_macros::hash_trait_impls!(256, false, T: Tag);

fn from_engine<T>(e: sha256::HashEngine) -> Hash<T>
where
    T: Tag,
{
    Hash::from_byte_array(sha256::Hash::from_engine(e).to_byte_array())
}

/// Macro used to define a newtype tagged hash.
///
/// This macro creates two types:
///
/// * a tag struct
/// * a hash wrapper
///
/// The syntax is:
///
/// ```
/// # use bitcoin_hashes::sha256t_hash_newtype;
/// sha256t_hash_newtype! {
///     /// Optional documentation details here.
///     /// Summary is always generated.
///     pub struct FooTag = hash_str("foo");
///
///     /// A foo hash.
///     // Direction works just like the hash_newtype! macro.
///     #[hash_newtype(backward)]
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
/// `#[hash_newtype(...)]`). The attributes suffer same compiler performance limitations as in
/// [`hash_newtype`] macro.
///
/// The macro accepts multiple inputs so you can define multiple hash newtypes in one macro call.
/// Just make sure to enter the structs in order `Tag0`, `Hash0`, `Tag1`, `Hash1`...
///
/// [`hash_newtype`]: crate::hash_newtype
#[macro_export]
macro_rules! sha256t_hash_newtype {
    ($(#[$($tag_attr:tt)*])* $tag_vis:vis struct $tag:ident = $constructor:tt($($tag_value:tt)+); $(#[$($hash_attr:tt)*])* $hash_vis:vis struct $hash_name:ident($(#[$($field_attr:tt)*])* _);) => {
        $crate::sha256t_hash_newtype_tag!($tag_vis, $tag, stringify!($hash_name), $(#[$($tag_attr)*])*);

        impl $crate::sha256t::Tag for $tag {
            #[inline]
            fn engine() -> $crate::sha256::HashEngine {
                const MIDSTATE: $crate::sha256::Midstate = $crate::sha256t_hash_newtype_tag_constructor!($constructor, $($tag_value)+);
                $crate::sha256::HashEngine::from_midstate(MIDSTATE)
            }
        }

        $crate::hash_newtype! {
            $(#[$($hash_attr)*])*
            $hash_vis struct $hash_name($(#[$($field_attr)*])* $crate::sha256t::Hash<$tag>);
        }

        impl $hash_name {
            /// Constructs a new engine.
            #[allow(unused)] // the user of macro may not need this
            pub fn engine() -> <$hash_name as $crate::GeneralHash>::Engine {
                <$hash_name as $crate::GeneralHash>::engine()
            }

            /// Produces a hash from the current state of a given engine.
            #[allow(unused)] // the user of macro may not need this
            pub fn from_engine(e: <$hash_name as $crate::GeneralHash>::Engine) -> Self {
                <$hash_name as $crate::GeneralHash>::from_engine(e)
            }

            /// Hashes some bytes.
            #[allow(unused)] // the user of macro may not need this
            pub fn hash(data: &[u8]) -> Self {
                use $crate::HashEngine;

                let mut engine = Self::engine();
                engine.input(data);
                Self::from_engine(engine)
            }

            /// Hashes all the byte slices retrieved from the iterator together.
            #[allow(unused)] // the user of macro may not need this
            pub fn hash_byte_chunks<B, I>(byte_slices: I) -> Self
            where
                B: AsRef<[u8]>,
                I: IntoIterator<Item = B>,
            {
                use $crate::HashEngine;

                let mut engine = Self::engine();
                for slice in byte_slices {
                    engine.input(slice.as_ref());
                }
                Self::from_engine(engine)
            }
        }

        impl $crate::GeneralHash for $hash_name {
            type Engine = <$crate::sha256t::Hash<$tag> as $crate::GeneralHash>::Engine;

            fn engine() -> Self::Engine {
                <$crate::sha256t::Hash<$tag> as $crate::GeneralHash>::engine()
            }

            fn from_engine(e: Self::Engine) -> $hash_name {
                Self::from(<$crate::sha256t::Hash<$tag> as $crate::GeneralHash>::from_engine(e))
            }
        }
    }
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

#[doc(hidden)]
#[macro_export]
macro_rules! sha256t_hash_newtype_tag_constructor {
    (hash_str, $value:expr) => {
        $crate::sha256::Midstate::hash_tag($value.as_bytes())
    };
    (hash_bytes, $value:expr) => {
        $crate::sha256::Midstate::hash_tag($value)
    };
    (raw, $bytes:expr, $len:expr) => {
        $crate::sha256::Midstate::new($bytes, $len)
    };
}

#[cfg(test)]
mod tests {
    use crate::{sha256, sha256t};

    const TEST_MIDSTATE: [u8; 32] = [
        156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147,
        108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
    ];

    // The digest created by sha256 hashing `&[0]` starting with `TEST_MIDSTATE`.
    #[cfg(feature = "alloc")]
    const HASH_ZERO_BACKWARD: &str =
        "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed";
    // And the same thing, forward.
    #[cfg(feature = "alloc")]
    const HASH_ZERO_FORWARD: &str =
        "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829";

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
    pub struct TestHashTag;

    impl sha256t::Tag for TestHashTag {
        fn engine() -> sha256::HashEngine {
            // The TapRoot TapLeaf midstate.
            let midstate = sha256::Midstate::new(TEST_MIDSTATE, 64);
            sha256::HashEngine::from_midstate(midstate)
        }
    }

    // We support manually implementing `Tag` and creating a tagged hash from it.
    #[cfg(feature = "alloc")]
    pub type TestHash = sha256t::Hash<TestHashTag>;

    #[test]
    #[cfg(feature = "alloc")]
    fn manually_created_sha256t_hash_type() {
        assert_eq!(TestHash::hash(&[0]).to_string(), HASH_ZERO_FORWARD);
    }

    // We also provide a macro to create the tag and the hash type.
    sha256t_hash_newtype! {
        /// Test detailed explanation.
        struct NewTypeTagBackward = raw(TEST_MIDSTATE, 64);

        /// A test hash.
        #[hash_newtype(backward)]
        struct NewTypeHashBackward(_);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn macro_created_sha256t_hash_type_backward() {
        assert_eq!(NewTypeHashBackward::hash(&[0]).to_string(), HASH_ZERO_BACKWARD);
    }

    // We also provide a macro to create the tag and the hash type.
    sha256t_hash_newtype! {
        /// Test detailed explanation.
        struct NewTypeTagForward = raw(TEST_MIDSTATE, 64);

        /// A test hash.
        #[hash_newtype(forward)]
        struct NewTypeHashForward(_);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn macro_created_sha256t_hash_type_prints_forward() {
        assert_eq!(NewTypeHashForward::hash(&[0]).to_string(), HASH_ZERO_FORWARD);
    }
}
