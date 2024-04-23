// SPDX-License-Identifier: CC0-1.0

//! SHA256t implementation (tagged SHA256).
//!

use core::marker::PhantomData;
use core::ops::Index;
use core::slice::SliceIndex;
use core::{cmp, str};

use crate::{sha256, FromSliceError};

type HashEngine = sha256::HashEngine;

/// Trait representing a tag that can be used as a context for SHA256t hashes.
pub trait Tag {
    /// Returns a hash engine that is pre-tagged and is ready to be used for the data.
    fn engine() -> sha256::HashEngine;
}

/// Output of the SHA256t hash function.
#[repr(transparent)]
pub struct Hash<T: Tag>([u8; 32], PhantomData<T>);

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

impl<T: Tag> Hash<T> {
    fn internal_new(arr: [u8; 32]) -> Self { Hash(arr, Default::default()) }

    fn internal_engine() -> HashEngine { T::engine() }
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

crate::internal_macros::hash_trait_impls!(256, true, T: Tag);

fn from_engine<T: Tag>(e: sha256::HashEngine) -> Hash<T> {
    use crate::Hash as _;

    Hash::from_byte_array(sha256::Hash::from_engine(e).to_byte_array())
}

#[doc(hidden)]
#[macro_export]
macro_rules! sha256t_hash_newtype_tag_constructor {
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
    #[cfg(feature = "alloc")]
    use crate::Hash;
    use crate::{sha256, sha256t};

    const TEST_MIDSTATE: [u8; 32] = [
        156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147,
        108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
    ];

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
    pub struct TestHashTag;

    impl sha256t::Tag for TestHashTag {
        fn engine() -> sha256::HashEngine {
            // The TapRoot TapLeaf midstate.
            let midstate = sha256::Midstate::from_byte_array(TEST_MIDSTATE);
            sha256::HashEngine::from_midstate(midstate, 64)
        }
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for TestHashTag {
        fn schema_name() -> String { "Hash".to_owned() }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            let mut schema: schemars::schema::SchemaObject = <String>::json_schema(gen).into();
            schema.string = Some(Box::new(schemars::schema::StringValidation {
                max_length: Some(64 * 2),
                min_length: Some(64 * 2),
                pattern: Some("[0-9a-fA-F]+".to_owned()),
            }));
            schema.into()
        }
    }

    /// A hash tagged with `$name`.
    #[cfg(feature = "alloc")]
    pub type TestHash = sha256t::Hash<TestHashTag>;

    #[test]
    #[cfg(feature = "alloc")]
    fn test_sha256t() {
        assert_eq!(
            TestHash::hash(&[0]).to_string(),
            "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed"
        );
    }
}
