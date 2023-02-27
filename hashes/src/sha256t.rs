// Bitcoin Hashes Library
// Written in 2019 by
//   The rust-bitcoin developers.
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

//! SHA256t implementation (tagged SHA256).
//!

use core::{cmp, str};
use core::marker::PhantomData;
use core::ops::Index;
use core::slice::SliceIndex;

use crate::{Error, sha256};

type HashEngine = sha256::HashEngine;

/// Trait representing a tag that can be used as a context for SHA256t hashes.
pub trait Tag {
    /// Returns a hash engine that is pre-tagged and is ready to be used for the data.
    fn engine() -> sha256::HashEngine;
}

/// Output of the SHA256t hash function.
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[repr(transparent)]
pub struct Hash<T: Tag>(
    #[cfg_attr(feature = "schemars", schemars(schema_with = "crate::util::json_hex_string::len_32"))]
    [u8; 32],
    #[cfg_attr(feature = "schemars", schemars(skip))]
    PhantomData<T>
);

impl<T: Tag> Hash<T> {
    fn internal_new(arr: [u8; 32]) -> Self {
        Hash(arr, Default::default())
    }

    fn internal_engine() -> HashEngine {
        T::engine()
    }
}

impl<T: Tag> Copy for Hash<T> {}
impl<T: Tag> Clone for Hash<T> {
    fn clone(&self) -> Self {
        Hash(self.0, self.1)
    }
}
impl<T: Tag> PartialEq for Hash<T> {
    fn eq(&self, other: &Hash<T>) -> bool {
        self.0 == other.0
    }
}
impl<T: Tag> Eq for Hash<T> {}
impl<T: Tag> Default for Hash<T> {
    fn default() -> Self {
        Hash([0; 32], PhantomData)
    }
}
impl<T: Tag> PartialOrd for Hash<T> {
    fn partial_cmp(&self, other: &Hash<T>) -> Option<cmp::Ordering> {
        Some(cmp::Ord::cmp(self, other))
    }
}
impl<T: Tag> Ord for Hash<T> {
    fn cmp(&self, other: &Hash<T>) -> cmp::Ordering {
        cmp::Ord::cmp(&self.0, &other.0)
    }
}
impl<T: Tag> core::hash::Hash for Hash<T> {
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) {
        self.0.hash(h)
    }
}

crate::internal_macros::hash_trait_impls!(256, true, T: Tag);

fn from_engine<T: Tag>(e: sha256::HashEngine) -> Hash<T> {
    use crate::Hash as _;

    Hash::from_byte_array(sha256::Hash::from_engine(e).to_byte_array())
}

/// Macro used to define a newtype tagged hash.
/// It creates two public types:
/// - a sha256t::Tag struct,
/// - a sha256t::Hash type alias.
#[macro_export]
macro_rules! sha256t_hash_newtype {
    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $direction:tt) => {
        sha256t_hash_newtype!($newtype, $tag, $midstate, $midstate_len, $docs, $direction, stringify!($newtype));
    };

    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $direction:tt, $sname:expr) => {
        #[doc = "The tag used for ["]
        #[doc = $sname]
        #[doc = "]"]
        #[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
        pub struct $tag;

        impl $crate::sha256t::Tag for $tag {
            fn engine() -> $crate::sha256::HashEngine {
                let midstate = $crate::sha256::Midstate::from_byte_array($midstate);
                $crate::sha256::HashEngine::from_midstate(midstate, $midstate_len)
            }
        }

        $crate::hash_newtype! {
            #[$docs]
            #[hash_newtype($direction)]
            pub struct $newtype($crate::sha256t::Hash<$tag>);
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::{sha256, sha256t};
    #[cfg(feature = "alloc")]
    use crate::Hash;

    const TEST_MIDSTATE: [u8; 32] = [
       156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243,
       147, 108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
    ];

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    pub struct TestHashTag;

    impl sha256t::Tag for TestHashTag {
        fn engine() -> sha256::HashEngine {
            // The TapRoot TapLeaf midstate.
            let midstate = sha256::Midstate::from_byte_array(TEST_MIDSTATE);
            sha256::HashEngine::from_midstate(midstate, 64)
        }
    }

    /// A hash tagged with `$name`.
    #[cfg(feature = "alloc")]
    pub type TestHash = sha256t::Hash<TestHashTag>;

    sha256t_hash_newtype!(NewTypeHash, NewTypeTag, TEST_MIDSTATE, 64, doc="test hash", backward);

    #[test]
    #[cfg(feature = "alloc")]
    fn test_sha256t() {
        assert_eq!(
            TestHash::hash(&[0]).to_string(),
            "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed"
        );
        assert_eq!(
            NewTypeHash::hash(&[0]).to_string(),
            "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed"
        );
    }
}
