// SPDX-License-Identifier: CC0-1.0

//! `SHA256t` implementation (tagged SHA256).

use core::cmp;
use core::marker::PhantomData;

#[cfg(doc)]
use crate::sha256::Midstate;
use crate::{sha256, HashEngine as _};

/// Hashes some bytes.
pub fn hash<T>(data: &[u8]) -> Hash<T>
where
    T: Tag,
{
    use crate::HashEngine as _;

    let mut engine = HashEngine::default();
    engine.input(data);
    engine.finalize()
}

/// Hashes all the byte slices retrieved from the iterator together.
pub fn hash_byte_chunks<B, I, T>(byte_slices: I) -> Hash<T>
where
    B: AsRef<[u8]>,
    I: IntoIterator<Item = B>,
    T: Tag,
{
    use crate::HashEngine as _;

    let mut engine = HashEngine::default();
    for slice in byte_slices {
        engine.input(slice.as_ref());
    }
    engine.finalize()
}

/// Trait representing a tag that can be used as a context for `SHA256t` hashes.
pub trait Tag {
    /// The [`Midstate`] after pre-tagging the hash engine.
    const MIDSTATE: sha256::Midstate;
}

internals::transparent_newtype! {
    /// Output of the SHA256t hash function.
    pub struct Hash<T>(PhantomData<T>, [u8; 32]);

    impl<T> Hash<T> {
        /// Zero cost conversion between a fixed length byte array shared reference and
        /// a shared reference to this Hash type.
        pub fn from_bytes_ref(bytes: &_) -> &Self;

        /// Zero cost conversion between a fixed length byte array exclusive reference and
        /// an exclusive reference to this Hash type.
        pub fn from_bytes_mut(bytes: &mut _) -> &mut Self;
    }
}

impl<T> Hash<T>
where
    T: Tag,
{
    /// Constructs a new hash from the underlying byte array.
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self { Self(PhantomData, bytes) }

    /// Produces a hash from the current state of a given engine.
    pub fn from_engine(e: HashEngine<T>) -> Self {
        Self::from_byte_array(sha256::Hash::from_engine(e.0).to_byte_array())
    }

    /// Constructs a new engine.
    pub fn engine() -> HashEngine<T> { HashEngine::default() }

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
    pub const fn to_byte_array(self) -> [u8; 32] { self.1 }

    /// Returns a reference to the underlying byte array.
    pub const fn as_byte_array(&self) -> &[u8; 32] { &self.1 }
}

impl<T: Tag> Copy for Hash<T> {}
impl<T: Tag> Clone for Hash<T> {
    fn clone(&self) -> Self { *self }
}
impl<T: Tag> PartialEq for Hash<T> {
    fn eq(&self, other: &Self) -> bool { self.as_byte_array() == other.as_byte_array() }
}
impl<T: Tag> Eq for Hash<T> {}
impl<T: Tag> PartialOrd for Hash<T> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(cmp::Ord::cmp(self, other))
    }
}
impl<T: Tag> Ord for Hash<T> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        cmp::Ord::cmp(&self.as_byte_array(), &other.as_byte_array())
    }
}
impl<T: Tag> core::hash::Hash for Hash<T> {
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) { self.as_byte_array().hash(h) }
}

crate::internal_macros::hash_trait_impls!(256, false, T: Tag);

/// Engine to compute `SHA256t` hash function.
#[derive(Debug)]
pub struct HashEngine<T>(sha256::HashEngine, PhantomData<T>);

impl<T: Tag> Default for HashEngine<T> {
    fn default() -> Self {
        let tagged = sha256::HashEngine::from_midstate(T::MIDSTATE);
        Self(tagged, PhantomData)
    }
}

impl<T: Tag> Clone for HashEngine<T> {
    fn clone(&self) -> Self { Self(self.0.clone(), PhantomData) }
}

impl<T: Tag> crate::HashEngine for HashEngine<T> {
    type Hash = Hash<T>;
    type Bytes = [u8; 32];
    const BLOCK_SIZE: usize = 64; // Same as sha256::HashEngine::BLOCK_SIZE;

    fn input(&mut self, data: &[u8]) { self.0.input(data) }
    fn n_bytes_hashed(&self) -> u64 { self.0.n_bytes_hashed() }
    fn finalize(self) -> Self::Hash { Hash::from_engine(self) }
}

crate::internal_macros::impl_write!(
    HashEngine<T>,
    |us: &mut HashEngine<T>, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) },
    T: crate::sha256t::Tag
);

// Workaround macros being unavailable in attributes.
#[doc(hidden)]
#[macro_export]
macro_rules! sha256t_tag_struct {
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
macro_rules! sha256t_tag_constructor {
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
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    use crate::sha256;
    use crate::sha256t;

    const TEST_MIDSTATE: [u8; 32] = [
        156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147,
        108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
    ];

    // The digest created by sha256 hashing `&[0]` starting with `TEST_MIDSTATE`.
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    const HASH_ZERO_BACKWARD: &str =
        "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed";
    // And the same thing, forward.
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    const HASH_ZERO_FORWARD: &str =
        "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829";

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    pub struct TestHashTag;

    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    impl sha256t::Tag for TestHashTag {
        const MIDSTATE: sha256::Midstate = sha256::Midstate::new(TEST_MIDSTATE, 64);
    }

    // We support manually implementing `Tag` and creating a tagged hash from it.
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    pub type TestHash = sha256t::Hash<TestHashTag>;

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn manually_created_sha256t_hash_type() {
        use alloc::string::ToString;

        assert_eq!(TestHash::hash(&[0]).to_string(), HASH_ZERO_FORWARD);
    }

    // We also provide macros to create the tag and the hash type.
    sha256t_tag! {
        /// Test detailed explanation.
        struct NewTypeTagBackward = raw(TEST_MIDSTATE, 64);
    }
    hash_newtype! {
        /// A test hash.
        #[hash_newtype(backward)]
        struct NewTypeHashBackward(sha256t::Hash<NewTypeTagBackward>);
    }
    #[cfg(feature = "hex")]
    crate::impl_hex_for_newtype!(NewTypeHashBackward);
    #[cfg(not(feature = "hex"))]
    crate::impl_debug_only_for_newtype!(NewTypeHashBackward);

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn macro_created_sha256t_hash_type_backward() {
        use alloc::string::ToString;

        let inner = sha256t::Hash::<NewTypeTagBackward>::hash(&[0]);
        let hash = NewTypeHashBackward::from_byte_array(inner.to_byte_array());
        assert_eq!(hash.to_string(), HASH_ZERO_BACKWARD);
        // Note one has to use the new wrapper type to get backwards formatting.
        assert_eq!(sha256t::Hash::<NewTypeTagBackward>::hash(&[0]).to_string(), HASH_ZERO_FORWARD);
    }

    // We also provide a macro to create the tag and the hash type.
    sha256t_tag! {
        /// Test detailed explanation.
        struct NewTypeTagForward = raw(TEST_MIDSTATE, 64);
    }
    hash_newtype! {
        /// A test hash.
        #[hash_newtype(forward)]
        struct NewTypeHashForward(sha256t::Hash<NewTypeTagForward>);
    }
    #[cfg(feature = "hex")]
    crate::impl_hex_for_newtype!(NewTypeHashForward);
    #[cfg(not(feature = "hex"))]
    crate::impl_debug_only_for_newtype!(NewTypeHashForward);

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn macro_created_sha256t_hash_type_prints_forward() {
        use alloc::string::ToString;

        let inner = sha256t::Hash::<NewTypeTagForward>::hash(&[0]);
        let hash = NewTypeHashForward::from_byte_array(inner.to_byte_array());
        assert_eq!(hash.to_string(), HASH_ZERO_FORWARD);
        // We can also just use the `sha256t::Hash` type directly.
        assert_eq!(sha256t::Hash::<NewTypeTagForward>::hash(&[0]).to_string(), HASH_ZERO_FORWARD);
    }
}
