// SPDX-License-Identifier: CC0-1.0

//! MuHash3072 implementation.
//!
//! Unlike other hash algorithms in this crate, [`MuHash`] is a wrapper type that provides
//! semantic meaning to a plain byte array. It cannot be computed by this crate.
//!
//! [`MuHash`]: `super::MuHash`

/// The size in bytes of the hash output.
const BYTE_SIZE: usize = 384;

// This code is the exact same as calling `hash_type_no_default!` but excludes call to `impl_write`.
internals::transparent_newtype! {
    #[doc = "Output of the MuHash3072 hash function."]
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Hash([u8; BYTE_SIZE]);

    impl Hash {
        /// Zero cost conversion between a fixed length byte array shared reference and
        /// a shared reference to this Hash type.
        pub fn from_bytes_ref(bytes: &_) -> &Self;

        /// Zero cost conversion between a fixed length byte array exclusive reference and
        /// an exclusive reference to this Hash type.
        pub fn from_bytes_mut(bytes: &mut _) -> &mut Self;
    }
}

impl Hash {
    /// Constructs a new hash from the underlying byte array.
    pub const fn from_byte_array(bytes: [u8; BYTE_SIZE]) -> Self { Self(bytes) }

    /// Returns the underlying byte array.
    pub const fn to_byte_array(self) -> [u8; BYTE_SIZE] { self.0 }

    /// Returns a reference to the underlying byte array.
    pub const fn as_byte_array(&self) -> &[u8; BYTE_SIZE] { &self.0 }
}

crate::internal_macros::hash_trait_impls!(BYTE_SIZE * 8, false);
