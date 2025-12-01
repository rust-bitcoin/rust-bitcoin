// SPDX-License-Identifier: CC0-1.0

//! Non-public macros

/// Adds trait impls to the type called `Hash` in the current scope.
///
/// Implements various conversion traits as well as the [`crate::Hash`] trait.
///
/// # Parameters
///
/// * `$bits` - the number of bits this hash type has
/// * `$reverse` - `bool`  - `true` if the hash type should be displayed backwards, `false`
///   otherwise.
/// * `$gen: $gent` - the generic type(s) and trait bound(s)
///
/// Restrictions on usage:
///
/// * The `Hash` type in scope must provide `from_byte_array`, `to_byte_array`, and `as_byte_array` (e.g., via `hash_type_no_default!`).
macro_rules! hash_trait_impls {
    ($bits:expr, $reverse:expr $(, $gen:ident: $gent:ident)*) => {
        $crate::impl_bytelike_traits!(Hash, { $bits / 8 } $(, $gen: $gent)*);
        #[cfg(feature = "hex")]
        $crate::impl_hex_string_traits!(Hash, { $bits / 8 }, $reverse $(, $gen: $gent)*);
        #[cfg(not(feature = "hex"))]
        $crate::impl_debug_only!(Hash, { $bits / 8 }, $reverse $(, $gen: $gent)*);

        #[cfg(feature = "serde")]
        $crate::serde_impl!(Hash, { $bits / 8} $(, $gen: $gent)*);

        impl<$($gen: $gent),*> $crate::Hash for Hash<$($gen),*> {
            type Bytes = [u8; $bits / 8];

            const DISPLAY_BACKWARD: bool = $reverse;

            fn from_byte_array(bytes: Self::Bytes) -> Self { Self::from_byte_array(bytes) }

            fn to_byte_array(self) -> Self::Bytes { self.to_byte_array() }

            fn as_byte_array(&self) -> &Self::Bytes { self.as_byte_array() }
        }
    }
}
pub(crate) use hash_trait_impls;

/// Constructs a type called `Hash` and implements the standard general hashing interface for it.
///
/// The created type has a single field and will have all standard derives as well as an
/// implementation of [`crate::Hash`].
///
/// # Parameters
///
/// * `$bits` - the number of bits of the hash type
/// * `$reverse` - `true` if the hash should be displayed backwards, `false` otherwise
/// * `$doc` - the doc string to put on the type
///
/// Restrictions on usage:
///
/// * Requires a `HashEngine` type in this module implementing `Default` and `crate::HashEngine<Hash = Hash, Bytes = [u8; $bits / 8]>`.
macro_rules! general_hash_type {
    ($bits:expr, $reverse:expr, $doc:literal) => {
        /// Hashes some bytes.
        pub fn hash(data: &[u8]) -> Hash {
            use crate::HashEngine as _;

            let mut engine = Hash::engine();
            engine.input(data);
            engine.finalize()
        }

        /// Hashes all the byte slices retrieved from the iterator together.
        pub fn hash_byte_chunks<B, I>(byte_slices: I) -> Hash
        where
            B: AsRef<[u8]>,
            I: IntoIterator<Item = B>,
        {
            use crate::HashEngine as _;

            let mut engine = Hash::engine();
            for slice in byte_slices {
                engine.input(slice.as_ref());
            }
            engine.finalize()
        }

        $crate::internal_macros::hash_type_no_default!($bits, $reverse, $doc);

        impl Hash {
            /// Constructs a new engine.
            pub fn engine() -> HashEngine { Default::default() }

            /// Hashes some bytes.
            #[allow(clippy::self_named_constructors)] // Hash is a noun and a verb.
            pub fn hash(data: &[u8]) -> Self { hash(data) }

            /// Hashes all the byte slices retrieved from the iterator together.
            pub fn hash_byte_chunks<B, I>(byte_slices: I) -> Self
            where
                B: AsRef<[u8]>,
                I: IntoIterator<Item = B>,
            {
                hash_byte_chunks(byte_slices)
            }
        }
    };
}
pub(crate) use general_hash_type;

macro_rules! hash_type_no_default {
    ($bits:expr, $reverse:expr, $doc:literal) => {
        internals::transparent_newtype! {
            #[doc = $doc]
            #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct Hash([u8; $bits / 8]);

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
            pub const fn from_byte_array(bytes: [u8; $bits / 8]) -> Self { Hash(bytes) }

            /// Returns the underlying byte array.
            pub const fn to_byte_array(self) -> [u8; $bits / 8] { self.0 }

            /// Returns a reference to the underlying byte array.
            pub const fn as_byte_array(&self) -> &[u8; $bits / 8] { &self.0 }
        }

        $crate::internal_macros::hash_trait_impls!($bits, $reverse);

        $crate::internal_macros::impl_write!(
            HashEngine,
            |us: &mut HashEngine, buf| {
                crate::HashEngine::input(us, buf);
                Ok(buf.len())
            },
            |_us| { Ok(()) }
        );
    };
}
pub(crate) use hash_type_no_default;

macro_rules! impl_write {
    ($ty: ty, $write_fn: expr, $flush_fn: expr $(, $bounded_ty: ident : $bounds: path),*) => {
        // `bitcoin_io::Write` is implemented in `bitcoin_io`.
        #[cfg(feature = "std")]
        impl<$($bounded_ty: $bounds),*> std::io::Write for $ty {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                $write_fn(self, buf)
            }

            #[inline]
            fn flush(&mut self) -> std::io::Result<()> {
                $flush_fn(self)
            }
        }
    }
}
pub(crate) use impl_write;

macro_rules! engine_input_impl(
    () => (
        #[cfg(not(hashes_fuzz))]
        fn input(&mut self, mut inp: &[u8]) {

            while !inp.is_empty() {
                let buf_idx = $crate::incomplete_block_len(self);
                let rem_len = <Self as crate::HashEngine>::BLOCK_SIZE - buf_idx;
                let write_len = cmp::min(rem_len, inp.len());

                self.buffer[buf_idx..buf_idx + write_len]
                    .copy_from_slice(&inp[..write_len]);
                self.bytes_hashed += write_len as u64;
                if $crate::incomplete_block_len(self) == 0 {
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
            self.bytes_hashed += inp.len() as u64;
        }
    )
);
pub(crate) use engine_input_impl;
