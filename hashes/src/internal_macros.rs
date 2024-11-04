// SPDX-License-Identifier: CC0-1.0

//! Non-public macros

/// Adds trait impls to the type called `Hash` in the current scope.
///
/// Implpements various conversion traits as well as the [`crate::Hash`] trait.
/// Arguments:
///
/// * `$bits` - number of bits this hash type has
/// * `$reverse` - `bool`  - `true` if the hash type should be displayed backwards, `false`
///    otherwise.
/// * `$gen: $gent` - generic type(s) and trait bound(s)
///
/// Restrictions on usage:
///
/// * There must be a free-standing `fn from_engine(HashEngine) -> Hash` in the scope
/// * `fn internal_new([u8; $bits / 8]) -> Self` must exist on `Hash`
///
/// `from_engine` obviously implements the finalization algorithm.
macro_rules! hash_trait_impls {
    ($bits:expr, $reverse:expr $(, $gen:ident: $gent:ident)*) => {
        $crate::impl_bytelike_traits!(Hash, { $bits / 8 }, $reverse $(, $gen: $gent)*);

        impl<$($gen: $gent),*> $crate::GeneralHash for Hash<$($gen),*> {
            type Engine = HashEngine;

            fn from_engine(e: HashEngine) -> Hash<$($gen),*> { Self::from_engine(e) }
        }

        impl<$($gen: $gent),*> $crate::Hash for Hash<$($gen),*> {
            type Bytes = [u8; $bits / 8];

            const DISPLAY_BACKWARD: bool = $reverse;

            fn from_byte_array(bytes: Self::Bytes) -> Self { Self::from_byte_array(bytes) }

            #[allow(deprecated)]
            fn from_slice(sl: &[u8]) -> $crate::_export::_core::result::Result<Hash<$($gen),*>, $crate::FromSliceError> {
                Self::from_slice(sl)
            }

            fn to_byte_array(self) -> Self::Bytes { self.to_byte_array() }

            fn as_byte_array(&self) -> &Self::Bytes { self.as_byte_array() }
        }
    }
}
pub(crate) use hash_trait_impls;

/// Creates a type called `Hash` and implements the standard general hashing interface for it.
///
/// The created type has a single field and will have all standard derives as well as an
/// implementation of [`crate::Hash`].
///
/// Arguments:
///
/// * `$bits` - the number of bits of the hash type
/// * `$reverse` - `true` if the hash should be displayed backwards, `false` otherwise
/// * `$doc` - doc string to put on the type
///
/// The `from_engine` free-standing function is still required with this macro. See the doc of
/// [`hash_trait_impls`].
macro_rules! general_hash_type {
    ($bits:expr, $reverse:expr, $doc:literal) => {
        $crate::internal_macros::hash_type_no_default!($bits, $reverse, $doc);

        impl Hash {
            /// Produces a hash from the current state of a given engine.
            pub fn from_engine(e: HashEngine) -> Hash { from_engine(e) }

            /// Constructs a new engine.
            pub fn engine() -> HashEngine { Default::default() }

            /// Hashes some bytes.
            #[allow(clippy::self_named_constructors)] // Hash is a noun and a verb.
            pub fn hash(data: &[u8]) -> Self { <Self as $crate::GeneralHash>::hash(data) }

            /// Hashes all the byte slices retrieved from the iterator together.
            pub fn hash_byte_chunks<B, I>(byte_slices: I) -> Self
            where
                B: AsRef<[u8]>,
                I: IntoIterator<Item = B>,
            {
                <Self as $crate::GeneralHash>::hash_byte_chunks(byte_slices)
            }

            /// Hashes the entire contents of the `reader`.
            #[cfg(feature = "bitcoin-io")]
            pub fn hash_reader<R: io::BufRead>(reader: &mut R) -> Result<Self, io::Error> {
                <Self as $crate::GeneralHash>::hash_reader(reader)
            }
        }
    };
}
pub(crate) use general_hash_type;

macro_rules! hash_type_no_default {
    ($bits:expr, $reverse:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct Hash([u8; $bits / 8]);

        impl Hash {
            const fn internal_new(arr: [u8; $bits / 8]) -> Self { Hash(arr) }

            /// Constructs a hash from the underlying byte array.
            pub const fn from_byte_array(bytes: [u8; $bits / 8]) -> Self {
                Self::internal_new(bytes)
            }

            /// Zero cost conversion between a fixed length byte array shared reference and
            /// a shared reference to this Hash type.
            pub fn from_bytes_ref(bytes: &[u8; $bits / 8]) -> &Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; $bits / 8]
                unsafe { &*(bytes as *const _ as *const Self) }
            }

            /// Zero cost conversion between a fixed length byte array exclusive reference and
            /// an exclusive reference to this Hash type.
            pub fn from_bytes_mut(bytes: &mut [u8; $bits / 8]) -> &mut Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; $bits / 8]
                unsafe { &mut *(bytes as *mut _ as *mut Self) }
            }

            /// Copies a byte slice into a hash object.
            pub fn from_slice(
                sl: &[u8],
            ) -> $crate::_export::_core::result::Result<Hash, $crate::FromSliceError> {
                if sl.len() != $bits / 8 {
                    Err($crate::FromSliceError($crate::error::FromSliceErrorInner {
                        expected: $bits / 8,
                        got: sl.len(),
                    }))
                } else {
                    let mut ret = [0; $bits / 8];
                    ret.copy_from_slice(sl);
                    Ok(Self::internal_new(ret))
                }
            }

            /// Returns the underlying byte array.
            pub const fn to_byte_array(self) -> [u8; $bits / 8] { self.0 }

            /// Returns a reference to the underlying byte array.
            pub const fn as_byte_array(&self) -> &[u8; $bits / 8] { &self.0 }
        }

        $crate::internal_macros::hash_trait_impls!($bits, $reverse);

        $crate::internal_macros::impl_io_write!(
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

// We do not use the `bitcoin_io::impl_write` macro because we don't have an unconditional
// dependency on `bitcoin-io` and we want to implement `std:io::Write` even when we don't depend on
// `bitcoin-io`.
macro_rules! impl_io_write {
    ($ty: ty, $write_fn: expr, $flush_fn: expr $(, $bounded_ty: ident : $bounds: path),*) => {
        #[cfg(feature = "bitcoin-io")]
        impl<$($bounded_ty: $bounds),*> bitcoin_io::Write for $ty {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> bitcoin_io::Result<usize> {
                $write_fn(self, buf)
            }
            #[inline]
            fn flush(&mut self) -> bitcoin_io::Result<()> {
                $flush_fn(self)
            }
        }

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
pub(crate) use impl_io_write;

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
