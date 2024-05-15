// SPDX-License-Identifier: CC0-1.0

//! Public macros.

/// Creates a new wrapper type - a hash type that wraps another hash type.
///
/// The syntax is as follows:
///
///
/// # Basic usage
///
/// ```
/// use bitcoin_hashes::{hash_newtype, sha256};
///
/// // See `examples/` for more.
///
/// hash_newtype! {
///     /// Controls the scope of:
///     ///
///     /// - The `ExampleEngine` type
///     /// - The `engine()` and `from_engine()` functions
///     /// - The inner field of `Example`
///     pub struct ExampleEngine(sha256);
///
///     /// Controls the scope of the `Example` type.
///     ///
///     /// The scope of the inner field is controlled by the scope of `ExampleEngine`.
///     pub struct Example(_);
/// }
///
/// let _ = Example::hash(&[]);
/// ```
///
/// You can use any valid visibility specifier in place of `pub` or you can omit either or both, if
/// you want the type or its field to be private.
///
/// # Attributes
///
/// Attributes can be put on the engine and the hash type as well as the inner fields.
///
/// Whether the hash is reversed or not when displaying depends on the inner type. You can override
/// it like this:
///
/// ```
/// # use bitcoin_hashes::{hash_newtype, sha256};
/// hash_newtype! {
///     /// Custom docs can go here.
///     pub struct ExampleEngine(sha256);
///
///     /// Custom docs can go here as well.
///     #[hash_newtype(backward)]
///     pub struct Example(_);
/// }
/// ```
///
/// This will display the hash backwards regardless of what the inner type does. Use `forward`
/// instead of `backward` to force displaying forward.
///
/// You can add arbitrary doc comments or other attributes to the struct or it's field. Note that
/// the macro already derives [`Copy`], [`Clone`], [`Eq`], [`PartialEq`],
/// [`Hash`](core::hash::Hash), [`Ord`], [`PartialOrd`]. With the `serde` feature on, this also adds
/// `Serialize` and `Deserialize` implementations.
///
/// Note: the macro is internally recursive. If you use too many attributes (> 256 tokens) you may
/// hit recursion limit. If you have so many attributes for a good reason, just raising the limit
/// should be OK. Note however that attribute-processing part has to use [TT muncher] which has
/// quadratic complexity, so having many attributes may blow up compile time. This should be rare.
///
/// [TT muncher]: https://danielkeep.github.io/tlborm/book/pat-incremental-tt-munchers.html
//
// Ever heard of legendary comments warning developers to not touch the code? Yep, here's another
// one. The following code is written the way it is for some specific reasons. If you think you can
// simplify it, I suggest spending your time elsewhere.
//
// If you looks at the code carefully you might ask these questions:
//
// * Why are attributes using `tt` and not `meta`?!
// * Why are the macros split like that?!
// * Why use recursion instead of `$()*`?
//
// None of these are here by accident. For some reason unknown to me, if you accept an argument to
// macro with any fragment specifier other than `tt` it will **not** match any of the rules
// requiring a specific token. Yep, I tried it, I literally got error that `hash_newtype` doesn't
// match `hash_newtype`. So all input attributes must be `tt`.
//
// Originally I wanted to define a bunch of macros that would filter-out hash_type attributes. Then
// I remembered (by seeing compiler error) that calling macros is not allowed inside attributes.
// And no, you can't bypass it by calling a helper macro and passing "output of another macro" into
// it. The whole macro gets passed, not the resulting value. So we have to generate the entire
// attributes. And you can't just place an attribute-producing macro above struct - they are
// considered separate items. This is not C.
//
// Thus struct is generated in a separate macro together with attributes. And since the macro needs
// attributes as the input and I didn't want to create confusion by using `#[]` syntax *after*
// struct, I opted to use `{}` as a separator. Yes, a separator is required because an attribute
// may be composed of multiple token trees - that's the point of "double repetition".
#[macro_export]
macro_rules! hash_newtype {
    (
        $(#[$($engine_type_attrs:tt)*])* $engine_type_vis:vis struct $new_engine_type:ident($(#[$engine_type_field_attrs:tt])* $hash:ident);
        $(#[$($hash_type_attrs:tt)*])* $hash_type_vis:vis struct $new_hash_type:ident($(#[$hash_type_field_attrs:tt])* _);
    ) => {
        $crate::hash_newtype_struct! {
            $engine_type_vis struct $new_engine_type($(#[$engine_type_field_attrs])* $engine_type_vis $hash::Engine);

            $({ $($engine_type_attrs)* })*
        }

        impl $crate::HashEngine for $new_engine_type {
            type Digest = <$hash::Engine as $crate::HashEngine>::Digest;
            type Midstate = <$hash::Engine as $crate::HashEngine>::Midstate;
            const BLOCK_SIZE: usize = $hash::Engine::BLOCK_SIZE;

            #[inline]
            fn n_bytes_hashed(&self) -> usize { self.0.n_bytes_hashed() }

            #[inline]
            fn input(&mut self, data: &[u8]) { self.0.input(data) }

            #[inline]
            fn finalize(self) -> Self::Digest { self.0.finalize() }

            #[inline]
            fn midstate(&self) -> Self::Midstate { self.0.midstate() }

            #[inline]
            fn from_midstate(midstate: Self::Midstate, length: usize) -> Self {
                let inner = $hash::Engine::from_midstate(midstate, length);
                Self(inner)
            }
        }

        $crate::bitcoin_io::impl_write!(
            $new_engine_type,
            |us: &mut $new_engine_type, buf| {
                use $crate::HashEngine as _;
                us.input(buf);
                Ok(buf.len())
            },
            |_us| { Ok(()) }
        );

        impl $new_engine_type {
            /// Creates a new
            #[doc = "Creates a new `"]
            #[doc = stringify!($new_engine_type)]
            #[doc = "` hash engine."]
            #[inline]
            pub const fn new() -> Self { Self($hash::Engine::new()) }
        }

        impl Default for $new_engine_type {
            fn default() -> Self { Self::new() }
        }

        $($crate::hash_newtype_known_attrs!(#[ $($hash_type_attrs)* ]);)*

        $crate::hash_newtype_struct! {
            #[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            $hash_type_vis struct $new_hash_type($(#[$hash_type_field_attrs])* $engine_type_vis $hash::Hash);

            $({ $($hash_type_attrs)* })*
        }

        #[allow(unused)] // the user of macro may not need this
        impl $new_hash_type {
            const DISPLAY_BACKWARD: bool = $crate::hash_newtype_get_direction!($hash, $(#[$($hash_type_attrs)*])*);

            /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
            ///
            /// # Returns
            ///
            /// The digest created by hashing `bytes` with engine's hashing algorithm.
            $engine_type_vis fn hash(bytes: &[u8]) -> Self {
                use $crate::HashEngine;
                let mut engine = Self::engine();
                engine.input(bytes);
                Self::from_engine(engine)
            }

            /// Creates a new engine.
            $engine_type_vis fn engine() -> $new_engine_type { $new_engine_type($hash::Hash::engine()) }

            /// Produces a hash from the current state of a given engine.
            $engine_type_vis fn from_engine(e: $new_engine_type) -> Self { Self($hash::Hash::from_engine(e.0)) }

            /// Zero cost conversion between a fixed length byte array shared reference and
            /// a shared reference to this hash type.
            pub fn from_bytes_ref(bytes: &[u8; $hash::DIGEST_SIZE]) -> &Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; $hash::DIGEST_SIZE]
                unsafe { &*(bytes as *const _ as *const Self) }
            }

            /// Zero cost conversion between a fixed length byte array exclusive reference and
            /// an exclusive reference to this hash type.
            pub fn from_bytes_mut(bytes: &mut [u8; $hash::DIGEST_SIZE]) -> &mut Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; $hash::DIGEST_SIZE]
                unsafe { &mut *(bytes as *mut _ as *mut Self) }
            }

            /// Copies a byte slice into a hash object.
            #[inline]
            pub fn from_slice(sl: &[u8]) -> $crate::_export::_core::result::Result<Self, $crate::FromSliceError> {
                Ok(Self($hash::Hash::from_slice(sl)?))
            }

            /// Constructs a hash from the underlying byte array.
            pub const fn from_byte_array(bytes: [u8; $hash::DIGEST_SIZE]) -> Self {
                Self($hash::Hash::from_byte_array(bytes))
            }

            /// Returns the underlying byte array.
            pub fn to_byte_array(self) -> [u8; $hash::DIGEST_SIZE] { self.0.to_byte_array() }

            /// Returns a reference to the underlying byte array.
            pub fn as_byte_array(&self) -> &[u8; $hash::DIGEST_SIZE] { self.0.as_byte_array() }

            /// Returns an all zero hash.
            ///
            /// An all zeros hash is a made up construct because there is not a known input that can create
            /// it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis block's
            /// previous blockhash and the coinbase transaction's outpoint txid.
            pub const fn all_zeros() -> Self { Self($hash::Hash::all_zeros()) }
        }

        impl $crate::_export::_core::convert::From<$hash::Hash> for $new_hash_type {
            fn from(inner: $hash::Hash) -> Self { Self(inner) }
        }

        impl $crate::_export::_core::convert::From<$new_hash_type> for $hash::Hash {
            fn from(hashtype: $new_hash_type) -> Self { hashtype.0 }
        }

        $crate::impl_bytelike_traits!($new_hash_type, $hash::DIGEST_SIZE, $new_hash_type::DISPLAY_BACKWARD);
    };
}

// Generates the struct only (no impls)
//
// This is a separate macro to make it more readable and have a separate interface that allows for
// two groups of type attributes: processed and not-yet-processed ones (think about it like
// computation via recursion). The macro recursively matches unprocessed attributes, popping them
// one at a time and either ignoring them (`hash_newtype`) or appending them to the list of
// processed attributes to be added to the struct.
//
// Once the list of not-yet-processed attributes is empty the struct is generated with processed
// attributes added.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_struct {
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path);) => {
        $(#[$other_attrs])*
        #[derive(Clone)]
        $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);
    };
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path); { hash_newtype($($ignore:tt)*) } $($type_attrs:tt)*) => {
        $crate::hash_newtype_struct! {
            $(#[$other_attrs])*
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $($type_attrs)*
        }
    };
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path); { $other_attr:meta } $($type_attrs:tt)*) => {
        $crate::hash_newtype_struct! {
            $(#[$other_attrs])*
            #[$other_attr]
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $($type_attrs)*
        }
    };
}

/// Adds trait impls to a bytelike type.
///
/// Implements:
///
/// * `str::FromStr`
/// * `fmt::{LowerHex, UpperHex}` using `hex-conservative`.
/// * `fmt::{Display, Debug}` by calling `LowerHex`
/// * `serde::{Deserialize, Serialize}`
/// * `AsRef[u8; $len]`
/// * `AsRef[u8]`
/// * `Borrow<[u8]>`
/// * `slice::SliceIndex<[u8]>`
///
/// Arguments:
///
/// * `ty` - The bytelike type to implement the traits on.
/// * `$len` - The number of bytes this type has.
/// * `$reverse` - `true` if the type should be displayed backwards, `false` otherwise.
/// * `$gen: $gent` - generic type(s) and trait bound(s).
#[macro_export]
macro_rules! impl_bytelike_traits {
    ($ty:ident, $len:expr, $reverse:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> $crate::_export::_core::str::FromStr for $ty<$($gen),*> {
            type Err = $crate::hex::HexToArrayError;

            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                use $crate::hex::FromHex;

                let mut bytes = <[u8; $len]>::from_hex(s)?;
                if $reverse {
                    bytes.reverse();
                }
                Ok(Self::from_byte_array(bytes))
            }
        }

        $crate::hex::impl_fmt_traits! {
            #[display_backward($reverse)]
            impl<$($gen: $gent),*> fmt_traits for $ty<$($gen),*> {
                const LENGTH: usize = $len;
            }
        }

        $crate::serde_impl!($ty, $len $(, $gen: $gent)*);

        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8; $len]> for $ty<$($gen),*> {
            #[inline]
            fn as_ref(&self) -> &[u8; $len] { self.as_byte_array() }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8]> for $ty<$($gen),*> {
            #[inline]
            fn as_ref(&self) -> &[u8] { &self[..] }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::borrow::Borrow<[u8]> for $ty<$($gen),*>  {
            fn borrow(&self) -> &[u8] {  &self[..] }
        }

        impl<I: $crate::_export::_core::slice::SliceIndex<[u8]> $(, $gen: $gent)*>
            $crate::_export::_core::ops::Index<I> for $ty<$($gen),*> {
            type Output = I::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }
    }
}

// Extracts `hash_newtype(forward)` and `hash_newtype(backward)` attributes if any and turns them
// into bool, defaulting to `DISPLAY_BACKWARD` of the wrapped type if the attribute is omitted.
//
// Once an appropriate attribute is found we pass the remaining ones into another macro to detect
// duplicates/conflicts and report an error.
//
// FYI, no, we can't use a helper macro to first filter all `hash_newtype` attributes. We would be
// attempting to match on macros instead. So we must write `hashe_newtype` in each branch.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_get_direction {
    (sha256d, ) => { true };
    (hash160, ) => { false };
    ($_newtype:ident, ) => { false };
    ($hash:ident, #[hash_newtype(forward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(forward, $($others)*); false } };
    ($hash:ident, #[hash_newtype(backward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(backward, $($others)*); true } };
    ($hash:ident, #[$($ignore:tt)*]  $($others:tt)*) => { $crate::hash_newtype_get_direction!($hash, $($others)*) };
}

// Reports an error if any of the attributes is `hash_newtype($direction)`.
//
// This is used for detection of duplicates/conflicts, see the macro above.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_forbid_direction {
    ($direction:ident, ) => {};
    ($direction:ident, #[hash_newtype(forward)] $(others:tt)*) => {
        compile_error!(concat!("Cannot set display direction to forward: ", stringify!($direction), " was already specified"));
    };
    ($direction:ident, #[hash_newtype(backward)] $(others:tt)*) => {
        compile_error!(concat!("Cannot set display direction to backward: ", stringify!($direction), " was already specified"));
    };
    ($direction:ident, #[$($ignore:tt)*] $(#[$others:tt])*) => {
        $crate::hash_newtype_forbid_direction!($direction, $(#[$others])*)
    };
}

// Checks (at compile time) that all `hash_newtype` attributes are known.
//
// An unknown attribute could be a typo that could cause problems - e.g. wrong display direction if
// it's missing. To prevent this, we call this macro above. The macro produces nothing unless an
// unknown attribute is found in which case it produces `compile_error!`.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_known_attrs {
    (#[hash_newtype(forward)]) => {};
    (#[hash_newtype(backward)]) => {};
    (#[hash_newtype($($unknown:tt)*)]) => { compile_error!(concat!("Unrecognized attribute ", stringify!($($unknown)*))); };
    ($($ignore:tt)*) => {};
}

#[cfg(test)]
mod test {
    use crate::{hash160, sha256, sha256d, HashEngine};

    #[test]
    fn hash_as_ref_array() {
        let hash = sha256::Hash::hash(&[3, 50]);
        let r = AsRef::<[u8; 32]>::as_ref(&hash);
        assert_eq!(r, hash.as_byte_array());
    }

    #[test]
    fn hash_as_ref_slice() {
        let hash = sha256::Hash::hash(&[3, 50]);
        let r = AsRef::<[u8]>::as_ref(&hash);
        assert_eq!(r, hash.as_byte_array());
    }

    hash_newtype! {
        /// Test hash engine.
        struct TestHashEngine(sha256d);

        /// Test hash.
        struct TestHash(_);
    }

    #[test]
    fn test_hash_engine() {
        let mut engine = TestHashEngine::new();
        engine.input(&[]);
    }

    #[test]
    fn display() {
        let want = "0000000000000000000000000000000000000000000000000000000000000000";
        let got = format!("{}", TestHash::all_zeros());
        assert_eq!(got, want)
    }

    #[test]
    fn display_alternate() {
        let want = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let got = format!("{:#}", TestHash::all_zeros());
        assert_eq!(got, want)
    }

    #[test]
    fn lower_hex() {
        let want = "0000000000000000000000000000000000000000000000000000000000000000";
        let got = format!("{:x}", TestHash::all_zeros());
        assert_eq!(got, want)
    }

    #[test]
    fn lower_hex_alternate() {
        let want = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let got = format!("{:#x}", TestHash::all_zeros());
        assert_eq!(got, want)
    }

    #[test]
    fn inner_hash_as_ref_array() {
        let hash = TestHash::all_zeros();
        let r = AsRef::<[u8; 32]>::as_ref(&hash);
        assert_eq!(r, hash.as_byte_array());
    }

    #[test]
    fn inner_hash_as_ref_slice() {
        let hash = TestHash::all_zeros();
        let r = AsRef::<[u8]>::as_ref(&hash);
        assert_eq!(r, hash.as_byte_array());
    }

    #[test]
    fn hash_borrow() {
        use core::borrow::Borrow;

        let hash = sha256::Hash::hash(&[3, 50]);
        let borrowed: &[u8] = hash.borrow();
        assert_eq!(borrowed, hash.as_byte_array());
    }

    hash_newtype! {
        /// Test hash engine.
        struct TestHashBackwardEngine(sha256d);

        /// Test hash.
        #[hash_newtype(backward)]
        struct TestHashBackward(_);
    }

    #[test]
    fn display_backward() {
        let want = "0x9a538906e6466ebd2617d321f71bc94e56056ce213d366773699e28158e00614";
        let got = format!("{:#x}", TestHashBackward::hash(&[0]));
        assert_eq!(got, want)
    }

    hash_newtype! {
        /// Test hash engine.
        struct TestHashForwardEngine(sha256d);

        /// Test hash.
        #[hash_newtype(forward)]
        struct TestHashForward(_);
    }

    #[test]
    fn display_forward() {
        let want = "0x1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a";
        let got = format!("{:#x}", TestHashForward::hash(&[0]));
        assert_eq!(got, want)
    }

    hash_newtype! {
        /// Test a hash from this crate.
        struct TestHashEngine160(hash160);

        /// Test a hash from this crate.
        struct TestHash160(_);
    }

    #[test]
    fn wrap_hash160() {
        let want = "0x9f7fd096d37ed2c0e3f7f0cfc924beef4ffceb68";
        let got = format!("{:#x}", TestHash160::hash(&[0]));
        assert_eq!(got, want)
    }
}
