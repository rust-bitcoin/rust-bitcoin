// Bitcoin Hashes Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

#[macro_export]
/// Adds hexadecimal formatting implementation of a trait `$imp` to a given type `$ty`.
macro_rules! hex_fmt_impl(
    ($reverse:expr, $ty:ident) => (
        $crate::hex_fmt_impl!($reverse, $ty, );
    );
    ($reverse:expr, $ty:ident, $($gen:ident: $gent:ident),*) => (
        impl<$($gen: $gent),*> $crate::_export::_core::fmt::LowerHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                if $reverse {
                    $crate::_export::_core::fmt::LowerHex::fmt(&self.0.backward_hex(), f)
                } else {
                    $crate::_export::_core::fmt::LowerHex::fmt(&self.0.forward_hex(), f)
                }
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::UpperHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                if $reverse {
                    $crate::_export::_core::fmt::UpperHex::fmt(&self.0.backward_hex(), f)
                } else {
                    $crate::_export::_core::fmt::UpperHex::fmt(&self.0.forward_hex(), f)
                }
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Display for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::_export::_core::fmt::LowerHex::fmt(&self, f)
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Debug for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                write!(f, "{:#}", self)
            }
        }
    );
);

/// Adds slicing traits implementations to a given type `$ty`
#[macro_export]
macro_rules! borrow_slice_impl(
    ($ty:ident) => (
        $crate::borrow_slice_impl!($ty, );
    );
    ($ty:ident, $($gen:ident: $gent:ident),*) => (
        impl<$($gen: $gent),*> $crate::_export::_core::borrow::Borrow<[u8]> for $ty<$($gen),*>  {
            fn borrow(&self) -> &[u8] {
                &self[..]
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8]> for $ty<$($gen),*>  {
            fn as_ref(&self) -> &[u8] {
                &self[..]
            }
        }
    )
);

macro_rules! engine_input_impl(
    () => (
        #[cfg(not(fuzzing))]
        fn input(&mut self, mut inp: &[u8]) {
            while !inp.is_empty() {
                let buf_idx = self.length % <Self as crate::HashEngine>::BLOCK_SIZE;
                let rem_len = <Self as crate::HashEngine>::BLOCK_SIZE - buf_idx;
                let write_len = cmp::min(rem_len, inp.len());

                self.buffer[buf_idx..buf_idx + write_len]
                    .copy_from_slice(&inp[..write_len]);
                self.length += write_len;
                if self.length % <Self as crate::HashEngine>::BLOCK_SIZE == 0 {
                    self.process_block();
                }
                inp = &inp[write_len..];
            }
        }

        #[cfg(fuzzing)]
        fn input(&mut self, inp: &[u8]) {
            for c in inp {
                self.buffer[0] ^= *c;
            }
            self.length += inp.len();
        }
    )
);



/// Creates a new newtype around a [`Hash`] type.
///
/// The syntax is similar to the usual tuple struct syntax:
///
/// ```
/// # use bitcoin_hashes::{hash_newtype, sha256};
/// hash_newtype! {
///     /// Hash of `Foo`.
///     pub struct MyNewtype(pub sha256::Hash);
/// }
/// ```
///
/// You can use any valid visibility specifier in place of `pub` or you can leave it out if you
/// don't want the type or its field to be private.
///
/// Whether the hash is reversed or not depends on the inner type. However you can override it like
/// this:
///
/// ```
/// # use bitcoin_hashes::{hash_newtype, sha256};
/// hash_newtype! {
///     #[hash_newtype(backward)]
///     struct MyNewtype(sha256::Hash);
/// }
/// ```
///
/// This will display the hash backwards regardless of what the inner type does. Use `forward`
/// instead of `backward` to force displaying forward.
///
/// You can add arbitrary doc comments or other attributes to the struct or it's field. Note that
/// the macro already derives [`Copy`], [`Clone`], [`Eq`], [`PartialEq`],
/// [`Hash`](core::hash::Hash), [`Ord`], [`PartialOrd`]. With the `serde` feature on, this also adds
/// [`Serialize`](serde::Serialize) and [`Deserialize](serde::Deserialize) implementations.
///
/// You can also define multiple newtypes within one macro call:
///
/// ```
/// # use bitcoin_hashes::{hash_newtype, sha256, hash160};
///
/// hash_newtype! {
///     /// My custom type 1
///     pub struct Newtype1(sha256::Hash);
///
///     /// My custom type 2
///     struct Newtype2(hash160::Hash);
/// }
/// ```
#[macro_export]
macro_rules! hash_newtype {
    ($($(#[$($type_attrs:tt)*])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:tt])* $field_vis:vis $hash:path);)+) => {
        $(
        $($crate::hash_newtype_known_attrs!(#[ $($type_attrs)* ]);)*

        $crate::hash_newtype_struct! {
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $({ $($type_attrs)* })*
        }

        $crate::hex_fmt_impl!(<$newtype as $crate::Hash>::DISPLAY_BACKWARD, $newtype);
        $crate::serde_impl!($newtype, <$newtype as $crate::Hash>::LEN);
        $crate::borrow_slice_impl!($newtype);

        impl $newtype {
            /// Creates this type from the inner hash type.
            #[allow(unused)] // the user of macro may not need this
            pub fn from_hash(inner: $hash) -> $newtype {
                $newtype(inner)
            }

            /// Converts this type into the inner hash type.
            #[allow(unused)] // the user of macro may not need this
            pub fn as_hash(&self) -> $hash {
                // Hashes implement Copy so don't need into_hash.
                self.0
            }
        }

        impl $crate::_export::_core::convert::From<$hash> for $newtype {
            fn from(inner: $hash) -> $newtype {
                // Due to rust 1.22 we have to use this instead of simple `Self(inner)`
                Self { 0: inner }
            }
        }

        impl $crate::_export::_core::convert::From<$newtype> for $hash {
            fn from(hashtype: $newtype) -> $hash {
                hashtype.0
            }
        }

        impl $crate::Hash for $newtype {
            type Engine = <$hash as $crate::Hash>::Engine;
            type Inner = <$hash as $crate::Hash>::Inner;

            const LEN: usize = <$hash as $crate::Hash>::LEN;
            const DISPLAY_BACKWARD: bool = $crate::hash_newtype_get_direction!($hash, $(#[$($type_attrs)*])*);

            fn engine() -> Self::Engine {
                <$hash as $crate::Hash>::engine()
            }

            fn from_engine(e: Self::Engine) -> Self {
                Self::from(<$hash as $crate::Hash>::from_engine(e))
            }

            #[inline]
            fn from_slice(sl: &[u8]) -> Result<$newtype, $crate::Error> {
                Ok($newtype(<$hash as $crate::Hash>::from_slice(sl)?))
            }

            #[inline]
            fn from_inner(inner: Self::Inner) -> Self {
                $newtype(<$hash as $crate::Hash>::from_inner(inner))
            }

            #[inline]
            fn into_inner(self) -> Self::Inner {
                self.0.into_inner()
            }

            #[inline]
            fn as_inner(&self) -> &Self::Inner {
                self.0.as_inner()
            }

            #[inline]
            fn all_zeros() -> Self {
                let zeros = <$hash>::all_zeros();
                $newtype(zeros)
            }
        }

        impl $crate::_export::_core::str::FromStr for $newtype {
            type Err = $crate::hex::Error;
            fn from_str(s: &str) -> $crate::_export::_core::result::Result<$newtype, Self::Err> {
                use $crate::hex::{HexIterator, FromHex};
                use $crate::Hash;

                let inner: <$hash as Hash>::Inner = if <Self as $crate::Hash>::DISPLAY_BACKWARD {
                    FromHex::from_byte_iter(HexIterator::new(s)?.rev())?
                } else {
                    FromHex::from_byte_iter(HexIterator::new(s)?)?
                };
                Ok($newtype(<$hash>::from_inner(inner)))
            }
        }

        impl $crate::_export::_core::convert::AsRef<[u8; <$hash as $crate::Hash>::LEN]> for $newtype {
            fn as_ref(&self) -> &[u8; <$hash as $crate::Hash>::LEN] {
                AsRef::<[u8; <$hash as $crate::Hash>::LEN]>::as_ref(&self.0)
            }
        }

        impl<I: $crate::_export::_core::slice::SliceIndex<[u8]>> $crate::_export::_core::ops::Index<I> for $newtype {
            type Output = I::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output {
                &self.0[index]
            }
        }
        )+
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_struct {
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path);) => {
        $(#[$other_attrs])*
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_our_attrs {
    (hash_newtype($($attr:tt)*)) => { $($attr)* };
    ($($ignore:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_get_direction {
    ($hash:ty, ) => { <$hash as $crate::Hash>::DISPLAY_BACKWARD };
    ($hash:ty, #[hash_newtype(forward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(forward, $($others)*); false } };
    ($hash:ty, #[hash_newtype(backward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(backward, $($others)*); true } };
    ($hash:ty, #[$($ignore:tt)*]  $($others:tt)*) => { $crate::hash_newtype_get_direction!($hash, $($others)*) };
}

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

#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_known_attrs {
    (#[hash_newtype(forward)]) => {};
    (#[hash_newtype(backward)]) => {};
    (#[hash_newtype($($unknown:tt)*)]) => { compile_error!(concat!("Unrecognized attribute ", stringify!($($unknown)*))); };
    ($($ignore:tt)*) => {};
}

#[cfg(feature = "schemars")]
#[cfg_attr(docsrs, doc(cfg(feature = "schemars")))]
pub mod json_hex_string {
    use schemars::schema::{Schema, SchemaObject};
    use schemars::{gen::SchemaGenerator, JsonSchema};
    macro_rules! define_custom_hex {
        ($name:ident, $len:expr) => {
            pub fn $name(gen: &mut SchemaGenerator) -> Schema {
                let mut schema: SchemaObject = <String>::json_schema(gen).into();
                schema.string = Some(Box::new(schemars::schema::StringValidation {
                    max_length: Some($len * 2),
                    min_length: Some($len * 2),
                    pattern: Some("[0-9a-fA-F]+".to_owned()),
                }));
                schema.into()
            }
        };
    }
    define_custom_hex!(len_8, 8);
    define_custom_hex!(len_20, 20);
    define_custom_hex!(len_32, 32);
    define_custom_hex!(len_64, 64);
}

#[cfg(test)]
mod test {
    use crate::{Hash, sha256};

    #[test]
    fn hash_as_ref_array() {
        let hash = sha256::Hash::hash(&[3, 50]);
        let r = AsRef::<[u8; 32]>::as_ref(&hash);
        assert_eq!(r, hash.as_inner());
    }

    #[test]
    fn hash_as_ref_slice() {
        let hash = sha256::Hash::hash(&[3, 50]);
        let r = AsRef::<[u8]>::as_ref(&hash);
        assert_eq!(r, hash.as_inner());
    }

    #[test]
    fn hash_borrow() {
        use core::borrow::Borrow;

        let hash = sha256::Hash::hash(&[3, 50]);
        let borrowed: &[u8] = hash.borrow();
        assert_eq!(borrowed, hash.as_inner());
    }

    hash_newtype! {
        /// Test hash.
        struct TestHash(crate::sha256d::Hash);
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
        assert_eq!(r, hash.as_inner());
    }

    #[test]
    fn inner_hash_as_ref_slice() {
        let hash = TestHash::all_zeros();
        let r = AsRef::<[u8]>::as_ref(&hash);
        assert_eq!(r, hash.as_inner());
    }
}
