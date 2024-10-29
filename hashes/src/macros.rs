// SPDX-License-Identifier: CC0-1.0

//! Public macros.

#[macro_export]
/// Adds hexadecimal formatting implementation of a trait `$imp` to a given type `$ty`.
macro_rules! hex_fmt_impl(
    ($reverse:expr, $len:expr, $ty:ident) => (
        $crate::hex_fmt_impl!($reverse, $len, $ty, );
    );
    ($reverse:expr, $len:expr, $ty:ident, $($gen:ident: $gent:ident),*) => (
        impl<$($gen: $gent),*> $crate::_export::_core::fmt::LowerHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                if $reverse {
                    $crate::hex::fmt_hex_exact!(f, $len, <Self as $crate::Hash>::as_byte_array(&self).iter().rev(), $crate::hex::Case::Lower)
                } else {
                    $crate::hex::fmt_hex_exact!(f, $len, <Self as $crate::Hash>::as_byte_array(&self), $crate::hex::Case::Lower)
                }
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::UpperHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                if $reverse {
                    $crate::hex::fmt_hex_exact!(f, $len, <Self as $crate::Hash>::as_byte_array(&self).iter().rev(), $crate::hex::Case::Upper)
                } else {
                    $crate::hex::fmt_hex_exact!(f, $len, <Self as $crate::Hash>::as_byte_array(&self), $crate::hex::Case::Upper)
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
                write!(f, "{}", self)
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
                self.as_byte_array()
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8]> for $ty<$($gen),*>  {
            fn as_ref(&self) -> &[u8] {
                self.as_byte_array()
            }
        }
    )
);

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
/// You can use any valid visibility specifier in place of `pub` or you can omit either or both, if
/// you want the type or its field to be private.
///
/// Whether the hash is reversed or not when displaying depends on the inner type. However you can
/// override it like this:
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
/// `Serialize` and `Deserialize` implementations.
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
///
/// Note: the macro is internally recursive. If you use too many attributes (> 256 tokens) you may
/// hit recursion limit. If you have so many attributes for a good reason, just raising the limit
/// should be OK. Note however that attribute-processing part has to use [TT muncher] which has
/// quadratic complexity, so having many attributes may blow up compile time. This should be rare.
///
/// [TT muncher]: https://danielkeep.github.io/tlborm/book/pat-incremental-tt-munchers.html
///
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
    ($($(#[$($type_attrs:tt)*])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:tt])* $field_vis:vis $hash:path);)+) => {
        $(
        $($crate::hash_newtype_known_attrs!(#[ $($type_attrs)* ]);)*

        $crate::hash_newtype_struct! {
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $({ $($type_attrs)* })*
        }

        $crate::hex_fmt_impl!(<$newtype as $crate::Hash>::DISPLAY_BACKWARD, <$newtype as $crate::Hash>::LEN, $newtype);
        $crate::serde_impl!($newtype, { <$newtype as $crate::Hash>::LEN });
        $crate::borrow_slice_impl!($newtype);

        #[allow(unused)] // Private wrapper types may not need all functions.
        impl $newtype {
            /// Constructs a hash from the underlying byte array.
            pub const fn from_byte_array(bytes: <$hash as $crate::Hash>::Bytes) -> Self {
                $newtype(<$hash>::from_byte_array(bytes))
            }

            /// Copies a byte slice into a hash object.
            #[deprecated(since = "TBD", note = "use `from_byte_array` instead")]
            #[allow(deprecated_in_future)]
            pub fn from_slice(sl: &[u8]) -> $crate::_export::_core::result::Result<$newtype, $crate::FromSliceError> {
                Ok($newtype(<$hash as $crate::Hash>::from_slice(sl)?))
            }

            /// Returns the underlying byte array.
            pub const fn to_byte_array(self) -> <$hash as $crate::Hash>::Bytes {
                self.0.to_byte_array()
            }

            /// Returns a reference to the underlying byte array.
            pub const fn as_byte_array(&self) -> &<$hash as $crate::Hash>::Bytes {
                self.0.as_byte_array()
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
            type Bytes = <$hash as $crate::Hash>::Bytes;

            const DISPLAY_BACKWARD: bool = $crate::hash_newtype_get_direction!($hash, $(#[$($type_attrs)*])*);

            fn from_byte_array(bytes: Self::Bytes) -> Self { Self::from_byte_array(bytes) }

            #[inline]
            #[allow(deprecated_in_future)]
            fn from_slice(sl: &[u8]) -> $crate::_export::_core::result::Result<$newtype, $crate::FromSliceError> {
                Self::from_slice(sl)
            }

            fn to_byte_array(self) -> Self::Bytes { self.to_byte_array() }

            fn as_byte_array(&self) -> &Self::Bytes { self.as_byte_array() }
        }

        impl $crate::_export::_core::str::FromStr for $newtype {
            type Err = $crate::hex::HexToArrayError;
            fn from_str(s: &str) -> $crate::_export::_core::result::Result<$newtype, Self::Err> {
                use $crate::{hex::FromHex};

                let mut bytes = <[u8; <Self as $crate::Hash>::LEN]>::from_hex(s)?;
                if <Self as $crate::Hash>::DISPLAY_BACKWARD {
                    bytes.reverse();
                };
                Ok($newtype(<$hash>::from_byte_array(bytes)))
            }
        }

        impl $crate::_export::_core::convert::AsRef<[u8; <$hash as $crate::Hash>::LEN]> for $newtype {
            fn as_ref(&self) -> &[u8; <$hash as $crate::Hash>::LEN] {
                AsRef::<[u8; <$hash as $crate::Hash>::LEN]>::as_ref(&self.0)
            }
        }
        )+
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
    ($hash:ty, ) => { <$hash as $crate::Hash>::DISPLAY_BACKWARD };
    ($hash:ty, #[hash_newtype(forward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(forward, $($others)*); false } };
    ($hash:ty, #[hash_newtype(backward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(backward, $($others)*); true } };
    ($hash:ty, #[$($ignore:tt)*]  $($others:tt)*) => { $crate::hash_newtype_get_direction!($hash, $($others)*) };
}

// Reports an error if any of the attributes is `hash_newtype($direction)`.
//
// This is used for detection of duplicates/conflicts, see the macro above.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_forbid_direction {
    ($direction:ident, ) => {};
    ($direction:ident, #[hash_newtype(forward)] $(others:tt)*) => {
        compile_error!(concat!("cannot set display direction to forward: ", stringify!($direction), " was already specified"));
    };
    ($direction:ident, #[hash_newtype(backward)] $(others:tt)*) => {
        compile_error!(concat!("cannot set display direction to backward: ", stringify!($direction), " was already specified"));
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
    (#[hash_newtype($($unknown:tt)*)]) => { compile_error!(concat!("unrecognized attribute ", stringify!($($unknown)*))); };
    ($($ignore:tt)*) => {};
}

/// Functions used by serde impls of all hashes.
#[cfg(feature = "serde")]
pub mod serde_details {
    use core::marker::PhantomData;
    use core::str::FromStr;
    use core::{fmt, str};

    use serde::de;

    /// Type used to implement serde traits for hashes as hex strings.
    pub struct HexVisitor<ValueT>(PhantomData<ValueT>);

    impl<ValueT> Default for HexVisitor<ValueT> {
        fn default() -> Self { Self(PhantomData) }
    }

    impl<ValueT> de::Visitor<'_> for HexVisitor<ValueT>
    where
        ValueT: FromStr,
        <ValueT as FromStr>::Err: fmt::Display,
    {
        type Value = ValueT;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an ASCII hex string")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            if let Ok(hex) = str::from_utf8(v) {
                hex.parse::<Self::Value>().map_err(E::custom)
            } else {
                Err(E::invalid_value(de::Unexpected::Bytes(v), &self))
            }
        }

        fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse::<Self::Value>().map_err(E::custom)
        }
    }

    /// Type used to implement serde traits for hashes as bytes.
    pub struct BytesVisitor<ValueT, const N: usize>(PhantomData<ValueT>);

    impl<ValueT, const N: usize> Default for BytesVisitor<ValueT, N> {
        fn default() -> Self { Self(PhantomData) }
    }

    impl<ValueT, const N: usize> de::Visitor<'_> for BytesVisitor<ValueT, N>
    where
        ValueT: crate::Hash,
        ValueT: crate::Hash<Bytes = [u8; N]>,
    {
        type Value = ValueT;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a bytestring")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = <[u8; N]>::try_from(v).map_err(|_| {
                // from_slice only errors on incorrect length
                E::invalid_length(v.len(), &stringify!(N))
            })?;

            Ok(<Self::Value as crate::Hash>::from_byte_array(bytes))
        }
    }
}

/// Implements `Serialize` and `Deserialize` for a type `$t` which
/// represents a newtype over a byte-slice over length `$len`.
#[macro_export]
#[cfg(feature = "serde")]
macro_rules! serde_impl(
    ($t:ident, $len:expr $(, $gen:ident: $gent:ident)*) => (
        impl<$($gen: $gent),*> $crate::serde::Serialize for $t<$($gen),*> {
            fn serialize<S: $crate::serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    s.serialize_bytes(<Self as $crate::Hash>::as_byte_array(self))
                }
            }
        }

        impl<'de $(, $gen: $gent)*> $crate::serde::Deserialize<'de> for $t<$($gen),*> {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(d: D) -> core::result::Result<$t<$($gen),*>, D::Error> {
                use $crate::serde_macros::serde_details::{BytesVisitor, HexVisitor};

                if d.is_human_readable() {
                    d.deserialize_str(HexVisitor::<Self>::default())
                } else {
                    d.deserialize_bytes(BytesVisitor::<Self, $len>::default())
                }
            }
        }
));

/// Does an "empty" serde implementation for the configuration without serde feature.
#[macro_export]
#[cfg(not(feature = "serde"))]
macro_rules! serde_impl(
        ($t:ident, $len:expr $(, $gen:ident: $gent:ident)*) => ()
);

#[cfg(test)]
mod test {
    use crate::sha256;

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

    #[test]
    fn hash_borrow() {
        use core::borrow::Borrow;

        let hash = sha256::Hash::hash(&[3, 50]);
        let borrowed: &[u8] = hash.borrow();
        assert_eq!(borrowed, hash.as_byte_array());
    }

    hash_newtype! {
        /// Test hash.
        struct TestHash(crate::sha256d::Hash);
    }

    impl TestHash {
        fn all_zeros() -> Self { Self::from_byte_array([0; 32]) }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn display() {
        use alloc::format;

        let want = "0000000000000000000000000000000000000000000000000000000000000000";
        let got = format!("{}", TestHash::all_zeros());
        assert_eq!(got, want)
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn display_alternate() {
        use alloc::format;

        let want = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let got = format!("{:#}", TestHash::all_zeros());
        assert_eq!(got, want)
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn lower_hex() {
        use alloc::format;

        let want = "0000000000000000000000000000000000000000000000000000000000000000";
        let got = format!("{:x}", TestHash::all_zeros());
        assert_eq!(got, want)
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn lower_hex_alternate() {
        use alloc::format;

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
}
