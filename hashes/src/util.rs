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
    ($ty:ident) => (
        $crate::hex_fmt_impl!($ty, );
    );
    ($ty:ident, $($gen:ident: $gent:ident),*) => (
        impl<$($gen: $gent),*> $crate::_export::_core::fmt::LowerHex for $ty<$($gen),*> {
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                #[allow(unused_imports)]
                use $crate::{Hash as _, HashEngine as _, hex};

                if f.alternate() {
                    write!(f, "0x")?;
                }
                if $ty::<$($gen),*>::DISPLAY_BACKWARD {
                    hex::format_hex_reverse(self.as_ref(), f)
                } else {
                    hex::format_hex(self.as_ref(), f)
                }
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Display for $ty<$($gen),*> {
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::_export::_core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Debug for $ty<$($gen),*> {
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
#[macro_export]
macro_rules! hash_newtype {
    ($newtype:ident, $hash:ty, $len:expr, $docs:meta) => {
        $crate::hash_newtype!($newtype, $hash, $len, $docs, <$hash as $crate::Hash>::DISPLAY_BACKWARD);
    };
    ($newtype:ident, $hash:ty, $len:expr, $docs:meta, $reverse:expr) => {
        #[$docs]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $newtype($hash);

        $crate::hex_fmt_impl!($newtype);
        $crate::serde_impl!($newtype, $len);
        $crate::borrow_slice_impl!($newtype);

        impl $newtype {
            /// Creates this type from the inner hash type.
            pub fn from_hash(inner: $hash) -> $newtype {
                $newtype(inner)
            }

            /// Converts this type into the inner hash type.
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
            const DISPLAY_BACKWARD: bool = $reverse;

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
                $crate::hex::FromHex::from_hex(s)
            }
        }

        impl<I: $crate::_export::_core::slice::SliceIndex<[u8]>> $crate::_export::_core::ops::Index<I> for $newtype {
            type Output = I::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output {
                &self.0[index]
            }
        }
    };
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
    fn hash_as_ref() {
        let hash = sha256::Hash::hash(&[3, 50]);
        assert_eq!(hash.as_ref(), hash.as_inner());
    }

    #[test]
    fn hash_borrow() {
        use core::borrow::Borrow;

        let hash = sha256::Hash::hash(&[3, 50]);
        let borrowed: &[u8] = hash.borrow();
        assert_eq!(borrowed, hash.as_inner());
    }

    hash_newtype!(TestHash, crate::sha256d::Hash, 32, doc="Test hash.");

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
}
