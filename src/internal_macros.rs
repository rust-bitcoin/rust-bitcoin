// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Internal Macros
//!
//! Macros meant to be used inside the Rust Bitcoin library

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl<S: ::consensus::encode::Encoder> ::consensus::encode::Encodable<S> for $thing {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), ::consensus::encode::Error> {
                $( self.$field.consensus_encode(s)?; )+
                Ok(())
            }
        }

        impl<D: ::consensus::encode::Decoder> ::consensus::encode::Decodable<D> for $thing {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<$thing, ::consensus::encode::Error> {
                use consensus::encode::Decodable;
                Ok($thing {
                    $( $field: Decodable::consensus_decode(d)?, )+
                })
            }
        }
    );
}

macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:expr) => {
        impl $thing {
            #[inline]
            /// Converts the object to a raw pointer
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            #[inline]
            /// Converts the object to a mutable raw pointer
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            #[inline]
            /// Returns the length of the object as an array
            pub fn len(&self) -> usize { $len }

            #[inline]
            /// Returns whether the object, as an array, is empty. Always false.
            pub fn is_empty(&self) -> bool { false }

            #[inline]
            /// Returns the underlying bytes.
            pub fn as_bytes(&self) -> &[$ty; $len] { &self.0 }

            #[inline]
            /// Returns the underlying bytes.
            pub fn to_bytes(&self) -> [$ty; $len] { self.0.clone() }

            #[inline]
            /// Returns the underlying bytes.
            pub fn into_bytes(self) -> [$ty; $len] { self.0 }
        }

        impl<'a> From<&'a [$ty]> for $thing {
            fn from(data: &'a [$ty]) -> $thing {
                assert_eq!(data.len(), $len);
                let mut ret = [0; $len];
                ret.copy_from_slice(&data[..]);
                $thing(ret)
            }
        }

        impl ::std::ops::Index<usize> for $thing {
            type Output = $ty;

            #[inline]
            fn index(&self, index: usize) -> &$ty {
                let &$thing(ref dat) = self;
                &dat[index]
            }
        }

        impl_index_newtype!($thing, $ty);

        impl PartialEq for $thing {
            #[inline]
            fn eq(&self, other: &$thing) -> bool {
                &self[..] == &other[..]
            }
        }

        impl Eq for $thing {}

        impl PartialOrd for $thing {
            #[inline]
            fn partial_cmp(&self, other: &$thing) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(&other))
            }
        }

        impl Ord for $thing {
            #[inline]
            fn cmp(&self, other: &$thing) -> ::std::cmp::Ordering {
                // manually implement comparison to get little-endian ordering
                // (we need this for our numeric types; non-numeric ones shouldn't
                // be ordered anyway except to put them in BTrees or whatever, and
                // they don't care how we order as long as we're consistent).
                for i in 0..$len {
                    if self[$len - 1 - i] < other[$len - 1 - i] { return ::std::cmp::Ordering::Less; }
                    if self[$len - 1 - i] > other[$len - 1 - i] { return ::std::cmp::Ordering::Greater; }
                }
                ::std::cmp::Ordering::Equal
            }
        }

        #[cfg_attr(feature = "clippy", allow(expl_impl_clone_on_copy))] // we don't define the `struct`, we have to explicitly impl
        impl Clone for $thing {
            #[inline]
            fn clone(&self) -> $thing {
                $thing::from(&self[..])
            }
        }

        impl Copy for $thing {}

        impl ::std::hash::Hash for $thing {
            #[inline]
            fn hash<H>(&self, state: &mut H)
                where H: ::std::hash::Hasher
            {
                (&self[..]).hash(state);
            }

            fn hash_slice<H>(data: &[$thing], state: &mut H)
                where H: ::std::hash::Hasher
            {
                for d in data.iter() {
                    (&d[..]).hash(state);
                }
            }
        }

        impl ::rand::Rand for $thing {
            #[inline]
            fn rand<R: ::rand::Rng>(r: &mut R) -> $thing {
                $thing(::rand::Rand::rand(r))
            }
        }
    }
}

macro_rules! impl_array_newtype_encodable {
    ($thing:ident, $ty:ty, $len:expr) => {
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $thing {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::serde::Deserializer<'de>,
            {
                use $crate::std::fmt::{self, Formatter};

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $thing;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a fixed size array")
                    }

                    #[inline]
                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::serde::de::SeqAccess<'de>,
                    {
                        let mut ret: [$ty; $len] = [0; $len];
                        for item in ret.iter_mut() {
                            *item = match seq.next_element()? {
                                Some(c) => c,
                                None => return Err($crate::serde::de::Error::custom("end of stream"))
                            };
                        }
                        Ok($thing(ret))
                    }
                }

                deserializer.deserialize_seq(Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl $crate::serde::Serialize for $thing {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                let &$thing(ref dat) = self;
                (&dat[..]).serialize(serializer)
            }
        }
    }
}

macro_rules! impl_array_newtype_show {
    ($thing:ident) => {
        impl ::std::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, concat!(stringify!($thing), "({:?})"), &self[..])
            }
        }
    }
}

macro_rules! impl_index_newtype {
    ($thing:ident, $ty:ty) => {
        impl ::std::ops::Index<::std::ops::Range<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::Range<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFull> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, _: ::std::ops::RangeFull) -> &[$ty] {
                &self.0[..]
            }
        }

    }
}

macro_rules! display_from_debug {
    ($thing:ident) => {
        impl ::std::fmt::Display for $thing {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
                ::std::fmt::Debug::fmt(self, f)
            }
        }
    }
}

#[cfg(test)]
macro_rules! hex_script (($s:expr) => (::blockdata::script::Script::from(::hex::decode($s).unwrap())));

#[cfg(test)]
macro_rules! hex_hash (($s:expr) => (::bitcoin_hashes::sha256d::Hash::from_slice(&::hex::decode($s).unwrap()).unwrap()));

macro_rules! serde_struct_impl {
    ($name:ident, $($fe:ident),*) => (
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use $crate::std::fmt::{self, Formatter};
                use $crate::serde::de::IgnoredAny;

                #[allow(non_camel_case_types)]
                enum Enum { Unknown__Field, $($fe),* }

                struct EnumVisitor;
                impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                    type Value = Enum;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a field name")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        match v {
                            $(
                            stringify!($fe) => Ok(Enum::$fe)
                            ),*,
                            _ => Ok(Enum::Unknown__Field)
                        }
                    }
                }

                impl<'de> $crate::serde::Deserialize<'de> for Enum {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: ::serde::de::Deserializer<'de>,
                    {
                        deserializer.deserialize_str(EnumVisitor)
                    }
                }

                struct Visitor;

                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a struct")
                    }

                    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::serde::de::MapAccess<'de>,
                    {
                        use $crate::serde::de::Error;

                        $(let mut $fe = None;)*

                        loop {
                            match map.next_key::<Enum>()? {
                                Some(Enum::Unknown__Field) => {
                                    map.next_value::<IgnoredAny>()?;
                                }
                                $(
                                    Some(Enum::$fe) => {
                                        $fe = Some(map.next_value()?);
                                    }
                                )*
                                None => { break; }
                            }
                        }

                        $(
                            let $fe = match $fe {
                                Some(x) => x,
                                None => return Err(A::Error::missing_field(stringify!($fe))),
                            };
                        )*

                        let ret = $name {
                            $($fe: $fe),*
                        };

                        Ok(ret)
                    }
                }
                // end type defs

                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                use $crate::serde::ser::SerializeStruct;

                // Only used to get the struct length.
                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                $(
                    st.serialize_field(stringify!($fe), &self.$fe)?;
                )*

                st.end()
            }
        }
    )
}

macro_rules! user_enum {
    (
        $(#[$attr:meta])*
        pub enum $name:ident {
            $(#[$doc:meta]
              $elem:ident <-> $txt:expr),*
        }
    ) => (
        $(#[$attr])*
        pub enum $name {
            $(#[$doc] $elem),*
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                f.pad(match *self {
                    $($name::$elem => $txt),*
                })
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                f.pad(match *self {
                    $($name::$elem => $txt),*
                })
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = ::std::io::Error;
            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($txt => Ok($name::$elem)),*,
                    _ => Err(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidInput,
                        format!("Unknown network (type {})", s),
                    )),
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::serde::Deserializer<'de>,
            {
                use $crate::std::fmt::{self, Formatter};

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("an enum value")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        static FIELDS: &'static [&'static str] = &[$(stringify!($txt)),*];

                        $( if v == $txt { Ok($name::$elem) } )else*
                        else {
                            Err(E::unknown_variant(v, FIELDS))
                        }
                    }

                    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(v)
                    }

                    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(&v)
                    }

                }

                deserializer.deserialize_str(Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }
    );
}
