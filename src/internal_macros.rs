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
        impl $crate::consensus::Encodable for $thing {
            #[inline]
            fn consensus_encode<S: $crate::io::Write>(
                &self,
                mut s: S,
            ) -> Result<usize, $crate::io::Error> {
                let mut len = 0;
                $(len += self.$field.consensus_encode(&mut s)?;)+
                Ok(len)
            }
        }

        impl $crate::consensus::Decodable for $thing {
            #[inline]
            fn consensus_decode<D: $crate::io::Read>(
                d: D,
            ) -> Result<$thing, $crate::consensus::encode::Error> {
                let mut d = d.take($crate::consensus::encode::MAX_VEC_SIZE as u64);
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode(&mut d)?),+
                })
            }
        }
    );
}

/// Implements standard array methods for a given wrapper type
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

        impl<'a> ::core::convert::From<&'a [$ty]> for $thing {
            fn from(data: &'a [$ty]) -> $thing {
                assert_eq!(data.len(), $len);
                let mut ret = [0; $len];
                ret.copy_from_slice(&data[..]);
                $thing(ret)
            }
        }

        impl_index_newtype!($thing, $ty);
    }
}

/// Implements standard indexing methods for a given wrapper type
macro_rules! impl_index_newtype {
    ($thing:ident, $ty:ty) => {

        impl ::core::ops::Index<usize> for $thing {
            type Output = $ty;

            #[inline]
            fn index(&self, index: usize) -> &$ty {
                &self.0[index]
            }
        }

        impl ::core::ops::Index<::core::ops::Range<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::core::ops::Range<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::core::ops::Index<::core::ops::RangeTo<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::core::ops::RangeTo<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::core::ops::Index<::core::ops::RangeFrom<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::core::ops::RangeFrom<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::core::ops::Index<::core::ops::RangeFull> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, _: ::core::ops::RangeFull) -> &[$ty] {
                &self.0[..]
            }
        }

    }
}

macro_rules! display_from_debug {
    ($thing:ident) => {
        impl ::core::fmt::Display for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
                ::core::fmt::Debug::fmt(self, f)
            }
        }
    }
}

#[cfg(test)]
macro_rules! hex_script (($s:expr) => (<$crate::Script as ::core::str::FromStr>::from_str($s).unwrap()));

#[cfg(test)]
macro_rules! hex_hash (($h:ident, $s:expr) => ($h::from_slice(&<$crate::prelude::Vec<u8> as $crate::hashes::hex::FromHex>::from_hex($s).unwrap()).unwrap()));

macro_rules! serde_string_impl {
    ($name:ident, $expecting:expr) => {
        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use ::core::fmt::{self, Formatter};
                use ::core::str::FromStr;

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        $name::from_str(v).map_err(E::custom)
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
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    };
}

/// A combination macro where the human-readable serialization is done like
/// serde_string_impl and the non-human-readable impl is done as a struct.
macro_rules! serde_struct_human_string_impl {
    ($name:ident, $expecting:expr, $($fe:ident),*) => (
        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    use ::core::fmt::{self, Formatter};
                    use ::core::str::FromStr;

                    struct Visitor;
                    impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                        type Value = $name;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str($expecting)
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            $name::from_str(v).map_err(E::custom)
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
                } else {
                    use ::core::fmt::{self, Formatter};
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
                            D: $crate::serde::de::Deserializer<'de>,
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

                        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
                        where
                            V: $crate::serde::de::SeqAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            let length = 0;
                            $(
                                let $fe = seq.next_element()?.ok_or_else(|| {
                                    Error::invalid_length(length, &self)
                                })?;
                                #[allow(unused_variables)]
                                let length = length + 1;
                            )*

                            let ret = $name {
                                $($fe: $fe),*
                            };

                            Ok(ret)
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
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.collect_str(&self)
                } else {
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
        }
    )
}

/// Implements several traits for byte-based newtypes.
/// Implements:
/// - core::fmt::LowerHex (implies hashes::hex::ToHex)
/// - core::fmt::Display
/// - core::str::FromStr
/// - hashes::hex::FromHex
macro_rules! impl_bytes_newtype {
    ($t:ident, $len:expr) => (

        impl ::core::fmt::LowerHex for $t {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                for &ch in self.0.iter() {
                    write!(f, "{:02x}", ch)?;
                }
                Ok(())
            }
        }

        impl ::core::fmt::Display for $t {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                fmt::LowerHex::fmt(self, f)
            }
        }

        impl ::core::fmt::Debug for $t {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                fmt::LowerHex::fmt(self, f)
            }
        }

        impl $crate::hashes::hex::FromHex for $t {
            fn from_byte_iter<I>(iter: I) -> Result<Self, $crate::hashes::hex::Error>
                where I: ::core::iter::Iterator<Item=Result<u8, $crate::hashes::hex::Error>> +
                    ::core::iter::ExactSizeIterator +
                    ::core::iter::DoubleEndedIterator,
            {
                if iter.len() == $len {
                    let mut ret = [0; $len];
                    for (n, byte) in iter.enumerate() {
                        ret[n] = byte?;
                    }
                    Ok($t(ret))
                } else {
                    Err($crate::hashes::hex::Error::InvalidLength(2 * $len, 2 * iter.len()))
                }
            }
        }

        impl ::core::str::FromStr for $t {
            type Err = $crate::hashes::hex::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::hashes::hex::FromHex::from_hex(s)
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl $crate::serde::Serialize for $t {
            fn serialize<S: $crate::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.serialize_str(&$crate::hashes::hex::ToHex::to_hex(self))
                } else {
                    s.serialize_bytes(&self[..])
                }
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de> $crate::serde::Deserialize<'de> for $t {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(d: D) -> Result<$t, D::Error> {
                if d.is_human_readable() {
                    struct HexVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for HexVisitor {
                        type Value = $t;

                        fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                            formatter.write_str("an ASCII hex string")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            if let Ok(hex) = ::core::str::from_utf8(v) {
                                $crate::hashes::hex::FromHex::from_hex(hex).map_err(E::custom)
                            } else {
                                return Err(E::invalid_value($crate::serde::de::Unexpected::Bytes(v), &self));
                            }
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            $crate::hashes::hex::FromHex::from_hex(v).map_err(E::custom)
                        }
                    }

                    d.deserialize_str(HexVisitor)
                } else {
                    struct BytesVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for BytesVisitor {
                        type Value = $t;

                        fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                            formatter.write_str("a bytestring")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            if v.len() != $len {
                                Err(E::invalid_length(v.len(), &stringify!($len)))
                            } else {
                                let mut ret = [0; $len];
                                ret.copy_from_slice(v);
                                Ok($t(ret))
                            }
                        }
                    }

                    d.deserialize_bytes(BytesVisitor)
                }
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

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                f.pad(match *self {
                    $($name::$elem => $txt),*
                })
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::io::Error;
            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($txt => Ok($name::$elem)),*,
                    _ => {
                        #[cfg(not(feature = "std"))] let message = "Unknown network";
                        #[cfg(feature = "std")] let message = format!("Unknown network (type {})", s);
                        Err($crate::io::Error::new(
                            $crate::io::ErrorKind::InvalidInput,
                            message,
                        ))
                    }
                }
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::serde::Deserializer<'de>,
            {
                use ::core::fmt::{self, Formatter};

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

                    fn visit_string<E>(self, v: $crate::prelude::String) -> Result<Self::Value, E>
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
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    );
}
