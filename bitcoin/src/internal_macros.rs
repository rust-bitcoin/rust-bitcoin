// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the Rust Bitcoin library.

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl $crate::consensus::Encodable for $thing {
            #[inline]
            fn consensus_encode<W: $crate::io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, $crate::io::Error> {
                let mut len = 0;
                $(len += self.$field.consensus_encode(w)?;)+
                Ok(len)
            }
        }

        impl $crate::consensus::Decodable for $thing {

            #[inline]
            fn consensus_decode_from_finite_reader<R: $crate::io::BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, $crate::consensus::encode::Error> {
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode_from_finite_reader(r)?),+
                })
            }

            #[inline]
            fn consensus_decode<R: $crate::io::BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, $crate::consensus::encode::Error> {
                let mut r = $crate::io::Read::take(r, internals::ToU64::to_u64($crate::consensus::encode::MAX_VEC_SIZE));
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode(&mut r)?),+
                })
            }
        }
    );
}
pub(crate) use impl_consensus_encoding;

/// Implements several string-ish traits for byte-based newtypes.
///
/// - `fmt::Display` and `str::FromStr` (using lowercase hex)
/// - `fmt::LowerHex` and `UpperHex`
/// - `fmt::Debug` (using `LowerHex`)
/// - `serde::Serialize` and `Deserialize` (using lowercase hex)
///
/// As well as an inherent `from_hex` method.
macro_rules! impl_array_newtype_stringify {
    ($t:ident, $len:literal) => {
        impl $t {
            /// Constructs a new `Self` from a hex string.
            pub fn from_hex(s: &str) -> Result<Self, hex_unstable::HexToArrayError> {
                Ok($t(hex_unstable::FromHex::from_hex(s)?))
            }
        }

        impl core::fmt::LowerHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use hex_unstable::{display, Case};
                display::fmt_hex_exact!(f, $len, &self.0, Case::Lower)
            }
        }

        impl core::fmt::UpperHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use hex_unstable::{display, Case};
                display::fmt_hex_exact!(f, $len, &self.0, Case::Upper)
            }
        }

        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl core::str::FromStr for $t {
            type Err = hex_unstable::HexToArrayError;
            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> { Self::from_hex(s) }
        }

        #[cfg(feature = "serde")]
        impl $crate::serde::Serialize for $t {
            fn serialize<S: $crate::serde::Serializer>(
                &self,
                s: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    s.serialize_bytes(&self[..])
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $t {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(
                d: D,
            ) -> core::result::Result<$t, D::Error> {
                if d.is_human_readable() {
                    struct HexVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for HexVisitor {
                        type Value = $t;

                        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                            f.write_str("an ASCII hex string")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            use $crate::serde::de::Unexpected;

                            if let Ok(hex) = core::str::from_utf8(v) {
                                core::str::FromStr::from_str(hex).map_err(E::custom)
                            } else {
                                return Err(E::invalid_value(Unexpected::Bytes(v), &self));
                            }
                        }

                        fn visit_str<E>(self, hex: &str) -> core::result::Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            core::str::FromStr::from_str(hex).map_err(E::custom)
                        }
                    }

                    d.deserialize_str(HexVisitor)
                } else {
                    struct BytesVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for BytesVisitor {
                        type Value = $t;

                        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                            f.write_str("a bytestring")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
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
    };
}
pub(crate) use impl_array_newtype_stringify;

#[rustfmt::skip]
macro_rules! impl_asref_push_bytes {
    ($($hashtype:ident),*) => {
        $(
            impl AsRef<$crate::script::PushBytes> for $hashtype {
                fn as_ref(&self) -> &$crate::script::PushBytes {
                    self.as_byte_array().into()
                }
            }

            impl From<$hashtype> for $crate::script::PushBytesBuf {
                fn from(hash: $hashtype) -> Self {
                    hash.as_byte_array().into()
                }
            }
        )*
    };
}
pub(crate) use impl_asref_push_bytes;

macro_rules! only_doc_attrs {
    ({}, {$($fun:tt)*}) => {
        $($fun)*
    };
    ({#[doc = $($doc:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { #[doc = $($doc)*] $($fun)* });
    };
    ({#[doc($($doc:tt)*)] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { #[doc($($doc)*)] $($fun)* });
    };
    ({#[$($other:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { $($fun)* });
    };
}
pub(crate) use only_doc_attrs;

macro_rules! only_non_doc_attrs {
    ({}, {$($fun:tt)*}) => {
        $($fun)*
    };
    ({#[doc = $($doc:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { #[doc = $($doc)*] $($fun)* });
    };
    ({#[doc($($doc:tt)*)] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { $($fun)* });
    };
    ({#[$($other:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { #[$(other)*] $($fun)* });
    };
}
pub(crate) use only_non_doc_attrs;

/// Defines a trait `$trait_name` and implements it for `ty`, used to define extension traits.
macro_rules! define_extension_trait {
    ($(#[$($trait_attrs:tt)*])* $trait_vis:vis trait $trait_name:ident$(<$traitgen:ident $(= $traitdefault:ty)?>)? impl$(<$implgen:ident $(= $impldefault:ty)?>)? for $ty:ident$(<$tygen:ident $(= $tydefault:ty)?>)? {
        $(
            $(#[$($fn_attrs:tt)*])*
            fn $fn:ident$(<$($gen:ident: $gent:path),*>)?($($params:tt)*) $( -> $ret:ty )? $(where $wherety:ident $(= $whereeq:ident)? $(: $wherebound:ident)?)? $body:block
        )*
    }) => {
        #[cfg_attr(docsrs, doc(notable_trait))]
        $(#[$($trait_attrs)*])* $trait_vis trait $trait_name$(<$traitgen $(= $traitdefault)?>)?: sealed::Sealed {
            $(
                $crate::internal_macros::only_doc_attrs! {
                    { $(#[$($fn_attrs)*])* },
                    {
                        fn $fn$(<$($gen: $gent),*>)?($($params)*) $( -> $ret)? $(where $wherety $(= $whereeq)? $(: $wherebound)?)?;
                    }
                }
            )*
        }

        impl$(<$implgen $(= $impldefault)?>)? $trait_name$(<$traitgen $(= $traitdefault)?>)? for $ty$(<$tygen $(= $tydefault)?>)? {
            $(
                $crate::internal_macros::only_non_doc_attrs! {
                    { $(#[$($fn_attrs)*])* },
                    {
                        fn $fn$(<$($gen: $gent),*>)?($($params)*) $( -> $ret )? $(where $wherety $(= $whereeq)? $(: $wherebound)?)? $body
                    }
                }
            )*
        }
    };
}
pub(crate) use define_extension_trait;
