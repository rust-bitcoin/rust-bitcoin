// SPDX-License-Identifier: CC0-1.0

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
            ///
            /// # Errors
            ///
            /// Returns an error if `s` contains invalid characters or has incorrect length. (Should be
            /// `N * 2`.)
            pub fn from_hex(s: &str) -> Result<Self, $crate::hex::DecodeFixedLengthBytesError> {
                Ok($t($crate::hex::decode_to_array(s)?))
            }
        }

        impl core::fmt::LowerHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use hex::{display, Case};
                display::fmt_hex_exact!(f, $len, &self.0, Case::Lower)
            }
        }

        impl core::fmt::UpperHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use hex::{display, Case};
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
            type Err = $crate::hex::DecodeFixedLengthBytesError;
            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> { Self::from_hex(s) }
        }

        impl core::convert::TryFrom<&str> for $t {
            type Error = $crate::hex::DecodeFixedLengthBytesError;

            #[inline]
            fn try_from(s: &str) -> core::result::Result<Self, Self::Error> { Self::from_hex(s) }
        }

        internals::_emit_alloc! {
            impl core::convert::TryFrom<alloc::string::String> for $t {
                type Error = $crate::hex::DecodeFixedLengthBytesError;

                #[inline]
                fn try_from(
                    s: alloc::string::String,
                ) -> core::result::Result<Self, Self::Error> {
                    Self::from_hex(&s)
                }
            }

            impl core::convert::TryFrom<alloc::boxed::Box<str>> for $t {
                type Error = $crate::hex::DecodeFixedLengthBytesError;

                #[inline]
                fn try_from(
                    s: alloc::boxed::Box<str>,
                ) -> core::result::Result<Self, Self::Error> {
                    Self::from_hex(&s)
                }
            }

            impl core::convert::TryFrom<alloc::rc::Rc<str>> for $t {
                type Error = $crate::hex::DecodeFixedLengthBytesError;

                #[inline]
                fn try_from(
                    s: alloc::rc::Rc<str>,
                ) -> core::result::Result<Self, Self::Error> {
                    Self::from_hex(&s)
                }
            }

            #[cfg(target_has_atomic = "ptr")]
            impl core::convert::TryFrom<alloc::sync::Arc<str>> for $t {
                type Error = $crate::hex::DecodeFixedLengthBytesError;

                #[inline]
                fn try_from(
                    s: alloc::sync::Arc<str>,
                ) -> core::result::Result<Self, Self::Error> {
                    Self::from_hex(&s)
                }
            }
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
