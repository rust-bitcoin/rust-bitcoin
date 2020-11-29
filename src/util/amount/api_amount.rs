// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//
//
use std::convert::TryFrom;
use super::*;

/// Type for dealing with unknown amounts
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, PartialEq, PartialOrd, Debug)]
pub enum ApiAmount {
    /// Sats type
    Sats(i64),
    /// Btc type
    Btc(f64),
}
impl TryFrom<ApiAmount> for  Amount {
    type Error = ParseAmountError;
    fn try_from(c: ApiAmount) -> Result<Amount, ParseAmountError> {
        match c {
            ApiAmount::Sats(x) => Ok(Amount::from_sat(x)),
            ApiAmount::Btc(y) => Amount::from_btc(y),
        }
    }
}

impl From<Amount> for ApiAmount {
    fn from(a:Amount) -> Self {
        ApiAmount::Sats(a.as_sat())
    }
}

impl TryFrom<ApiAmount> for UnsignedAmount {
    type Error = ParseAmountError;
    fn try_from(c: ApiAmount) -> Result<UnsignedAmount, ParseAmountError> {
        match c {
            ApiAmount::Sats(x) => 
                if x < 0 {
                    Err(ParseAmountError::Negative)
                } else {
                    Ok(UnsignedAmount::from_sat(x as u64))
                },
            ApiAmount::Btc(y) => UnsignedAmount::from_btc(y),
        }
    }
}

impl From<UnsignedAmount> for ApiAmount {
    fn from(a:UnsignedAmount) -> Self {
        let s = a.as_sat();
        if s > (i64::max_value() as u64) {
            ApiAmount::Btc(a.as_btc())
        } else {
            ApiAmount::Sats(s as i64)
        }
    }
}

/// Derived externally using serde_derive
#[cfg(feature = "serde")]
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(rust_2018_idioms, clippy::useless_attribute)]
    extern crate serde as _serde;
    impl _serde::Serialize for ApiAmount {
        fn serialize<__S>(&self, __serializer: __S) -> _serde::export::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            match *self {
                ApiAmount::Sats(ref __field0) => _serde::Serializer::serialize_newtype_variant(
                    __serializer,
                    "ApiAmount",
                    0u32,
                    "Sats",
                    __field0,
                ),
                ApiAmount::Btc(ref __field0) => _serde::Serializer::serialize_newtype_variant(
                    __serializer,
                    "ApiAmount",
                    1u32,
                    "Btc",
                    __field0,
                ),
            }
        }
    }
    impl<'de> _serde::Deserialize<'de> for ApiAmount {
        fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            enum __Field {
                __field0,
                __field1,
            }
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::export::Formatter,
                ) -> _serde::export::fmt::Result {
                    _serde::export::Formatter::write_str(__formatter, "variant identifier")
                }
                fn visit_u64<__E>(self, __value: u64) -> _serde::export::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::export::Ok(__Field::__field0),
                        1u64 => _serde::export::Ok(__Field::__field1),
                        _ => _serde::export::Err(_serde::de::Error::invalid_value(
                            _serde::de::Unexpected::Unsigned(__value),
                            &"variant index 0 <= i < 2",
                        )),
                    }
                }
                fn visit_str<__E>(self, __value: &str) -> _serde::export::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "Sats" => _serde::export::Ok(__Field::__field0),
                        "Btc" => _serde::export::Ok(__Field::__field1),
                        _ => _serde::export::Err(_serde::de::Error::unknown_variant(
                            __value, VARIANTS,
                        )),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::export::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"Sats" => _serde::export::Ok(__Field::__field0),
                        b"Btc" => _serde::export::Ok(__Field::__field1),
                        _ => {
                            let __value = &_serde::export::from_utf8_lossy(__value);
                            _serde::export::Err(_serde::de::Error::unknown_variant(
                                __value, VARIANTS,
                            ))
                        }
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                }
            }
            struct __Visitor<'de> {
                marker: _serde::export::PhantomData<ApiAmount>,
                lifetime: _serde::export::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = ApiAmount;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::export::Formatter,
                ) -> _serde::export::fmt::Result {
                    _serde::export::Formatter::write_str(__formatter, "enum ApiAmount")
                }
                fn visit_enum<__A>(
                    self,
                    __data: __A,
                ) -> _serde::export::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::EnumAccess<'de>,
                {
                    match match _serde::de::EnumAccess::variant(__data) {
                        _serde::export::Ok(__val) => __val,
                        _serde::export::Err(__err) => {
                            return _serde::export::Err(__err);
                        }
                    } {
                        (__Field::__field0, __variant) => _serde::export::Result::map(
                            _serde::de::VariantAccess::newtype_variant::<i64>(__variant),
                            ApiAmount::Sats,
                        ),
                        (__Field::__field1, __variant) => _serde::export::Result::map(
                            _serde::de::VariantAccess::newtype_variant::<f64>(__variant),
                            ApiAmount::Btc,
                        ),
                    }
                }
            }
            const VARIANTS: &'static [&'static str] = &["Sats", "Btc"];
            _serde::Deserializer::deserialize_enum(
                __deserializer,
                "ApiAmount",
                VARIANTS,
                __Visitor {
                    marker: _serde::export::PhantomData::<ApiAmount>,
                    lifetime: _serde::export::PhantomData,
                },
            )
        }
    }
};

