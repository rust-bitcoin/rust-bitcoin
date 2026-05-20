// SPDX-License-Identifier: CC0-1.0

/// Implements the `TryFrom<{string-like}>` family for a type that already implements `FromStr`.
///
/// Generates the following impls by delegating to the existing `FromStr` impl and reusing its
/// `Err` type:
///
/// * `TryFrom<&str>` (always available)
/// * `TryFrom<String>` (requires `alloc`)
/// * `TryFrom<Box<str>>` (requires `alloc`)
/// * `TryFrom<Rc<str>>` (requires `alloc`)
/// * `TryFrom<Arc<str>>` (requires `alloc` and `target_has_atomic = "ptr"`)
///
#[allow(unused_macros)]
macro_rules! impl_tryfrom_str_family {
    ($ty:ty) => {
        impl ::core::convert::TryFrom<&str> for $ty {
            type Error = <$ty as ::core::str::FromStr>::Err;

            #[inline]
            fn try_from(s: &str) -> ::core::result::Result<Self, Self::Error> {
                <$ty as ::core::str::FromStr>::from_str(s)
            }
        }

        internals::_emit_alloc! {
            impl ::core::convert::TryFrom<alloc::string::String> for $ty {
                type Error = <$ty as ::core::str::FromStr>::Err;

                #[inline]
                fn try_from(
                    s: alloc::string::String,
                ) -> ::core::result::Result<Self, Self::Error> {
                    <$ty as ::core::str::FromStr>::from_str(&s)
                }
            }

            impl ::core::convert::TryFrom<alloc::boxed::Box<str>> for $ty {
                type Error = <$ty as ::core::str::FromStr>::Err;

                #[inline]
                fn try_from(
                    s: alloc::boxed::Box<str>,
                ) -> ::core::result::Result<Self, Self::Error> {
                    <$ty as ::core::str::FromStr>::from_str(&s)
                }
            }

            impl ::core::convert::TryFrom<alloc::rc::Rc<str>> for $ty {
                type Error = <$ty as ::core::str::FromStr>::Err;

                #[inline]
                fn try_from(
                    s: alloc::rc::Rc<str>,
                ) -> ::core::result::Result<Self, Self::Error> {
                    <$ty as ::core::str::FromStr>::from_str(&s)
                }
            }

            #[cfg(target_has_atomic = "ptr")]
            impl ::core::convert::TryFrom<alloc::sync::Arc<str>> for $ty {
                type Error = <$ty as ::core::str::FromStr>::Err;

                #[inline]
                fn try_from(
                    s: alloc::sync::Arc<str>,
                ) -> ::core::result::Result<Self, Self::Error> {
                    <$ty as ::core::str::FromStr>::from_str(&s)
                }
            }
        }
    };
}
#[allow(unused_imports)]
pub(crate) use impl_tryfrom_str_family;
