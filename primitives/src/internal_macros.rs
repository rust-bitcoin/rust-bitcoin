// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the `bitcoin-primitives` library.

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
