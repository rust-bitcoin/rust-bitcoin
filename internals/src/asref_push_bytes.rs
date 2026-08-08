// SPDX-License-Identifier: CC0-1.0

//! Macro for implementing `AsRef<PushBytes>` on byte-array-backed newtypes.

/// Implement `AsRef<PushBytes>` and `From<$type>` for `PushBytesBuf`.
///
/// # Caller Requirements
///
/// Because this macro is exported from `bitcoin-internals` but generates code that is compiled
/// in the *calling* crate, the identifiers `PushBytes` and `PushBytesBuf` must resolve at the
/// macro's invocation site. Typically this means importing them from `bitcoin-primitives`, but
/// any `use` that brings them into scope under those exact names (e.g. re-exported from another
/// dependency) also works.
#[macro_export]
macro_rules! impl_asref_push_bytes {
    ($($hashtype:ty),* $(,)?) => {
        $(
            impl AsRef<PushBytes> for $hashtype {
                fn as_ref(&self) -> &PushBytes {
                    self.as_byte_array().into()
                }
            }

            impl From<$hashtype> for PushBytesBuf {
                fn from(hash: $hashtype) -> Self {
                    hash.as_byte_array().into()
                }
            }
        )*
    };
}
