// SPDX-License-Identifier: CC0-1.0

/// Implement `AsRef<PushBytes>` and From<$type> for `PushBytesBuf`.
///
/// This macro requires `PushBytes` and `PushBytesBuf` to be visible in the calling scope.
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
pub(crate) use impl_asref_push_bytes;
