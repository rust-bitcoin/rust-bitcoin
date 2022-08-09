//! Contains error types and other error handling tools.

pub use crate::parse::ParseIntError;

/// Impls std::error::Error for the specified type with appropriate attributes, possibly returning
/// source.
macro_rules! impl_std_error {
    // No source available
    ($type:ty) => {
        #[cfg(feature = "std")]
        #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
        impl std::error::Error for $type {}
    };
    // Struct with $field as source
    ($type:ty, $field:ident) => {
        #[cfg(feature = "std")]
        #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
        impl std::error::Error for $type {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.$field)
            }
        }
    };
}
pub(crate) use impl_std_error;
