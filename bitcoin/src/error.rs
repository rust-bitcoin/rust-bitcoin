//! Contains error types and other error handling tools.

use core::fmt;

use bitcoin_internals::write_err;

use crate::consensus::encode;
pub use crate::parse::ParseIntError;

/// A general error code, other errors should implement conversions to/from this
/// if appropriate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Encoding error
    Encode(encode::Error),
    /// The header hash is not below the target
    BlockBadProofOfWork,
    /// The `target` field of a block header did not match the expected difficulty
    BlockBadTarget,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Encode(ref e) => write_err!(f, "encoding error"; e),
            Error::BlockBadProofOfWork => f.write_str("block target correct but not attained"),
            Error::BlockBadTarget => f.write_str("block target incorrect"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Encode(e) => Some(e),
            BlockBadProofOfWork | BlockBadTarget => None,
        }
    }
}

#[doc(hidden)]
impl From<encode::Error> for Error {
    fn from(e: encode::Error) -> Error { Error::Encode(e) }
}

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
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.$field) }
        }
    };
}
pub(crate) use impl_std_error;
