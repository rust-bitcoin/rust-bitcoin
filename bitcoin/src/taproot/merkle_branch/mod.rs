//! Contains `TaprootMerkleBranchBuf` and its associated types.

mod borrowed;
mod buf;

use core::fmt;

pub use borrowed::TaprootMerkleBranch;
pub use buf::TaprootMerkleBranchBuf;

use super::{
    InvalidMerkleBranchSizeError, InvalidMerkleTreeDepthError, TapNodeHash, TaprootError,
    TAPROOT_CONTROL_MAX_NODE_COUNT, TAPROOT_CONTROL_NODE_SIZE,
};

/// Returned when decoding of merkle branch fails.
#[derive(Debug)]
pub struct DecodeError {
    /// Represents the invalid number of bytes. It may be invalid in two ways: it might not be a
    /// multiple of 32, in which case it is guaranteed to be wrong for that reason;
    /// only if it is a multiple of 32 do we check that it does not exceed 32 * 128, in which case
    /// it is wrong for that reason.
    ///
    /// This error type is used in `Result<&TaprootMerkleBranch, DecodeError>`, so by keeping its
    /// size down to a single `usize` (by not using enum) and considering the niche optimization on
    /// the *fat reference* `&TaprootMerkleBranch`, the `Result` will have the same size as just
    /// `&TaprootMerkleBranch`.
    num_bytes: usize,
}

impl From<InvalidMerkleBranchSizeError> for DecodeError {
    fn from(value: InvalidMerkleBranchSizeError) -> Self { Self { num_bytes: value.0 } }
}

impl From<InvalidMerkleTreeDepthError> for DecodeError {
    fn from(value: InvalidMerkleTreeDepthError) -> Self {
        Self { num_bytes: value.0 * TAPROOT_CONTROL_NODE_SIZE }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.num_bytes % TAPROOT_CONTROL_NODE_SIZE == 0 {
            write!(
                f,
                "the Merkle branch has {} nodes which is more than the limit {}",
                self.num_bytes / TAPROOT_CONTROL_NODE_SIZE,
                TAPROOT_CONTROL_MAX_NODE_COUNT
            )
        } else {
            write!(
                f,
                "the Merkle branch is {} bytes long which is not an integer multiple of {}",
                self.num_bytes, TAPROOT_CONTROL_NODE_SIZE
            )
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

impl From<DecodeError> for TaprootError {
    fn from(value: DecodeError) -> Self {
        if value.num_bytes % TAPROOT_CONTROL_NODE_SIZE == 0 {
            InvalidMerkleTreeDepthError(value.num_bytes / TAPROOT_CONTROL_NODE_SIZE).into()
        } else {
            InvalidMerkleBranchSizeError(value.num_bytes).into()
        }
    }
}
