//! Contains `TaprootMerkleBranchBuf` and its associated types.

mod borrowed;
mod buf;

use core::fmt;
use alloc::boxed::Box;

use internals::error::ParseErrorContext;

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

impl ParseErrorContext for DecodeError {
    fn expecting(&self) -> Box<dyn fmt::Display + '_> {
        if self.num_bytes % TAPROOT_CONTROL_NODE_SIZE == 0 {
            // Use helper struct to capture limit for display
            struct LimitDisplay(usize);
            impl fmt::Display for LimitDisplay {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "a Merkle branch with at most {} nodes", self.0)
                }
            }
            Box::new(LimitDisplay(TAPROOT_CONTROL_MAX_NODE_COUNT))
        } else {
            // Use helper struct to capture size for display
            struct SizeDisplay(usize);
            impl fmt::Display for SizeDisplay {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "a Merkle branch size that is a multiple of {} bytes", self.0)
                }
            }
            Box::new(SizeDisplay(TAPROOT_CONTROL_NODE_SIZE))
        }
    }

    fn help(&self) -> Option<Box<dyn fmt::Display + '_>> {
        if self.num_bytes % TAPROOT_CONTROL_NODE_SIZE == 0 {
            // Create a struct to display the Merkle tree depth error
            struct HelpDisplay(usize);
            impl fmt::Display for HelpDisplay {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "Merkle tree depth {} exceeds the maximum allowed depth of {}.", self.0, TAPROOT_CONTROL_MAX_NODE_COUNT)
                }
            }
            Some(Box::new(HelpDisplay(self.num_bytes / TAPROOT_CONTROL_NODE_SIZE)))
        } else {
            // Create a struct to display the Merkle branch size error
            struct HelpDisplay(usize);
            impl fmt::Display for HelpDisplay {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "The provided Merkle branch data has length {}, which is not divisible by {}.", self.0, TAPROOT_CONTROL_NODE_SIZE)
                }
            }
            Some(Box::new(HelpDisplay(self.num_bytes)))
        }
    }

    fn note(&self) -> Option<&'static str> {
        if self.num_bytes % TAPROOT_CONTROL_NODE_SIZE == 0 {
            InvalidMerkleTreeDepthError(self.num_bytes / TAPROOT_CONTROL_NODE_SIZE).note()
        } else {
            InvalidMerkleBranchSizeError(self.num_bytes).note()
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
