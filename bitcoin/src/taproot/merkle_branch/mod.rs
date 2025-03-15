//! Contains `TaprootMerkleBranchBuf` and its associated types.

mod buf;

pub use buf::TaprootMerkleBranchBuf;
use super::{
    InvalidMerkleBranchSizeError, InvalidMerkleTreeDepthError, TapNodeHash, TaprootError,
    TAPROOT_CONTROL_MAX_NODE_COUNT, TAPROOT_CONTROL_NODE_SIZE,
};
