// SPDX-License-Identifier: CC0-1.0

//! Bitcoin constants.
//!
//! This module provides various constants relating to the blockchain and consensus code.

/// The maximum allowed redeem script size for a P2SH output.
pub const MAX_REDEEM_SCRIPT_SIZE: usize = 520;
/// The maximum allowed redeem script size of the witness script.
pub const MAX_WITNESS_SCRIPT_SIZE: usize = 10_000;
