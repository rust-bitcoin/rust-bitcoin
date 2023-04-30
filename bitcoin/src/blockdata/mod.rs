// SPDX-License-Identifier: CC0-1.0

//! Bitcoin block data.
//!
//! This module defines structures and functions for storing the blocks and
//! transactions which make up the Bitcoin system.
//!

pub mod block;
pub mod constants;
pub mod fee_rate;
pub mod locktime;
pub mod opcodes;
pub mod script;
pub mod transaction;
pub mod weight;
pub mod witness;

pub use fee_rate::FeeRate;
pub use weight::Weight;
