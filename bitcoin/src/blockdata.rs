// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin block data.
//!
//! This module defines structures and functions for storing the blocks and
//! transactions which make up the Bitcoin system.
//!

pub mod constants;
pub mod locktime;
pub mod opcodes;
pub mod script;
pub mod transaction;
pub mod block;
pub mod witness;
pub mod weight;
pub mod fee_rate;

pub use weight::Weight;
pub use fee_rate::FeeRate;
