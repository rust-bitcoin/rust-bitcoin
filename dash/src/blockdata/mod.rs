// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin block data.
//!
//! This module defines structures and functions for storing the blocks and
//! transactions which make up the Bitcoin system.
//!

pub mod block;
pub mod constants;
pub mod fee_rate;
pub mod opcodes;
pub mod transaction;
pub mod weight;
pub mod witness;
pub mod script;
pub mod locktime;

pub use fee_rate::FeeRate;
pub use weight::Weight;
