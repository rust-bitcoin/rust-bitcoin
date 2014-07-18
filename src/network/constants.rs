// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Network constants
//!
//! This module provides various constants relating to the Bitcoin network
//! protocol, such as protocol versioning and magic header bytes.
//!

pub static MAGIC_BITCOIN: u32       = 0xD9B4BEF9;

pub static PROTOCOL_VERSION: u32    = 70001;
pub static SERVICES: u64            = 0;
pub static USER_AGENT: &'static str = "bitcoin-rust v0.1";

