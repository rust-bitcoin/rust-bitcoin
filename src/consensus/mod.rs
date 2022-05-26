// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
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

//! Bitcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Bitcoin consensus.
//!

pub mod encode;
pub mod params;

pub use self::encode::{
    deserialize, deserialize_partial, serialize, Decodable, Encodable, ReadExt, WriteExt,
};
pub use self::params::Params;
