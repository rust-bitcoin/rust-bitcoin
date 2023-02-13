// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Bitcoin consensus.
//!

pub mod encode;
pub mod params;

pub use self::encode::{Encodable, Decodable, WriteExt, ReadExt};
pub use self::encode::{serialize, deserialize, deserialize_partial};
pub use self::params::Params;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod serde;
