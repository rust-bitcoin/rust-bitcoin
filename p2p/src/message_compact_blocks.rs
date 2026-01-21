// SPDX-License-Identifier: CC0-1.0

//!
//! BIP-0152  Compact Blocks network messages

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use crate::consensus::impl_consensus_encoding;

/// sendcmpct message
#[derive(PartialEq, Eq, Clone, Debug, Copy, PartialOrd, Ord, Hash)]
pub struct SendCmpct {
    /// Request to be sent compact blocks.
    pub send_compact: bool,
    /// Compact Blocks protocol version number.
    pub version: u64,
}
impl_consensus_encoding!(SendCmpct, send_compact, version);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SendCmpct {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { send_compact: u.arbitrary()?, version: u.arbitrary()? })
    }
}
