// Rust Dash Library
// Written for Dash in 2022 by
//     The Dash Core Developers
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

//! Dash Asset unlock Special Transaction request info.
//!
//! The asset unlock special transaction is used to withdraw from the asset lock credit pool.
//!
//! The request info should be added once the quorum selection for signing has been made.

use ::{io};
use io::{Error, Write};
use consensus::{Decodable, Encodable, encode};
use ::{QuorumHash};
use prelude::*;

/// An asset unlock request info
/// This is the information about the signing quorum
/// The request height should be the height at which the specified quorum is active on core.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AssetUnlockRequestInfo {
    request_height: u32,
    quorum_hash: QuorumHash,
}

impl AssetUnlockRequestInfo {
    /// Encodes the asset unlock on top of
    pub fn consensus_append_to_base_encode<S: Write>(&self, base_bytes: Vec<u8>, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += base_bytes.consensus_encode(&mut s)?;
        len += self.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Encodable for AssetUnlockRequestInfo {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.request_height.consensus_encode(&mut s)?;
        len += self.quorum_hash.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for AssetUnlockRequestInfo {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let request_height = u32::consensus_decode(&mut d)?;
        let quorum_hash = QuorumHash::consensus_decode(&mut d)?;
        Ok(AssetUnlockRequestInfo {
            request_height,
            quorum_hash,
        })
    }
}
