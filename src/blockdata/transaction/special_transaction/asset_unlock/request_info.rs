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

//! Dash Credit Withdrawal Special Transaction.
//!
//! The credit withdrawal special transaction is used to withdraw from the asset lock credit pool.
//!
//!
//! It is defined in DIPX https://github.com/dashpay/dips/blob/master/dip-000X.md as follows:
//!
//!
//! The special transaction type used for CrWithTx Transactions is 9.

use ::{io};
use io::{Error, Write};
use consensus::{Decodable, Encodable, encode};
use ::{QuorumHash};
use prelude::*;

/// A Credit Withdrawal payload. This is contained as the payload of a credit withdrawal special
/// transaction.
/// The Credit Withdrawal Special transaction and this payload is described in the Asset Lock DIP2X
/// (todo:update this).
/// The Credit Withdrawal Payload is signed by a quorum.
///
/// Transaction using it have no inputs. Hence the proof of validity lies solely on the BLS signature.
///
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
