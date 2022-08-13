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

//! Dash Coinbase Special Transaction.
//!
//! Each time a block is mined it includes a coinbase special transaction.
//! It is defined in DIP4 https://github.com/dashpay/dips/blob/master/dip-0004.md.
//!

use io;
use io::{Error, Write};
use ::{MerkleRootMasternodeList, MerkleRootQuorums};
use consensus::{Decodable, Encodable, encode};

/// A Coinbase payload. This is contained as the payload of a coinbase special transaction.
/// The Coinbase payload is described in DIP4.
///
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CoinbasePayload {
    version: u16,
    height: u32,
    merkle_root_masternode_list: MerkleRootMasternodeList,
    merkle_root_quorums: MerkleRootQuorums,
}

impl Encodable for CoinbasePayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.height.consensus_encode(&mut s)?;
        len += self.merkle_root_masternode_list.consensus_encode(&mut s)?;
        len += self.merkle_root_quorums.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for CoinbasePayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let height = u32::consensus_decode(&mut d)?;
        let merkle_root_masternode_list = MerkleRootMasternodeList::consensus_decode(&mut d)?;
        let merkle_root_quorums = MerkleRootQuorums::consensus_decode(&mut d)?;
        Ok(CoinbasePayload {
            version,
            height,
            merkle_root_masternode_list,
            merkle_root_quorums
        })
    }
}

#[cfg(test)]
mod tests {

}