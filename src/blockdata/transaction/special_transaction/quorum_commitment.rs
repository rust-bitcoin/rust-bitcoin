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

//! Dash Quorum Commitment Special Transaction.
//!
//! It is defined in DIP6 https://github.com/dashpay/dips/blob/master/dip-0006.md.
//!

use prelude::*;
use io;
use io::{Error, Write};
use ::{QuorumHash};
use bls_sig_utils::{BLSPublicKey, BLSSignature};
use consensus::{Decodable, Encodable, encode};
use QuorumVVecHash;




/// A Quorum Finalization Commitment. It is described in the finalization section of DIP6:
/// https://github.com/dashpay/dips/blob/master/dip-0006.md#6-finalization-phase
///
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QuorumFinalizationCommitment {
    version: u16,
    llmq_type: u8,
    quorum_hash: QuorumHash,
    signers: Vec<u8>,
    valid_members: Vec<u8>,
    quorum_public_key: BLSPublicKey,
    quorum_vvec_hash: QuorumVVecHash,
    quorum_sig: BLSSignature,
    sig: BLSSignature,
}

impl Encodable for QuorumFinalizationCommitment {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.llmq_type.consensus_encode(&mut s)?;
        len += self.quorum_hash.consensus_encode(&mut s)?;
        len += self.signers.consensus_encode(&mut s)?;
        len += self.valid_members.consensus_encode(&mut s)?;
        len += self.quorum_public_key.consensus_encode(&mut s)?;
        len += self.quorum_vvec_hash.consensus_encode(&mut s)?;
        len += self.quorum_sig.consensus_encode(&mut s)?;
        len += self.sig.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for QuorumFinalizationCommitment {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let llmq_type = u8::consensus_decode(&mut d)?;
        let quorum_hash = QuorumHash::consensus_decode(&mut d)?;
        let signers = Vec::<u8>::consensus_decode(&mut d)?;
        let valid_members = Vec::<u8>::consensus_decode(&mut d)?;
        let quorum_public_key = BLSPublicKey::consensus_decode(&mut d)?;
        let quorum_vvec_hash = QuorumVVecHash::consensus_decode(&mut d)?;
        let quorum_sig = BLSSignature::consensus_decode(&mut d)?;
        let sig = BLSSignature::consensus_decode(d)?;
        Ok(QuorumFinalizationCommitment {
            version,
            llmq_type,
            quorum_hash,
            signers,
            valid_members,
            quorum_public_key,
            quorum_vvec_hash,
            quorum_sig,
            sig
        })
    }
}

/// A Quorum Commitment Payload used in a Quorum Commitment Special Transaction.
/// This is used in the mining phase as described in DIP 6:
/// https://github.com/dashpay/dips/blob/master/dip-0006.md#7-mining-phase.
///
/// Miners take the best final commitment for a DKG session and mine it into a block.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QuorumCommitmentPayload {
    version: u16,
    height: u32,
    finalization_commitment: QuorumFinalizationCommitment,
}

impl Encodable for QuorumCommitmentPayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.height.consensus_encode(&mut s)?;
        len += self.finalization_commitment.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for QuorumCommitmentPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let height = u32::consensus_decode(&mut d)?;
        let finalization_commitment = QuorumFinalizationCommitment::consensus_decode(d)?;
        Ok(QuorumCommitmentPayload {
            version,
            height,
            finalization_commitment
        })
    }
}


#[cfg(test)]
mod tests {

}