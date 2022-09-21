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

use ::{io, SpecialTransactionPayloadHash};
use io::{Error, Write};
use hashes::Hash;
use bls_sig_utils::BLSSignature;
use consensus::{Decodable, Encodable, encode};
use blockdata::transaction::special_transaction::asset_unlock::request_info::AssetUnlockRequestInfo;
use blockdata::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::AssetUnlockBasePayload;
use blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;

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
pub struct AssetUnlockPayload {
    /// The base information about the asset unlock. This base information is the information that
    /// should be put into a queue.
    pub base: AssetUnlockBasePayload,
    /// The request information. This should be added to the unlock transaction as it is being sent
    /// to be signed.
    pub request_info: AssetUnlockRequestInfo,
    /// The threshold signature. This should be returned by the consensus engine.
    pub quorum_sig: BLSSignature,
}

impl SpecialTransactionBasePayloadEncodable for AssetUnlockPayload {
    fn base_payload_data_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.base.consensus_encode(&mut s)?;
        len += self.request_info.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for AssetUnlockPayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.base.consensus_encode(&mut s)?;
        len += self.request_info.consensus_encode(&mut s)?;
        len += self.quorum_sig.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for AssetUnlockPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let base = AssetUnlockBasePayload::consensus_decode(&mut d)?;
        let request_info = AssetUnlockRequestInfo::consensus_decode(&mut d)?;
        let quorum_sig = BLSSignature::consensus_decode(&mut d)?;
        Ok(AssetUnlockPayload {
            base,
            request_info,
            quorum_sig
        })
    }
}