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
//! It is defined in DIPX [dip-000X.md](https://github.com/dashpay/dips/blob/master/dip-000X.md) as follows:
//!
//!
//! The special transaction type used for CrWithTx Transactions is 9.

use crate::io;
use crate::hash_types::{SpecialTransactionPayloadHash};
use hashes::Hash;
use crate::bls_sig_utils::BLSSignature;
use crate::consensus::{Decodable, Encodable, encode};
use crate::blockdata::transaction::special_transaction::{
    asset_unlock::request_info::AssetUnlockRequestInfo,
    asset_unlock::unqualified_asset_unlock::AssetUnlockBasePayload,
    SpecialTransactionBasePayloadEncodable,
};

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
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
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

impl AssetUnlockPayload {
    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        self.base.size() + self.request_info.size() + 96
    }
}

impl SpecialTransactionBasePayloadEncodable for AssetUnlockPayload {
    fn base_payload_data_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
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
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base.consensus_encode(w)?;
        len += self.request_info.consensus_encode(w)?;
        len += self.quorum_sig.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for AssetUnlockPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let base = AssetUnlockBasePayload::consensus_decode(r)?;
        let request_info = AssetUnlockRequestInfo::consensus_decode(r)?;
        let quorum_sig = BLSSignature::consensus_decode(r)?;
        Ok(AssetUnlockPayload {
            base,
            request_info,
            quorum_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use hex::FromHex;
    use hashes::{Hash};
    use crate::bls_sig_utils::BLSSignature;
    use crate::consensus;
    use crate::consensus::{ Encodable};
    use crate::hash_types::QuorumHash;
    use crate::transaction::special_transaction::asset_unlock::qualified_asset_unlock::AssetUnlockPayload;
    use crate::transaction::special_transaction::asset_unlock::request_info::AssetUnlockRequestInfo;
    use crate::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::AssetUnlockBasePayload;

    #[test]
    fn size() {
        let want = 145;
        let payload = AssetUnlockPayload {
            base: AssetUnlockBasePayload { version: 0, index: 0, fee: 0 },
            request_info: AssetUnlockRequestInfo {
                request_height: 0,
                quorum_hash: QuorumHash::all_zeros(),
            },
            quorum_sig: BLSSignature::from([0; 96]),
        };
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(payload.size(), want);
        assert_eq!(actual, want);
    }

    #[test]
    fn deserialize() {
        let payload_bytes = Vec::from_hex("012d0100000000000070110100250500004acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7")
            .unwrap();

        let payload: AssetUnlockPayload = consensus::encode::deserialize(&payload_bytes).unwrap();
        assert_eq!(payload.base.version, 1);
        assert_eq!(payload.base.index, 301);
        assert_eq!(payload.base.fee, 70000);
        assert_eq!(payload.request_info.request_height, 1317);
        assert_eq!(payload.request_info.quorum_hash, QuorumHash::from_str("4acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448").unwrap());
        assert_eq!(payload.quorum_sig, BLSSignature::from_str("aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7").unwrap());
    }

    #[test]
    fn serialize() {
        let payload = AssetUnlockPayload {
            base: AssetUnlockBasePayload {
                version: 1,
                index: 301,
                fee: 70000,
            },
            request_info: AssetUnlockRequestInfo {
                request_height: 1317,
                quorum_hash: QuorumHash::from_str("4acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448").unwrap(),
            },
            quorum_sig: BLSSignature::from_str("aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7").unwrap()
        };

        let serialized_bytes = consensus::serialize(&payload);

        let expected_payload_bytes = Vec::from_hex("012d0100000000000070110100250500004acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7")
            .unwrap();
        assert_eq!(serialized_bytes, expected_payload_bytes);
    }
}
