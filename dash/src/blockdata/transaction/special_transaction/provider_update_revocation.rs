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

//! Dash Provider Update Revocation Special Transaction.
//!
//! The provider update revocation special transaction is used to signal to the owner that they
//! should choose a new operator.
//!
//! It is defined in DIP3 [dip-0003](https://github.com/dashpay/dips/blob/master/dip-0003.md) as follows:
//!
//! If an operator suspects their keys are insecure or if they wish to terminate service, they
//! can issue a special transaction to the network. This special transaction is called a Provider
//! Update Revocation Transaction and is abbreviated as ProUpRevTx. It can only be done by the
//! operator and allows them to signal the owner through the blockchain to choose a new operator
//! (or the same one with a new non-compromised key).

//! When a ProUpRevTx is processed, it updates the metadata of the masternode entry by removing
//! the operator and service information and marks the masternode as PoSe-banned. Owners must
//! later issue a ProUpRegTx Transaction to set a new operator key. After the ProUpRegTx is
//! processed, the new operator must issue a ProUpServTx Transaction to update the service-related
//! metadata and clear the PoSe-banned state (revive the masternode).

//! <https://github.com/dashpay/dips/blob/master/dip-0003.md#appendix-a-reasons-for-self-revocation-of-operators>
//! describes potential reasons for a revocation.

//! The special transaction type used for Provider Update Revoking Transactions is 4.

use crate::io;
use hashes::Hash;
use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::bls_sig_utils::BLSSignature;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{InputsHash, SpecialTransactionPayloadHash, Txid};

/// A Provider Update Revocation Payload used in a Provider Update Revocation Special Transaction.
/// This is used to signal and stop a Masternode from the operator.
/// It must be signed by the operator's key that was set at registration or registrar update.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct ProviderUpdateRevocationPayload {
    pub version: u16,
    pub pro_tx_hash: Txid,
    pub reason: u16,
    pub inputs_hash: InputsHash,
    pub payload_sig: BLSSignature,
}

impl ProviderUpdateRevocationPayload {
    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        2 + 32 + 2 + 32 + 96
    }
}

impl SpecialTransactionBasePayloadEncodable for ProviderUpdateRevocationPayload {
    fn base_payload_data_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.pro_tx_hash.consensus_encode(&mut s)?;
        len += self.reason.consensus_encode(&mut s)?;
        len += self.inputs_hash.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderUpdateRevocationPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, mut w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut w)?;
        len += self.payload_sig.consensus_encode(&mut w)?;
        Ok(len)
    }
}

impl Decodable for ProviderUpdateRevocationPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;
        let pro_tx_hash = Txid::consensus_decode(r)?;
        let reason = u16::consensus_decode(r)?;
        let inputs_hash = InputsHash::consensus_decode(r)?;
        let payload_sig = BLSSignature::consensus_decode(r)?;

        Ok(ProviderUpdateRevocationPayload {
            version,
            pro_tx_hash,
            reason,
            inputs_hash,
            payload_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use hashes::Hash;
    use crate::bls_sig_utils::BLSSignature;
    use crate::consensus::Encodable;
    use crate::hash_types::InputsHash;
    use crate::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
    use crate::Txid;

    #[test]
    fn size() {
        let want = 164;
        let payload = ProviderUpdateRevocationPayload {
            version: 0,
            pro_tx_hash: Txid::all_zeros(),
            reason: 0,
            inputs_hash: InputsHash::all_zeros(),
            payload_sig: BLSSignature::from([0; 96]),
        };
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(payload.size(), want);
        assert_eq!(actual, want);
    }
}
