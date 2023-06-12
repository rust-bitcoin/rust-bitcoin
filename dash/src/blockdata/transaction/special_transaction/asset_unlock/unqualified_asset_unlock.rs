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

//! Dash Asset Unlock Base Special Transaction and Payload.
//!
//! These base elements are used in withdrawal queues.
//!
//!
//! It is defined in DIPX [dip-000X.md](https://github.com/dashpay/dips/blob/master/dip-000X.md) as follows:
//!
//!
//! The special transaction type used for AssetUnlockTx Transactions is 9.

use crate::{io, VarInt};
use crate::transaction::TxOut;
use crate::blockdata::transaction::special_transaction::TransactionType;
use crate::blockdata::transaction::special_transaction::TransactionType::AssetUnlock;
use crate::consensus::{Decodable, Encodable, encode};
use crate::{ScriptBuf, TxIn};
use crate::prelude::*;
use crate::hash_types::{PubkeyHash, ScriptHash};

/// An Asset Unlock Base payload. This is the base payload of the Asset Unlock. In order to make
/// it a full payload the request info should be added.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct AssetUnlockBasePayload {
    /// The payload protocol version, is currently expected to be 0.
    pub version: u8,
    /// The index of the unlock transaction. It gets bumped on each transaction
    pub index: u64,
    /// The fee used in Duffs (Satoshis)
    pub fee: u32,
}

impl AssetUnlockBasePayload {
    /// The size of the payload in bytes.
    pub fn size(&self) -> usize { 1 + 8 + 4 }
}

impl Encodable for AssetUnlockBasePayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += self.index.consensus_encode(w)?;
        len += self.fee.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for AssetUnlockBasePayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u8::consensus_decode(r)?;
        let index = u64::consensus_decode(r)?;
        let fee = u32::consensus_decode(r)?;
        Ok(AssetUnlockBasePayload {
            version,
            index,
            fee,
        })
    }
}

/// An Asset Unlock Base Transaction Info. This is the base transaction information that is needed
/// to be kept in withdrawal queues.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct AssetUnlockBaseTransactionInfo {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    pub version: u16,
    /// Block number before which this transaction is valid, or 0 for valid immediately.
    pub lock_time: u32,
    /// List of transaction outputs.
    pub output: Vec<TxOut>,
    /// Base payload information
    pub base_payload: AssetUnlockBasePayload,
}

impl AssetUnlockBaseTransactionInfo {
    /// Adds an output that burns Dash. Used to top up a Dash Identity;
    /// accepts hash of the public key to prove ownership of the burnt
    /// dash on Dash Platform.
    pub fn add_burn_output(&mut self, satoshis_to_burn: u64, data: &[u8; 20]) {
        let burn_script = ScriptBuf::new_op_return(data);
        let output = TxOut {
            value: satoshis_to_burn,
            script_pubkey: burn_script,
        };
        self.output.push(output)
    }

    /// Convenience method that adds an output that pays to a public key hash.
    pub fn add_p2pkh_output(&mut self, amount: u64, public_key_hash: &PubkeyHash) {
        let public_key_hash_script = ScriptBuf::new_p2pkh(public_key_hash);
        let output = TxOut {
            value: amount,
            script_pubkey: public_key_hash_script,
        };
        self.output.push(output)
    }

    /// Convenience method that adds an output that pays to a public key hash.
    pub fn add_p2sh_output(&mut self, amount: u64, script_hash: &ScriptHash) {
        let pay_to_script_hash_script = ScriptBuf::new_p2sh(script_hash);
        let output = TxOut {
            value: amount,
            script_pubkey: pay_to_script_hash_script,
        };
        self.output.push(output)
    }

    /// The size of the transaction in bytes.
    pub fn size(&self) -> usize {
        let mut size = 2 + 2 + 1 + 4;
        size += self.output.iter().map(|o| o.size()).sum::<usize>();
        size += VarInt(self.output.len() as u64).len();
        size + self.base_payload.size()
    }
}

impl Encodable for AssetUnlockBaseTransactionInfo {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += (AssetUnlock as u16).consensus_encode(w)?;
        len += Vec::<TxIn>::new().consensus_encode(w)?;
        len += self.output.consensus_encode(w)?;
        len += self.lock_time.consensus_encode(w)?;
        len += self.base_payload.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for AssetUnlockBaseTransactionInfo {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;
        let special_transaction_type_u16 = u16::consensus_decode(r)?;
        let special_transaction_type = TransactionType::try_from(special_transaction_type_u16).map_err(|_| encode::Error::UnknownSpecialTransactionType(special_transaction_type_u16))?;
        if special_transaction_type != AssetUnlock {
            return Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: AssetUnlock, actual: special_transaction_type });
        }
        Vec::<TxIn>::consensus_decode(r)?; //no inputs
        Ok(AssetUnlockBaseTransactionInfo {
            version,
            output: Decodable::consensus_decode(r)?,
            lock_time: Decodable::consensus_decode(r)?,
            base_payload: AssetUnlockBasePayload::consensus_decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use hashes::Hash;
    use crate::consensus::Encodable;
    use crate::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::{AssetUnlockBasePayload, AssetUnlockBaseTransactionInfo};
    use crate::{ScriptBuf, TxOut};

    #[test]
    fn size() {
        let want = 51;
        let tx1 = TxOut {
            value: 0,
            script_pubkey: ScriptBuf::from(vec![1, 2, 3, 4, 5]),
        };
        let tx2 = TxOut {
            value: 0,
            script_pubkey: ScriptBuf::from(vec![6, 7, 8, 9, 0]),
        };
        let payload = AssetUnlockBaseTransactionInfo {
            version: 0,
            lock_time: 0,
            output: vec![tx1, tx2],
            base_payload: AssetUnlockBasePayload { version: 0, index: 0, fee: 0 },
        };
        assert_eq!(payload.size(), want);
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(actual, want);
    }
}
