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
//! It is defined in DIPX https://github.com/dashpay/dips/blob/master/dip-000X.md as follows:
//!
//!
//! The special transaction type used for AssetUnlockTx Transactions is 9.

use io::{Error, Write};
use core::convert::TryFrom;
use ::{io, TxOut};
use blockdata::transaction::special_transaction::TransactionType;
use blockdata::transaction::special_transaction::TransactionType::AssetUnlock;
use consensus::{Decodable, Encodable, encode};
use consensus::encode::MAX_VEC_SIZE;
use TxIn;
use prelude::*;

/// An Asset Unlock Base payload. This is the base payload of the Asset Unlock. In order to make
/// it a full payload the request info should be added.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AssetUnlockBasePayload {
    /// The payload protocol version, is currently expected to be 0.
    pub version: u8,
    /// The index of the unlock transaction. It gets bumped on each transaction
    pub index: u64,
    /// The fee used in Duffs (Satoshis)
    pub fee: u32,
}

impl Encodable for AssetUnlockBasePayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.index.consensus_encode(&mut s)?;
        len += self.fee.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for AssetUnlockBasePayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u8::consensus_decode(&mut d)?;
        let index = u64::consensus_decode(&mut d)?;
        let fee = u32::consensus_decode(&mut d)?;
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

impl Encodable for AssetUnlockBaseTransactionInfo {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += (AssetUnlock as u16).consensus_encode(&mut s)?;
        len += Vec::<TxIn>::new().consensus_encode(&mut s)?;
        len += self.output.consensus_encode(&mut s)?;
        len += self.lock_time.consensus_encode(&mut s)?;
        len += self.base_payload.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for AssetUnlockBaseTransactionInfo {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let mut d = d.take(MAX_VEC_SIZE as u64);
        let version = u16::consensus_decode(&mut d)?;
        let special_transaction_type_u16 = u16::consensus_decode(&mut d)?;
        let special_transaction_type = TransactionType::try_from(special_transaction_type_u16).map_err(|_| encode::Error::UnknownSpecialTransactionType(special_transaction_type_u16))?;
        if special_transaction_type != AssetUnlock {
            return Err(encode::Error::WrongSpecialTransactionPayloadConversion{ expected: AssetUnlock, actual: special_transaction_type})
        }
        Vec::<TxIn>::consensus_decode(&mut d)?; //no inputs
        Ok(AssetUnlockBaseTransactionInfo {
            version,
            output: Decodable::consensus_decode(&mut d)?,
            lock_time: Decodable::consensus_decode(&mut d)?,
            base_payload: AssetUnlockBasePayload::consensus_decode(d)?
        })
    }
}


