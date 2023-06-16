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

//! Dash Asset Lock Special Transaction.
//!
//! The asset lock special transaction is used to add to the asset lock credit pool.
//!
//!
//! It is defined in DIPX [dip-000X.md](https://github.com/dashpay/dips/blob/master/dip-000X.md) as follows:
//!
//!
//! The special transaction type used for AssetLockTx Transactions is 8.

use crate::prelude::*;
use crate::{io, VarInt};
use crate::consensus::{Decodable, Encodable, encode};
use crate::transaction::txout::TxOut;

/// An Asset Lock payload. This is contained as the payload of an asset lock special transaction.
/// The Asset Lock Special transaction and this payload is described in the Asset Lock DIP2X
/// (todo:update this).
/// An Asset Lock can fund multiple Identity registrations or top ups.
/// The Asset Lock payload credit outputs field contains a vector of TxOuts.
/// Each TxOut refers to a funding of an Identity.
///
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct AssetLockPayload {
    version: u8,
    credit_outputs: Vec<TxOut>,
}

impl AssetLockPayload {
    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        let size = 1 + VarInt(self.credit_outputs.len() as u64).len();
        size + self.credit_outputs.iter().map(|tx| tx.size()).sum::<usize>()
    }
}

impl Encodable for AssetLockPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += self.credit_outputs.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for AssetLockPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u8::consensus_decode(r)?;
        let credit_outputs = Vec::<TxOut>::consensus_decode(r)?;
        Ok(AssetLockPayload {
            version,
            credit_outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::consensus::Encodable;
    use crate::{ScriptBuf, TxOut};
    use crate::transaction::special_transaction::asset_lock::AssetLockPayload;

    #[test]
    fn size() {
        let want = 41;
        let tx1 = TxOut {
            value: 10,
            script_pubkey: ScriptBuf(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
        };
        let tx2 = TxOut {
            value: 11,
            script_pubkey: ScriptBuf(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1]),
        };
        let payload = AssetLockPayload {
            version: 1,
            credit_outputs: vec![tx1, tx2],
        };
        assert_eq!(payload.size(), want);
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(actual, want);
    }
}
