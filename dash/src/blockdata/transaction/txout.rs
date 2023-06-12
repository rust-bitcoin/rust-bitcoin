// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Refactored for Dash in 2022 by
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

//! Dash TxOut.
//!
//! A TxOut is an output of a transaction.
//!

use crate::{PubkeyHash, ScriptBuf, VarInt};
use crate::{Address, ScriptHash};
use crate::internal_macros::impl_consensus_encoding;

/// A transaction output, which defines new coins to be created from old ones.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct TxOut {
    /// The value of the output, in satoshis.
    pub value: u64,
    /// The script which must be satisfied for the output to be spent.
    pub script_pubkey: ScriptBuf,
}

// This is used as a "null txout" in consensus signing code.
// This is used as a "null txout" in consensus signing code.
impl Default for TxOut {
    fn default() -> TxOut { TxOut { value: 0xffffffffffffffff, script_pubkey: ScriptBuf::new() } }
}

impl TxOut {
    ///
    pub fn size(&self) -> usize {
        8 + VarInt(self.script_pubkey.len() as u64).len() + self.script_pubkey.len()
    }

    /// Convenience method to get an output from an address
    pub fn new_from_address(value: u64, address: &Address) -> Self {
        TxOut {
            value,
            script_pubkey: address.script_pubkey(),
        }
    }

    /// Convenience method to get an output from a pubkey hash
    pub fn new_from_p2pkh(value: u64, pubkey_hash: &PubkeyHash) -> Self {
        TxOut {
            value,
            script_pubkey: ScriptBuf::new_p2pkh(pubkey_hash),
        }
    }

    /// Convenience method to get an output from a script hash
    pub fn new_from_p2sh(value: u64, script_hash: &ScriptHash) -> Self {
        TxOut {
            value,
            script_pubkey: ScriptBuf::new_p2sh(script_hash),
        }
    }
}

impl_consensus_encoding!(TxOut, value, script_pubkey);