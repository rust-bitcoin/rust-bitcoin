// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Bitcoin Transaction
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.
//!

use std::default::Default;
use std::fmt;
use serde;

use util::hash::Sha256dHash;
use blockdata::script::{self, Script, ScriptTrace};
use network::encodable::ConsensusEncodable;
use network::serialize::BitcoinHash;

/// A reference to a transaction output
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct TxOutRef {
    /// The referenced transaction's txid
    pub txid: Sha256dHash,
    /// The index of the referenced output in its transaction's vout
    pub index: usize
}
serde_struct_impl!(TxOutRef, txid, index);

impl fmt::Display for TxOutRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.index)
    }
}

/// A transaction input, which defines old coins to be consumed
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct TxIn {
    /// The hash of the transaction whose output is being used an an input
    pub prev_hash: Sha256dHash,
    /// The index of the output in the previous transaction, which may have several
    pub prev_index: u32,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to accept
    pub script_sig: Script,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    pub sequence: u32,
}
serde_struct_impl!(TxIn, prev_hash, prev_index, script_sig, sequence);

/// A transaction output, which defines new coins to be created from old ones.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct TxOut {
    /// The value of the output, in satoshis
    pub value: u64,
    /// The script which must satisfy for the output to be spent
    pub script_pubkey: Script
}
serde_struct_impl!(TxOut, value, script_pubkey);

// This is used as a "null txout" in consensus signing code
impl Default for TxOut {
    fn default() -> TxOut {
        TxOut { value: 0xffffffffffffffff, script_pubkey: Script::new() }
    }
}

/// A Bitcoin transaction, which describes an authenticated movement of coins
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Transaction {
    /// The protocol version, should always be 1.
    pub version: u32,
    /// Block number before which this transaction is valid, or 0 for
    /// valid immediately.
    pub lock_time: u32,
    /// List of inputs
    pub input: Vec<TxIn>,
    /// List of outputs
    pub output: Vec<TxOut>
}
serde_struct_impl!(Transaction, version, lock_time, input, output);

impl Transaction {
    /// Computes a "normalized TXID" which does not include any signatures.
    /// This gives a way to identify a transaction that is ``the same'' as
    /// another in the sense of having same inputs and outputs.
    pub fn ntxid(&self) -> Sha256dHash {
        let cloned_tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self.input.iter().map(|txin| TxIn { script_sig: Script::new(), .. *txin }).collect(),
            output: self.output.clone()
        };
        cloned_tx.bitcoin_hash()
    }
}

/// A transaction error
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Error {
    /// Concatenated script failed in the input half (script error)
    InputScriptFailure(script::Error),
    /// Concatenated script failed in the output half (script error)
    OutputScriptFailure(script::Error),
    /// P2SH serialized script failed (script error)
    P2shScriptFailure(script::Error),
    /// P2SH serialized script ended with false at the top of the stack 
    P2shScriptReturnedFalse,
    /// P2SH serialized script ended with nothing in the stack
    P2shScriptReturnedEmptyStack,
    /// Script ended with false at the top of the stack 
    ScriptReturnedFalse,
    /// Script ended with nothing in the stack
    ScriptReturnedEmptyStack,
    /// Script ended with nothing in the stack (input txid, input vout)
    InputNotFound(Sha256dHash, u32),
}
display_from_debug!(Error);

impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer,
    {
        serializer.visit_str(&self.to_string())
    }
}

/// A trace of a transaction input's script execution
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct InputTrace {
    input_txid: Sha256dHash,
    input_vout: usize,
    sig_trace: ScriptTrace,
    pubkey_trace: Option<ScriptTrace>,
    p2sh_trace: Option<ScriptTrace>,
    error: Option<Error>
}

/// A trace of a transaction's execution
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct TransactionTrace {
    txid: Sha256dHash,
    inputs: Vec<InputTrace>
}

impl BitcoinHash for Transaction {
    fn bitcoin_hash(&self) -> Sha256dHash {
        use network::serialize::serialize;
        Sha256dHash::from_data(&serialize(self).unwrap())
    }
}

impl_consensus_encoding!(TxIn, prev_hash, prev_index, script_sig, sequence);
impl_consensus_encoding!(TxOut, value, script_pubkey);
impl_consensus_encoding!(Transaction, version, input, output, lock_time);

#[cfg(test)]
mod tests {
    use strason;

    use super::{Transaction, TxIn};

    use blockdata::script::Script;
    use network::serialize::BitcoinHash;
    use network::serialize::deserialize;
    use util::misc::hex_bytes;

    #[test]
    fn test_txin() {
        let txin: Result<TxIn, _> = deserialize(&hex_bytes("a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff").unwrap());
        assert!(txin.is_ok());
    }

    #[test]
    fn test_transaction() {
        let hex_tx = hex_bytes("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Result<Transaction, _> = deserialize(&hex_tx);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(realtx.version, 1);
        assert_eq!(realtx.input.len(), 1);
        // In particular this one is easy to get backward -- in bitcoin hashes are encoded
        // as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(realtx.input[0].prev_hash.be_hex_string(),
                   "ce9ea9f6f5e422c6a9dbcddb3b9a14d1c78fab9ab520cb281aa2a74a09575da1".to_string());
        assert_eq!(realtx.input[0].prev_index, 1);
        assert_eq!(realtx.output.len(), 1);
        assert_eq!(realtx.lock_time, 0);

        assert_eq!(realtx.bitcoin_hash().be_hex_string(),
                   "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string());
    }

    #[test]
    fn test_ntxid() {
        let hex_tx = hex_bytes("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let mut tx: Transaction = deserialize(&hex_tx).unwrap();

        let old_ntxid = tx.ntxid();
        assert_eq!(old_ntxid.be_hex_string(), "c3573dbea28ce24425c59a189391937e00d255150fa973d59d61caf3a06b601d");
        // changing sigs does not affect it
        tx.input[0].script_sig = Script::new();
        assert_eq!(old_ntxid, tx.ntxid());
        // changing pks does
        tx.output[0].script_pubkey = Script::new();
        assert!(old_ntxid != tx.ntxid());
    }

    #[test]
    fn test_txn_encode_decode() {
        let hex_tx = hex_bytes("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&hex_tx).unwrap();

        let encoded = strason::from_serialize(&tx).unwrap();
        let decoded = encoded.into_deserialize().unwrap();
        assert_eq!(tx, decoded);
    }
}

