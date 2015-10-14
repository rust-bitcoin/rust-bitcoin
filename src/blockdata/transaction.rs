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
use serde;
use secp256k1::Secp256k1;

use util::hash::Sha256dHash;
use blockdata::script::{self, Script, ScriptTrace, read_scriptbool};
use blockdata::utxoset::UtxoSet;
use network::encodable::ConsensusEncodable;
use network::serialize::BitcoinHash;

/// A transaction input, which defines old coins to be consumed
#[derive(Clone, PartialEq, Eq, Debug)]
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

/// A transaction output, which defines new coins to be created from old ones.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxOut {
    /// The value of the output, in satoshis
    pub value: u64,
    /// The script which must satisfy for the output to be spent
    pub script_pubkey: Script
}

// This is used as a "null txout" in consensus signing code
impl Default for TxOut {
    fn default() -> TxOut {
        TxOut { value: 0xffffffffffffffff, script_pubkey: Script::new() }
    }
}

/// A Bitcoin transaction, which describes an authenticated movement of coins
#[derive(Clone, PartialEq, Eq, Debug)]
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

impl TxIn {
    /// Check an input's script for validity
    pub fn validate(&self,
                    secp: &Secp256k1,
                    utxoset: &UtxoSet,
                    txn: &Transaction,
                    index: usize) -> Result<(), Error> {
        let txo = utxoset.get_utxo(self.prev_hash, self.prev_index);
        match txo {
            Some((_, txo)) => {
                let (mut p2sh_stack, mut p2sh_script) = (vec![], Script::new());

                let mut stack = vec![];
                match self.script_sig.evaluate(secp, &mut stack, Some((txn, index)), None) {
                    Ok(_) => {}
                    Err(e) => { return Err(Error::InputScriptFailure(e)); }
                }
                if txo.script_pubkey.is_p2sh() && stack.len() > 0 {
                    p2sh_stack = stack.clone();
                    p2sh_script = match p2sh_stack.pop() {
                        Some(script::MaybeOwned::Owned(v)) => Script::from(v),
                        Some(script::MaybeOwned::Borrowed(s)) => Script::from(s.to_vec()),
                        None => unreachable!()
                    };
                }
                match txo.script_pubkey.evaluate(secp, &mut stack, Some((txn, index)), None) {
                    Ok(_) => {}
                    Err(e) => { return Err(Error::OutputScriptFailure(e)); }
                }
                match stack.pop() {
                    Some(v) => {
                        if !read_scriptbool(&v[..]) {
                            return Err(Error::ScriptReturnedFalse);
                        }
                     }
                    None => { return Err(Error::ScriptReturnedEmptyStack); }
                }
                if txo.script_pubkey.is_p2sh() {
                    match p2sh_script.evaluate(secp, &mut p2sh_stack, Some((txn, index)), None) {
                        Ok(_) => {}
                        Err(e) => { return Err(Error::P2shScriptFailure(e)); }
                    }
                    match p2sh_stack.pop() {
                        Some(v) => {
                            if !read_scriptbool(&v[..]) {
                                return Err(Error::P2shScriptReturnedFalse);
                            }
                        }
                        None => { return Err(Error::P2shScriptReturnedEmptyStack); }
                    }
                }
            }
            None => { return Err(Error::InputNotFound(self.prev_hash, self.prev_index)); }
        }
        Ok(())
    }
}

impl Transaction {
    /// Check a transaction for validity
    pub fn validate(&self, secp: &Secp256k1, utxoset: &UtxoSet) -> Result<(), Error> {
        for (n, input) in self.input.iter().enumerate() {
            try!(input.validate(secp, utxoset, self, n));
        }
        Ok(())
    }

    /// Produce a trace of a transaction's execution
    pub fn trace(&self, secp: &Secp256k1, utxoset: &UtxoSet) -> TransactionTrace {
        let mut ret = TransactionTrace { txid: self.bitcoin_hash(),
                                         inputs: Vec::with_capacity(self.input.len()) };
        for (n, input) in self.input.iter().enumerate() {
            // Setup trace
            let mut trace = InputTrace {
                input_txid: input.prev_hash,
                input_vout: input.prev_index as usize,
                sig_trace: ScriptTrace {
                    script: Script::new(),
                    initial_stack: vec![],
                    iterations: vec![],
                    error: None
                },
                pubkey_trace: None,
                p2sh_trace: None,
                error: None
            };
            // Run through the input
            let txo = utxoset.get_utxo(input.prev_hash, input.prev_index);
            match txo {
                Some((_, txo)) => {
                    let (mut p2sh_stack, mut p2sh_script) = (vec![], Script::new());

                    let mut stack = Vec::with_capacity(6);
                    trace.sig_trace = input.script_sig.trace(secp, &mut stack, Some((self, n)));
                    let err = trace.sig_trace.error.as_ref().map(|e| e.clone());
                    err.map(|e| trace.error = Some(Error::InputScriptFailure(e)));

                    if txo.script_pubkey.is_p2sh() && stack.len() > 0 {
                        p2sh_stack = stack.clone();
                        p2sh_script = match p2sh_stack.pop() {
                            Some(script::MaybeOwned::Owned(v)) => Script::from(v),
                            Some(script::MaybeOwned::Borrowed(s)) => Script::from(s.to_vec()),
                            None => unreachable!()
                        };
                    }
                    if trace.error.is_none() {
                        trace.pubkey_trace = Some(txo.script_pubkey.trace(secp, &mut stack, Some((self, n))));
                        let err = trace.pubkey_trace.as_ref().unwrap().error.as_ref().map(|e| e.clone());
                        err.map(|e| trace.error = Some(Error::OutputScriptFailure(e)));
                        match stack.pop() {
                            Some(v) => {
                                if !read_scriptbool(&v[..]) {
                                    trace.error = Some(Error::ScriptReturnedFalse);
                                }
                            }
                            None => { trace.error = Some(Error::ScriptReturnedEmptyStack); }
                        }
                        if trace.error.is_none() && txo.script_pubkey.is_p2sh() {
                            trace.p2sh_trace = Some(p2sh_script.trace(secp, &mut p2sh_stack, Some((self, n))));
                            let err = trace.p2sh_trace.as_ref().unwrap().error.as_ref().map(|e| e.clone());
                            err.map(|e| trace.error = Some(Error::P2shScriptFailure(e)));
                            match p2sh_stack.pop() {
                                Some(v) => {
                                    if !read_scriptbool(&v[..]) {
                                        trace.error = Some(Error::P2shScriptReturnedFalse);
                                    }
                                }
                                None => { trace.error = Some(Error::P2shScriptReturnedEmptyStack); }
                            }
                        }
                    }
                }
                None => {
                    trace.error = Some(Error::InputNotFound(input.prev_hash, input.prev_index));
                }
            }
            ret.inputs.push(trace);
        }
        ret
    }
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
    use super::{Transaction, TxIn};

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
}

