// Rust Bitcoin Library
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # BIP143 Implementation
//!
//! Implementation of BIP143 Segwit-style signatures. Should be sufficient
//! to create signatures for Segwit transactions (which should be pushed into
//! the appropriate place in the `Transaction::witness` array) or bcash
//! signatures, which are placed in the scriptSig.
//!

use blockdata::script::Script;
use blockdata::transaction::{Transaction, TxIn};
use network::encodable::ConsensusEncodable;
use util::hash::{Sha256dHash, Sha256dEncoder};

/// Parts of a sighash which are common across inputs or signatures, and which are
/// sufficient (in conjunction with a private key) to sign the transaction
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SighashComponents {
    tx_version: u32,
    tx_locktime: u32,
    /// Hash of all the previous outputs
    pub hash_prevouts: Sha256dHash,
    /// Hash of all the input sequence nos
    pub hash_sequence: Sha256dHash,
    /// Hash of all the outputs in this transaction
    pub hash_outputs: Sha256dHash,
}

impl SighashComponents {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// information about its inputs.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: &Transaction) -> SighashComponents {
        let hash_prevouts = {
            let mut enc = Sha256dEncoder::new();
            for txin in &tx.input {
                txin.prev_hash.consensus_encode(&mut enc).unwrap();
                txin.prev_index.consensus_encode(&mut enc).unwrap();
            }
            enc.into_hash()
        };

        let hash_sequence = {
            let mut enc = Sha256dEncoder::new();
            for txin in &tx.input {
                txin.sequence.consensus_encode(&mut enc).unwrap();
            }
            enc.into_hash()
        };

        let hash_outputs = {
            let mut enc = Sha256dEncoder::new();
            for txout in &tx.output {
                txout.consensus_encode(&mut enc).unwrap();
            }
            enc.into_hash()
        };

        SighashComponents {
            tx_version: tx.version,
            tx_locktime: tx.lock_time,
            hash_prevouts: hash_prevouts,
            hash_sequence: hash_sequence,
            hash_outputs: hash_outputs,
        }
    }

    /// Compute the BIP143 sighash for a `SIGHASH_ALL` signature for the given
    /// input.
    pub fn sighash_all(&self, txin: &TxIn, witness_script: &Script, value: u64) -> Sha256dHash {
        let mut enc = Sha256dEncoder::new();
        self.tx_version.consensus_encode(&mut enc).unwrap();
        self.hash_prevouts.consensus_encode(&mut enc).unwrap();
        self.hash_sequence.consensus_encode(&mut enc).unwrap();
        txin
            .prev_hash
            .consensus_encode(&mut enc)
            .unwrap();
        txin
            .prev_index
            .consensus_encode(&mut enc)
            .unwrap();
        witness_script.consensus_encode(&mut enc).unwrap();
        value.consensus_encode(&mut enc).unwrap();
        txin.sequence.consensus_encode(&mut enc).unwrap();
        self.hash_outputs.consensus_encode(&mut enc).unwrap();
        self.tx_locktime.consensus_encode(&mut enc).unwrap();
        1u32.consensus_encode(&mut enc).unwrap(); // hashtype
        enc.into_hash()
    }
}

#[cfg(test)]
mod tests {
    use hex::decode;

    use blockdata::transaction::Transaction;
    use network::serialize::deserialize;
    use util::misc::hex_bytes;

    use super::*;

    #[test]
    fn bip143_sig() {
        let tx = deserialize::<Transaction>(
            &hex_bytes(
            "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000\
             ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f\
             05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000").unwrap()[..],
        ).unwrap();

        let witness_script = hex_script!(
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28\
             bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b\
             9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58\
             c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b1486\
             2c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b\
             56ae"
        );
        let value = 987654321;

        let comp = SighashComponents::new(&tx);
        assert_eq!(
            comp,
            SighashComponents {
                tx_version: 1,
                tx_locktime: 0,
                hash_prevouts: hex_hash!(
                    "74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0"
                ),
                hash_sequence: hex_hash!(
                    "3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044"
                ),
                hash_outputs: hex_hash!(
                    "bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc"
                ),
            }
        );

        assert_eq!(
            comp.sighash_all(&tx.input[0], &witness_script, value),
            hex_hash!("185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c")
        );
    }
}
