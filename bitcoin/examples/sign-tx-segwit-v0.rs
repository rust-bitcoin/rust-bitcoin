// SPDX-License-Identifier: CC0-1.0

//! Demonstrate creating a transaction that spends to and from p2wpkh outputs.

use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute;
use bitcoin::output::P2wpkh;
use bitcoin::secp256k1::{self, rand, Secp256k1, SecretKey, Signing};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
const SPEND_AMOUNT: Amount = Amount::from_sat(5_000_000);
const CHANGE_AMOUNT: Amount = Amount::from_sat(14_999_000); // 1000 sat fee.

fn main() {
    let secp = Secp256k1::new();

    // Get a secret key we control and its associated pubkey.
    // In a real application these would come from a stored secret.
    let (sk, pk) = senders_keys(&secp);

    // Get an address to send to.
    let address = receivers_address();

    // Get an unspent output that is locked to the key above that we control.
    // In a real application these would come from the chain.
    let (dummy_out_point, dummy_utxo) = dummy_unspent_transaction_output(pk);

    // The input for the transaction we are constructing.
    let input = TxIn {
        previous_output: dummy_out_point, // The dummy output we are spending.
        script_sig: P2wpkh::script_sig(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(), // Filled in after signing.
    };

    // The spend output is locked to a key controlled by the receiver.
    let spend = TxOut { value: SPEND_AMOUNT, script_pubkey: address.script_pubkey() };

    // The change output is locked to a key controlled by us.
    let change = TxOut {
        value: CHANGE_AMOUNT,
        script_pubkey: P2wpkh::script_pubkey(pk), // Change comes back to us.
    };

    // The transaction we want to sign and broadcast.
    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,  // Post BIP-68.
        lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
        input: vec![input],                  // Input goes into index 0.
        output: vec![spend, change],         // Outputs, order does not matter.
    };
    let input_index = 0;

    // Get the sighash to sign.
    let sighash_type = EcdsaSighashType::All;
    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .p2wpkh_signature_hash(input_index, &dummy_utxo.script_pubkey, SPEND_AMOUNT, sighash_type)
        .expect("failed to create sighash");

    let sig = sighash.sign(&secp, &sk, sighash_type);
    *sighasher.witness_mut(input_index).unwrap() = P2wpkh::witness(sig, pk);

    // Get the signed transaction.
    let tx = sighasher.into_transaction();

    // BOOM! Transaction signed and ready to broadcast.
    println!("{:#?}", tx);
}

/// An example of keys controlled by the transaction sender.
///
/// In a real application these would be actual secrets.
fn senders_keys<C: Signing>(secp: &Secp256k1<C>) -> (SecretKey, secp256k1::PublicKey) {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = sk.public_key(secp);

    (sk, pk)
}

/// A dummy address for the receiver.
///
/// We lock the spend output to the key associated with this address.
///
/// (FWIW this is a random mainnet address from block 80219.)
fn receivers_address() -> Address {
    Address::from_str("bc1q7cyrfmck2ffu2ud3rn5l5a8yv6f0chkp0zpemf")
        .expect("a valid address")
        .require_network(Network::Bitcoin)
        .expect("valid address for mainnet")
}

/// Creates a p2wpkh output locked to the key associated with `wpkh`.
///
/// An utxo is described by the `OutPoint` (txid and index within the transaction that it was
/// created). Using the out point one can get the transaction by `txid` and using the `vout` get the
/// transaction value and script pubkey (`TxOut`) of the utxo.
///
/// This output is locked to keys that we control, in a real application this would be a valid
/// output taken from a transaction that appears in the chain.
fn dummy_unspent_transaction_output(pk: secp256k1::PublicKey) -> (OutPoint, TxOut) {
    let out_point = OutPoint {
        txid: Txid::all_zeros(), // Obviously invalid.
        vout: 0,
    };

    let utxo = TxOut { value: DUMMY_UTXO_AMOUNT, script_pubkey: P2wpkh::script_pubkey(pk) };

    (out_point, utxo)
}
