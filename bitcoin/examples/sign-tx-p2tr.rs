// SPDX-License-Identifier: CC0-1.0

//! Demonstrate creating a transaction that spends to and from p2tr outputs.

use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::key::{UntweakedPublicKey, XOnlyPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
const SPEND_AMOUNT: Amount = Amount::from_sat(5_000_000);
const CHANGE_AMOUNT: Amount = Amount::from_sat(14_999_000); // 1000 sat fee.

fn main() {
    let secp = Secp256k1::new();

    // In a real application these would come from a stored secret.
    let (sk, x_only) = senders_keys(&secp);
    let kp = sk.keypair(&secp);

    let address = receivers_address();

    // In a real application these would come from the chain.
    let (dummy_out_point, dummy_utxo) = dummy_unspent_transaction_output(&secp, x_only);

    let input = TxIn {
        previous_output: dummy_out_point, // The dummy output we are spending.
        script_sig: ScriptBuf::default(), // For a p2tr script_sig is empty.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(), // Filled in after signing.
    };

    // The spend output is locked to a key controlled by the receiver.
    let spend = TxOut { value: SPEND_AMOUNT, script_pubkey: address.script_pubkey() };

    // The change output is locked to a key controlled by us.
    let change = TxOut {
        value: CHANGE_AMOUNT,
        script_pubkey: ScriptBuf::new_v1_p2tr(&secp, x_only, None), // Change comes back to us.
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
        input: vec![input],                  // Input goes into index 0.
        output: vec![spend, change],
    };
    let input_index = 0;

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![dummy_utxo];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    let sig = sighash.sign_key_spend(&secp, &kp, sighash_type);

    sighasher.witness_mut(input_index).unwrap().push_taproot_signature(&sig);

    // BOOM! Transaction signed and ready to broadcast.
}

/// An example of keys controlled by the transaction sender.
///
/// In a real application these would be actual secrets.
fn senders_keys<C: Signing>(secp: &Secp256k1<C>) -> (SecretKey, XOnlyPublicKey) {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = bitcoin::PublicKey::from(sk.public_key(secp));

    (sk, pk.into())
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
fn dummy_unspent_transaction_output<C: Verification>(
    secp: &Secp256k1<C>,
    internal_key: UntweakedPublicKey,
) -> (OutPoint, TxOut) {
    let script_pubkey = ScriptBuf::new_v1_p2tr(secp, internal_key, None);

    let out_point = OutPoint {
        txid: Txid::all_zeros(), // Obviously invalid.
        vout: 0,
    };

    let utxo = TxOut { value: DUMMY_UTXO_AMOUNT, script_pubkey };

    (out_point, utxo)
}
