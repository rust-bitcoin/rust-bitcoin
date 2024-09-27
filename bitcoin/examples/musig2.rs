// SPDX-License-Identifier: CC0-1.0

//! Demonstrate the musig2 module to create a multi-signature key and sign a message.

use std::str::FromStr;

use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapTweakHash, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey
};
use secp256k1::musig::{new_musig_nonce_pair, MusigAggNonce, MusigKeyAggCache, MusigSession, MusigSessionId};
use secp256k1::Keypair;

use bitcoin::address::script_pubkey::ScriptBufExt;
use bitcoin::key::TweakedPublicKey;

const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
const SPEND_AMOUNT: Amount = Amount::from_sat(5_000_000);
const CHANGE_AMOUNT: Amount = Amount::from_sat(14_999_000); // 1000 sat fee.

fn main() {
    let secp = Secp256k1::new();

    let secret_key_share_1 = SecretKey::new(&mut rand::thread_rng());
    let public_key_share_1 = secret_key_share_1.public_key(&secp);

    let secret_key_share_2 = SecretKey::new(&mut rand::thread_rng());
    let public_key_share_2 = secret_key_share_2.public_key(&secp);

    let public_keys = [public_key_share_1, public_key_share_2];

    let mut musig_key_agg_cache = MusigKeyAggCache::new(&secp, &public_keys);

    let tap_tweak = TapTweakHash::from_key_and_tweak(musig_key_agg_cache.agg_pk(), None);
    let tweak = tap_tweak.to_scalar();

    let tweaked_public_key = musig_key_agg_cache.pubkey_xonly_tweak_add(&secp, &tweak).unwrap();
    let x_only_tweaked_public_key = XOnlyPublicKey::from(tweaked_public_key);

    let (dummy_out_point, dummy_utxo, dummy_script_pubkey) = dummy_unspent_transaction_output(x_only_tweaked_public_key);

    let address = receivers_address();

    // The input for the transaction we are constructing.
    let input = TxIn {
        previous_output: dummy_out_point, // The dummy output we are spending.
        script_sig: ScriptBuf::default(), // For a p2tr script_sig is empty.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(), // Filled in after signing.
    };

    // The spend output is locked to a key controlled by the receiver.
    let spend = TxOut { value: SPEND_AMOUNT, script_pubkey: address.script_pubkey() };

    let change = TxOut {
        value: CHANGE_AMOUNT,
        script_pubkey: dummy_script_pubkey, // Change comes back to us.
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
    let sighash_type = TapSighashType::Default;
    let prevouts = vec![dummy_utxo];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    let msg_bytes = sighash.to_byte_array();
    let msg = secp256k1::Message::from(sighash);

    let musig_session_id = MusigSessionId::new(&mut rand::thread_rng());

    let nonce_pair1 = new_musig_nonce_pair(
        &secp, 
        musig_session_id, 
        Some(&musig_key_agg_cache),
        Some(secret_key_share_1), 
        public_key_share_1, 
        Some(msg), 
        None).unwrap();

    let musig_session_id = MusigSessionId::new(&mut rand::thread_rng());

    let nonce_pair2 = new_musig_nonce_pair(
        &secp, 
        musig_session_id, 
        Some(&musig_key_agg_cache),
        Some(secret_key_share_2), 
        public_key_share_2, 
        Some(msg), 
        None).unwrap();

    let sec_nonce1 = nonce_pair1.0;
    let pub_nonce1 = nonce_pair1.1;

    let sec_nonce2 = nonce_pair2.0;
    let pub_nonce2 = nonce_pair2.1;

    let agg_nonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);

    let session = MusigSession::new(&secp, &musig_key_agg_cache, agg_nonce, msg);

    let keypair1 = Keypair::from_secret_key(&secp, &secret_key_share_1);
    let partial_sign1 = session.partial_sign(&secp, sec_nonce1, &keypair1, &musig_key_agg_cache).unwrap();

    let keypair2 = Keypair::from_secret_key(&secp, &secret_key_share_2);
    let partial_sign2 = session.partial_sign(&secp, sec_nonce2, &keypair2, &musig_key_agg_cache).unwrap();

    let is_partial_signature_valid = session.partial_verify(&secp, &musig_key_agg_cache, partial_sign1, pub_nonce1, public_key_share_1);
    assert!(is_partial_signature_valid);

    let is_partial_signature_valid = session.partial_verify(&secp, &musig_key_agg_cache, partial_sign2, pub_nonce2, public_key_share_2);
    assert!(is_partial_signature_valid);

    let partial_sigs = [partial_sign1, partial_sign2];

    let sig64 = session.partial_sig_agg(&partial_sigs);

    let agg_pk = musig_key_agg_cache.agg_pk();

    assert!(secp.verify_schnorr(&sig64, &msg_bytes, &agg_pk).is_ok());

    println!("Signature created and validated sucessfully.");
}

/// A dummy address for the receiver.
///
/// We lock the spend output to the key associated with this address.
///
/// (FWIW this is an arbitrary mainnet address from block 805222.)
fn receivers_address() -> Address {
    Address::from_str("bc1p0dq0tzg2r780hldthn5mrznmpxsxc0jux5f20fwj0z3wqxxk6fpqm7q0va")
        .expect("a valid address")
        .require_network(Network::Bitcoin)
        .expect("valid address for mainnet")
}

/// Creates a p2tr output locked to the key associated with `tr`.
///
/// An utxo is described by the `OutPoint` (txid and index within the transaction that it was
/// created). Using the out point one can get the transaction by `txid` and using the `vout` get the
/// transaction value and script pubkey (`TxOut`) of the utxo.
///
/// This output is locked to keys that we control, in a real application this would be a valid
/// output taken from a transaction that appears in the chain.
fn dummy_unspent_transaction_output(
    output_key: XOnlyPublicKey,
) -> (OutPoint, TxOut, ScriptBuf) {
    let tweaked_public_key = TweakedPublicKey::dangerous_assume_tweaked(output_key);
    let script_pubkey = ScriptBuf::new_p2tr_tweaked(tweaked_public_key);

    let out_point = OutPoint {
        txid: Txid::all_zeros(), // Obviously invalid.
        vout: 0,
    };

    let utxo = TxOut { value: DUMMY_UTXO_AMOUNT, script_pubkey: script_pubkey.clone() };

    (out_point, utxo, script_pubkey)
}
