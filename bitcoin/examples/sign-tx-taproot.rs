// SPDX-License-Identifier: CC0-1.0

//! Demonstrate creating a transaction that spends to and from p2tr outputs.
use bitcoin::address::Payload;
use bitcoin::consensus::Encodable;
use hex::DisplayHex;
use sha2::Digest;
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, TweakedKeypair, UntweakedPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness, WitnessProgram,
};

// the utxo to spend must be correct
const UTXO_TX_HASH: &'static str =
    "f2a992a90be0fa16a9268e4be91811ab662ddd9c3396ec5708251934e189f4bd";
const UTXO_INDEX: u32 = 1;
// the utxo amount must be correct or will get invalid sig
const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(22000);

const SPEND_AMOUNT: Amount = Amount::from_sat(3_000); // the amount to transfer to destination

// sats to spend on transaction
const FEE_SATS: u64 = 1000;

// use the tweaked address + secret key or with no tweak at all
// TWEAK should _not_ be used with remove signers or MPC integrations.
const USE_TWEAK: bool = false;

fn compute_taproot_address(raw_public_key: &[u8]) -> Address {
    let mut compressed_public_key = [0u8; 32];
    // only supports compressed public key (32 or 33 bytes)
    if raw_public_key.len() == 32 {
        compressed_public_key.clone_from_slice(&raw_public_key);
    } else {
        compressed_public_key.clone_from_slice(&raw_public_key[1..]);
    }
    Address::new(
        Network::Bitcoin,
        Payload::WitnessProgram(
            WitnessProgram::new(bitcoin::WitnessVersion::V1, &compressed_public_key).unwrap(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_address() {
        let pubkey_compressed = [
            2, 72, 55, 97, 163, 47, 209, 209, 152, 229, 247, 239, 184, 204, 243, 250, 234, 90, 9,
            142, 126, 17, 151, 85, 190, 164, 141, 214, 228, 28, 194, 23, 109,
        ];
        assert!(
            "bc1pfqmkrge068ge3e0ha7uveul6afdqnrn7zxt4t04y3htwg8xzzaksl5000u"
                == compute_taproot_address(&pubkey_compressed).to_string()
        )
    }
}

fn main() {
    let secp = Secp256k1::new();

    // Get a keypair we control. In a real application these would come from a stored secret.
    let keypair = senders_keys(&secp);

    let sender_address_ref = if USE_TWEAK {
        panic!("dont use tweak");
    } else {
        // Address::from_witness_program(WitnessProgram::new_p2tr(public_key_raw), KnownHrp::Mainnet)
        println!("{:?}", keypair.public_key().serialize());
        compute_taproot_address(&keypair.public_key().serialize())
    };

    println!("sender taproot address: {} (tweaked={})", sender_address_ref, USE_TWEAK);

    let (internal_key, _parity) = keypair.x_only_public_key();

    // Get an unspent output that is locked to the key above that we control.
    // In a real application these would come from the chain.
    let (dummy_out_point, dummy_utxo) = dummy_unspent_transaction_output(&secp, internal_key);

    // Get an address to send to.
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

    // The change output is locked to a key controlled by us.
    let change_amount: Amount = Amount::from_sat(
        // 1000 sat fee.
        DUMMY_UTXO_AMOUNT.to_sat() - SPEND_AMOUNT.to_sat() - FEE_SATS,
    );
    let change = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None), // Change comes back to us.
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

    let signature = if USE_TWEAK {
        // let sighash = sighasher
        //     .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        //     .expect("failed to construct sighash");
        // let msg = Message::from_digest(sighash.to_byte_array());

        // let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
        // secp.sign_schnorr(&msg, &tweaked.to_inner())
        panic!("dont use tweak")
    } else {
        println!("signing using k256 schnorr implementation, not prehashed.");

        // encode without pre-hashing, safe to use with remote signer.
        let mut signing_base = Vec::<u8>::new();
        sighasher
            .taproot_encode_signing_data_to(
                &mut signing_base,
                input_index,
                &prevouts,
                None,
                None,
                sighash_type,
            )
            .expect("encode taproot tx");

        let mut hasher = sha2::Sha256::new();
        hasher.update(b"TapSighash");
        let tag_hash = hasher.finalize().to_vec();

        // The taproot signing body is Sha256("TapSighash") || Sha256("TapSighash") || x
        let mut prefixed_signing_base = Vec::<u8>::new();
        prefixed_signing_base.extend(&tag_hash);
        prefixed_signing_base.extend(&tag_hash);
        prefixed_signing_base.extend(&signing_base);

        println!("signing_base: {}", prefixed_signing_base.as_hex());
        // pass key handle + signing base to remote signer
        let sig_bytes = remote_sign(&keypair, &prefixed_signing_base);

        bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap()
    };

    // Update the witness stack.
    let signature = bitcoin::taproot::Signature { sig: signature, hash_ty: sighash_type };
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    *sighasher.witness_mut(input_index).unwrap() = witness;

    // Get the signed transaction.
    let tx = sighasher.into_transaction();

    // BOOM! Transaction signed and ready to broadcast.
    let mut buffer = Vec::<u8>::new();
    // println!("{:#?}", tx);
    tx.consensus_encode(&mut buffer).unwrap();
    // can decode on: https://live.blockcypher.com/btc/decodetx/
    println!("btc tx hex:\n{}", buffer.as_hex());

    // try to broadcast by copying and pasting to:
    // https://mempool.space/tx/push
}

// Mock for a remote signer
fn remote_sign(keypair: &Keypair, payload: &Vec<u8>) -> Vec<u8> {
    use k256::ecdsa::signature::Signer;
    let secret_bytes = keypair.secret_bytes();
    let schnorr_key = k256::schnorr::SigningKey::from_bytes(&secret_bytes).unwrap();
    schnorr_key.sign(&payload).to_bytes().to_vec()
}

/// An example of keys controlled by the transaction sender.
///
/// In a real application these would be actual secrets.
fn senders_keys<C: Signing>(secp: &Secp256k1<C>) -> Keypair {
    let sk_hex = std::env::var("MAINNET_PRIVATE_KEY")
        .expect("must set 32 byte hex in variable: MAINNET_PRIVATE_KEY");
    let sk = SecretKey::from_str(&sk_hex).unwrap();
    Keypair::from_secret_key(secp, &sk)
}

/// A dummy address for the receiver.
///
/// We lock the spend output to the key associated with this address.
///
/// (FWIW this is an arbitrary mainnet address from block 805222.)
fn receivers_address() -> Address {
    Address::from_str("bc1p8gsj9wp5qsdjduvfe5trq34tr9n8720kw6r4ytw9pds6xra640tqqup53c")
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
    let script_pubkey = if USE_TWEAK {
        ScriptBuf::new_p2tr(secp, internal_key, None)
    } else {
        // assume the public key is already 'tweaked'
        ScriptBuf::new_p2tr_tweaked(internal_key.dangerous_assume_tweaked())
    };

    let out_point = OutPoint { txid: Txid::from_str(UTXO_TX_HASH).unwrap(), vout: UTXO_INDEX };

    let utxo = TxOut { value: DUMMY_UTXO_AMOUNT, script_pubkey };

    (out_point, utxo)
}
