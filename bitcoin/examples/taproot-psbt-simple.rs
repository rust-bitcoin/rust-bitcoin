//! Implements a simple multi-input PSBT signing example
//!
//! The purpose of this section is to construct a PSBT that spends multiple inputs and signs it.
//! We'll cover the following [BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
//!  roles:
//!
//! - **Creator**: Creates a PSBT with multiple inputs and outputs.
//! - **Updater**: Adds Witness and Taproot data to the PSBT.
//! - **Signer**: Signs the PSBT.
//! - **Finalizer**: Finalizes the PSBT.
//!
//! The example will focus on spending two Taproot inputs:
//!
//! 1. 20,000,000 satoshi UTXO, the first receiving ("external") address.
//! 1. 10,000,000 satoshi UTXO, the first change ("internal") address.
//!
//! We'll be sending this to two outputs:
//!
//! 1. 25,000,000 satoshis to a receivers' address.
//! 1. 4,990,000 satoshis back to us as change.
//!
//! The miner's fee will be 10,000 satoshis.
use std::collections::BTreeMap;

use bitcoin::address::script_pubkey::ScriptBufExt as _;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, IntoDerivationPath, Xpriv, Xpub};
use bitcoin::key::UntweakedPublicKey;
use bitcoin::locktime::absolute;
use bitcoin::psbt::Input;
use bitcoin::secp256k1::{Secp256k1, Signing};
use bitcoin::{
    consensus, transaction, Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence,
    TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};

// The master xpriv, from which we derive the keys we control.
const XPRIV: &str = "xprv9tuogRdb5YTgcL3P8Waj7REqDuQx4sXcodQaWTtEVFEp6yRKh1CjrWfXChnhgHeLDuXxo2auDZegMiVMGGxwxcrb2PmiGyCngLxvLeGsZRq";

// The derivation path for the keys we control.
// This follows the BIP 86 derivation path for Bitcoin.
const BIP86_DERIVATION_PATH: &str = "m/86'/0'/0'";

// The master fingerprint of the master xpriv.
const MASTER_FINGERPRINT: &str = "9680603f";

// The dummy UTXO amounts we are spending.
const DUMMY_UTXO_AMOUNT_INPUT_1: Amount = Amount::from_sat(20_000_000);
const DUMMY_UTXO_AMOUNT_INPUT_2: Amount = Amount::from_sat(10_000_000);

// The amounts we are sending to someone, and receiving back as change.
const SPEND_AMOUNT: Amount = Amount::from_sat(25_000_000);
const CHANGE_AMOUNT: Amount = Amount::from_sat(4_990_000); // 10_000 sat fee.

// Derive the external address xpriv.
fn get_external_address_xpriv<C: Signing>(
    secp: &Secp256k1<C>,
    master_xpriv: Xpriv,
    index: u32,
) -> Xpriv {
    let derivation_path =
        BIP86_DERIVATION_PATH.into_derivation_path().expect("valid derivation path");
    let child_xpriv = master_xpriv.derive_priv(secp, &derivation_path);
    let external_index = ChildNumber::ZERO_NORMAL;
    let idx = ChildNumber::from_normal_idx(index).expect("valid index number");

    child_xpriv.derive_priv(secp, &[external_index, idx])
}

// Derive the internal address xpriv.
fn get_internal_address_xpriv<C: Signing>(
    secp: &Secp256k1<C>,
    master_xpriv: Xpriv,
    index: u32,
) -> Xpriv {
    let derivation_path =
        BIP86_DERIVATION_PATH.into_derivation_path().expect("valid derivation path");
    let child_xpriv = master_xpriv.derive_priv(secp, &derivation_path);
    let internal_index = ChildNumber::ONE_NORMAL;
    let idx = ChildNumber::from_normal_idx(index).expect("valid index number");

    child_xpriv.derive_priv(secp, &[internal_index, idx])
}

// Get the Taproot Key Origin.
fn get_tap_key_origin(
    x_only_key: UntweakedPublicKey,
    master_fingerprint: Fingerprint,
    path: DerivationPath,
) -> BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, (Fingerprint, DerivationPath))> {
    let mut map = BTreeMap::new();
    map.insert(x_only_key, (vec![], (master_fingerprint, path)));
    map
}

// The address to send to.
fn receivers_address() -> Address {
    "bc1p0dq0tzg2r780hldthn5mrznmpxsxc0jux5f20fwj0z3wqxxk6fpqm7q0va".parse::<Address<_>>()
        .expect("a valid address")
        .require_network(Network::Bitcoin)
        .expect("valid address for mainnet")
}

// The dummy unspent transaction outputs that we control.
fn dummy_unspent_transaction_outputs() -> Vec<(OutPoint, TxOut)> {
    let script_pubkey_1 =
        "bc1p80lanj0xee8q667aqcnn0xchlykllfsz3gu5skfv9vjsytaujmdqtv52vu".parse::<Address<_>>()
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
            .script_pubkey();

    let out_point_1 = OutPoint {
        txid: Txid::all_zeros(), // Obviously invalid.
        vout: 0,
    };

    let utxo_1 = TxOut { value: DUMMY_UTXO_AMOUNT_INPUT_1, script_pubkey: script_pubkey_1 };

    let script_pubkey_2 =
        "bc1pfd0jmmdnp278vppcw68tkkmquxtq50xchy7f6wdmjtjm7fgsr8dszdcqce".parse::<Address<_>>()
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
            .script_pubkey();

    let out_point_2 = OutPoint {
        txid: Txid::all_zeros(), // Obviously invalid.
        vout: 1,
    };

    let utxo_2 = TxOut { value: DUMMY_UTXO_AMOUNT_INPUT_2, script_pubkey: script_pubkey_2 };
    vec![(out_point_1, utxo_1), (out_point_2, utxo_2)]
}

fn main() {
    let secp = Secp256k1::new();

    // Get the individual xprivs we control. In a real application these would come from a stored secret.
    let master_xpriv = XPRIV.parse::<Xpriv>().expect("valid xpriv");
    let xpriv_input_1 = get_external_address_xpriv(&secp, master_xpriv, 0);
    let xpriv_input_2 = get_internal_address_xpriv(&secp, master_xpriv, 0);
    let xpriv_change = get_internal_address_xpriv(&secp, master_xpriv, 1);

    // Get the PKs
    let (pk_input_1, _) = Xpub::from_priv(&secp, &xpriv_input_1).public_key.x_only_public_key();
    let (pk_input_2, _) = Xpub::from_priv(&secp, &xpriv_input_2).public_key.x_only_public_key();
    let (pk_change, _) = Xpub::from_priv(&secp, &xpriv_change).public_key.x_only_public_key();

    // Get the Tap Key Origins
    // Map of tap root X-only keys to origin info and leaf hashes contained in it.
    let origin_input_1 = get_tap_key_origin(
        pk_input_1,
        MASTER_FINGERPRINT.parse::<Fingerprint>().unwrap(),
        "m/86'/0'/0'/0/0".parse::<DerivationPath>().unwrap(),
    );
    let origin_input_2 = get_tap_key_origin(
        pk_input_2,
        MASTER_FINGERPRINT.parse::<Fingerprint>().unwrap(),
        "m/86'/0'/0'/1/0".parse::<DerivationPath>().unwrap(),
    );
    let origins = [origin_input_1, origin_input_2];

    // Get the unspent outputs that are locked to the key above that we control.
    // In a real application these would come from the chain.
    let utxos: Vec<TxOut> =
        dummy_unspent_transaction_outputs().into_iter().map(|(_, utxo)| utxo).collect();

    // Get the addresses to send to.
    let address = receivers_address();

    // The inputs for the transaction we are constructing.
    let inputs: Vec<TxIn> = dummy_unspent_transaction_outputs()
        .into_iter()
        .map(|(outpoint, _)| TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        })
        .collect();

    // The spend output is locked to a key controlled by the receiver.
    let spend = TxOut { value: SPEND_AMOUNT, script_pubkey: address.script_pubkey() };

    // The change output is locked to a key controlled by us.
    let change = TxOut {
        value: CHANGE_AMOUNT,
        script_pubkey: ScriptBuf::new_p2tr(&secp, pk_change, None), // Change comes back to us.
    };

    // The transaction we want to sign and broadcast.
    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,  // Post BIP 68.
        lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
        input: inputs,                       // Input is 0-indexed.
        output: vec![spend, change],         // Outputs, order does not matter.
    };

    // Now we'll start the PSBT workflow.
    // Step 1: Creator role; that creates,
    // and add inputs and outputs to the PSBT.
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("could not create PSBT");

    // Step 2:Updater role; that adds additional
    // information to the PSBT.
    let ty = TapSighashType::All.into();
    psbt.inputs = vec![
        Input {
            witness_utxo: Some(utxos[0].clone()),
            tap_key_origins: origins[0].clone(),
            tap_internal_key: Some(pk_input_1),
            sighash_type: Some(ty),
            ..Default::default()
        },
        Input {
            witness_utxo: Some(utxos[1].clone()),
            tap_key_origins: origins[1].clone(),
            tap_internal_key: Some(pk_input_2),
            sighash_type: Some(ty),
            ..Default::default()
        },
    ];

    // Step 3: Signer role; that signs the PSBT.
    psbt.sign(&master_xpriv, &secp).expect("valid signature");

    // Step 4: Finalizer role; that finalizes the PSBT.
    psbt.inputs.iter_mut().for_each(|input| {
        let script_witness = Witness::p2tr_key_spend(&input.tap_key_sig.unwrap());
        input.final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });

    // BOOM! Transaction signed and ready to broadcast.
    let signed_tx = psbt.extract_tx().expect("valid transaction");
    let serialized_signed_tx = consensus::encode::serialize_hex(&signed_tx);
    println!("Transaction Details: {:#?}", signed_tx);
    // check with:
    // bitcoin-cli decoderawtransaction <RAW_TX> true
    println!("Raw Transaction: {}", serialized_signed_tx);
}
