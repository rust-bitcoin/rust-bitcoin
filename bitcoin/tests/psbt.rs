//! Tests PSBT integration vectors from BIP 174
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#test-vectors>

use core::convert::TryFrom;
use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::bip32::{ExtendedPrivKey, ExtendedPubKey, Fingerprint, IntoDerivationPath, KeySource};
use bitcoin::blockdata::opcodes::OP_0;
use bitcoin::blockdata::script;
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::hex::FromHex;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::script::PushBytes;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{
    absolute, Amount, Denomination, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};

const NETWORK: Network = Network::Testnet;

macro_rules! hex_script {
    ($s:expr) => {
        <ScriptBuf>::from_hex($s).unwrap()
    };
}

macro_rules! hex_psbt {
    ($s:expr) => {
        Psbt::deserialize(&<Vec<u8> as FromHex>::from_hex($s).unwrap())
    };
}

#[test]
fn bip174_psbt_workflow() {
    let secp = Secp256k1::new();

    //
    // Step 0: Create the extended private key from the test vector data.
    //

    let ext_priv = build_extended_private_key();
    let ext_pub = ExtendedPubKey::from_priv(&secp, &ext_priv);
    let parent_fingerprint = ext_pub.fingerprint();

    //
    // Step 1: The creator.
    //

    let tx = create_transaction();
    let psbt = create_psbt(tx);

    //
    // Step 2: The first updater.
    //

    let psbt = update_psbt(psbt, parent_fingerprint);

    //
    // Step 3: The second updater.
    //

    let psbt = update_psbt_with_sighash_all(psbt);

    //
    // Step 4: The first signer.
    //

    // Strings from BIP 174 test vector.
    let test_vector = vec![
        ("cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr", "m/0h/0h/0h"), // from_priv, into_derivation_path?
        ("cR6SXDoyfQrcp4piaiHE97Rsgta9mNhGTen9XeonVgwsh4iSgw6d", "m/0h/0h/2h"),
    ];

    // We pass the keys to the signer after doing verification to make explicit
    // that signer is only using these two keys.
    let keys = parse_and_verify_keys(&ext_priv, &test_vector);
    let psbt_1 = signer_one_sign(psbt.clone(), keys);

    //
    // Step 5: The second signer.
    //

    // Strings from BIP 174 test vector.
    let test_vector = vec![
        ("cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au", "m/0h/0h/1h"),
        ("cNBc3SWUip9PPm1GjRoLEJT6T41iNzCYtD7qro84FMnM5zEqeJsE", "m/0h/0h/3h"),
    ];

    let keys = parse_and_verify_keys(&ext_priv, &test_vector);
    let psbt_2 = signer_two_sign(psbt, keys);

    //
    // Step 6: Combiner the two signed PSBTs.
    //

    let combined = combine(psbt_1, psbt_2);

    //
    // Step 7: Finalize the PSBT.
    //

    let finalized = finalize(combined);

    //
    // Step 8: Extract the transaction.
    //

    let _tx = extract_transaction(finalized);

    //
    // Step 9: Test lexicographical PSBT combiner.
    //
    // Combine would be done earlier, at Step 6, in typical workflow.
    // We define it here to reflect the order of test vectors in BIP 174.
    //

    combine_lexicographically();
}

/// Attempts to build an extended private key from seed and also directly from a string.
fn build_extended_private_key() -> ExtendedPrivKey {
    // Strings from BIP 174 test vector.
    let extended_private_key = "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF";
    let seed = "cUkG8i1RFfWGWy5ziR11zJ5V4U4W3viSFCfyJmZnvQaUsd1xuF3T";

    let xpriv = ExtendedPrivKey::from_str(extended_private_key).unwrap();

    let sk = PrivateKey::from_wif(seed).unwrap();
    let seeded = ExtendedPrivKey::new_master(NETWORK, &sk.inner.secret_bytes()).unwrap();
    assert_eq!(xpriv, seeded);

    xpriv
}

/// Creates the initial transaction, called by the PSBT Creator.
fn create_transaction() -> Transaction {
    // Strings from BIP 174 test vector.
    let output_0 = TvOutput {
        amount: "1.49990000",
        script_pubkey: "0014d85c2b71d0060b09c9886aeb815e50991dda124d",
    };
    let output_1 = TvOutput {
        amount: "1.00000000",
        script_pubkey: "001400aea9a2e5f0f876a588df5546e8742d1d87008f",
    };
    let input_0 = TvInput {
        txid: "75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858",
        index: 0,
    };
    let input_1 = TvInput {
        txid: "1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83",
        index: 1,
    };
    struct TvOutput {
        amount: &'static str,
        script_pubkey: &'static str,
    }
    struct TvInput {
        txid: &'static str,
        index: u32,
    }

    Transaction {
        version: 2,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: input_0.txid.parse().expect("failed to parse txid"),
                    vout: input_0.index,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX, // Disable nSequence.
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: input_1.txid.parse().expect("failed to parse txid"),
                    vout: input_1.index,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_str_in(output_0.amount, Denomination::Bitcoin)
                    .expect("failed to parse amount")
                    .to_sat(),
                script_pubkey: ScriptBuf::from_hex(output_0.script_pubkey)
                    .expect("failed to parse script"),
            },
            TxOut {
                value: Amount::from_str_in(output_1.amount, Denomination::Bitcoin)
                    .expect("failed to parse amount")
                    .to_sat(),
                script_pubkey: ScriptBuf::from_hex(output_1.script_pubkey)
                    .expect("failed to parse script"),
            },
        ],
    }
}

/// Creates the initial PSBT, called by the Creator. Verifies against BIP 174 test vector.
fn create_psbt(tx: Transaction) -> Psbt {
    // String from BIP 174 test vector.
    let expected_psbt_hex = include_str!("data/create_psbt_hex");
    let expected_psbt = hex_psbt!(expected_psbt_hex).unwrap();

    let psbt = Psbt::from_unsigned_tx(tx).unwrap();

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Updates `psbt` according to the BIP, returns the newly updated PSBT. Verifies against BIP 174 test vector.
fn update_psbt(mut psbt: Psbt, fingerprint: Fingerprint) -> Psbt {
    // Strings from BIP 174 test vector.
    let previous_tx_0 = include_str!("data/previous_tx_0_hex");
    let previous_tx_1 = include_str!("data/previous_tx_1_hex");

    let redeem_script_0 = "5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae";
    let redeem_script_1 = "00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903";
    let witness_script = "522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae";

    // Public key and its derivation path (these are the child pubkeys for our `ExtendedPrivKey`,
    // can be verified by deriving the key using this derivation path).
    let pk_path = vec![
        ("029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f", "m/0h/0h/0h"),
        ("02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7", "m/0h/0h/1h"),
        ("03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc", "m/0h/0h/2h"),
        ("023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73", "m/0h/0h/3h"),
        ("03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771", "m/0h/0h/4h"),
        ("027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096", "m/0h/0h/5h"),
    ];

    let expected_psbt_hex = include_str!("data/update_1_psbt_hex");
    let expected_psbt = hex_psbt!(expected_psbt_hex).unwrap();

    let mut input_0 = psbt.inputs[0].clone();

    let v = Vec::from_hex(previous_tx_1).unwrap();
    let tx: Transaction = deserialize(&v).unwrap();
    input_0.non_witness_utxo = Some(tx);
    input_0.redeem_script = Some(hex_script!(redeem_script_0));
    input_0.bip32_derivation = bip32_derivation(fingerprint, &pk_path, vec![0, 1]);

    let mut input_1 = psbt.inputs[1].clone();

    let v = Vec::from_hex(previous_tx_0).unwrap();
    let tx: Transaction = deserialize(&v).unwrap();
    input_1.witness_utxo = Some(tx.output[1].clone());

    input_1.redeem_script = Some(hex_script!(redeem_script_1));
    input_1.witness_script = Some(hex_script!(witness_script));
    input_1.bip32_derivation = bip32_derivation(fingerprint, &pk_path, vec![2, 3]);

    psbt.inputs = vec![input_0, input_1];

    let mut output_0 = psbt.outputs[0].clone();
    output_0.bip32_derivation = bip32_derivation(fingerprint, &pk_path, vec![4]);

    let mut output_1 = psbt.outputs[1].clone();
    output_1.bip32_derivation = bip32_derivation(fingerprint, &pk_path, vec![5]);

    psbt.outputs = vec![output_0, output_1];

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// `pk_path` holds tuples of `(public_key, derivation_path)`. `indecies` is used to access the
/// `pk_path` vector. `fingerprint` is from the parent extended public key.
fn bip32_derivation(
    fingerprint: Fingerprint,
    pk_path: &[(&str, &str)],
    indecies: Vec<usize>,
) -> BTreeMap<secp256k1::PublicKey, KeySource> {
    let mut tree = BTreeMap::new();
    for i in indecies {
        let pk = pk_path[i].0;
        let path = pk_path[i].1;

        let pk = PublicKey::from_str(pk).unwrap();
        let path = path.into_derivation_path().unwrap();

        tree.insert(pk.inner, (fingerprint, path));
    }
    tree
}

/// Does the second update according to the BIP, returns the newly updated PSBT. Verifies against BIP 174 test vector.
fn update_psbt_with_sighash_all(mut psbt: Psbt) -> Psbt {
    let expected_psbt_hex = include_str!("data/update_2_psbt_hex");
    let expected_psbt = hex_psbt!(expected_psbt_hex).unwrap();

    let ty = PsbtSighashType::from_str("SIGHASH_ALL").unwrap();

    let mut input_0 = psbt.inputs[0].clone();
    input_0.sighash_type = Some(ty);
    let mut input_1 = psbt.inputs[1].clone();
    input_1.sighash_type = Some(ty);

    psbt.inputs = vec![input_0, input_1];

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Verifies the keys in the test vector are valid for the extended private key and derivation path.
fn parse_and_verify_keys(
    ext_priv: &ExtendedPrivKey,
    sk_path: &[(&str, &str)],
) -> BTreeMap<PublicKey, PrivateKey> {
    let secp = &Secp256k1::new();

    let mut key_map = BTreeMap::new();
    for (secret_key, derivation_path) in sk_path.iter() {
        let wif_priv = PrivateKey::from_wif(secret_key).expect("failed to parse key");

        let path =
            derivation_path.into_derivation_path().expect("failed to convert derivation path");
        let derived_priv =
            ext_priv.derive_priv(secp, &path).expect("failed to derive ext priv key").to_priv();
        assert_eq!(wif_priv, derived_priv);
        let derived_pub = derived_priv.public_key(secp);
        key_map.insert(derived_pub, derived_priv);
    }
    key_map
}

/// Does the first signing according to the BIP, returns the signed PSBT. Verifies against BIP 174 test vector.
fn signer_one_sign(psbt: Psbt, key_map: BTreeMap<bitcoin::PublicKey, PrivateKey>) -> Psbt {
    let expected_psbt_hex = include_str!("data/sign_1_psbt_hex");
    let expected_psbt = hex_psbt!(expected_psbt_hex).unwrap();

    let psbt = sign(psbt, key_map);

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Does the second signing according to the BIP, returns the signed PSBT. Verifies against BIP 174 test vector.
fn signer_two_sign(psbt: Psbt, key_map: BTreeMap<bitcoin::PublicKey, PrivateKey>) -> Psbt {
    let expected_psbt_hex = include_str!("data/sign_2_psbt_hex");
    let expected_psbt = hex_psbt!(expected_psbt_hex).unwrap();

    let psbt = sign(psbt, key_map);

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Does the combine according to the BIP, returns the combined PSBT. Verifies against BIP 174 test vector.
fn combine(mut this: Psbt, that: Psbt) -> Psbt {
    let expected_psbt_hex = include_str!("data/combine_psbt_hex");
    let expected_psbt = hex_psbt!(expected_psbt_hex).unwrap();

    this.combine(that).expect("failed to combine PSBTs");

    assert_eq!(this, expected_psbt);
    this
}

/// Does the finalize step according to the BIP, returns the combined PSBT. Verifies against BIP 174
/// test vector.
fn finalize(psbt: Psbt) -> Psbt {
    let expected_psbt_hex = include_str!("data/finalize_psbt_hex");
    let expected_psbt = hex_psbt!(expected_psbt_hex).unwrap();

    let psbt = finalize_psbt(psbt);

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Does the transaction extractor step according to the BIP, returns the combined PSBT. Verifies
/// against BIP 174 test vector.
fn extract_transaction(psbt: Psbt) -> Transaction {
    let expected_tx_hex = include_str!("data/extract_tx_hex");

    let tx = psbt.extract_tx();

    let got = serialize_hex(&tx);
    assert_eq!(got, expected_tx_hex);

    tx
}

/// Combines two PSBTs lexicographically according to the BIP. Verifies against BIP 174 test vector.
fn combine_lexicographically() {
    let psbt_1_hex = include_str!("data/lex_psbt_1_hex");
    let psbt_2_hex = include_str!("data/lex_psbt_2_hex");

    let expected_psbt_hex = include_str!("data/lex_combine_psbt_hex");
    let expected_psbt = hex_psbt!(expected_psbt_hex).unwrap();

    let v = Vec::from_hex(psbt_1_hex).unwrap();
    let mut psbt_1 = Psbt::deserialize(&v).expect("failed to deserialize psbt 1");

    let v = Vec::from_hex(psbt_2_hex).unwrap();
    let psbt_2 = Psbt::deserialize(&v).expect("failed to deserialize psbt 2");

    psbt_1.combine(psbt_2).expect("failed to combine PSBTs");

    assert_eq!(psbt_1, expected_psbt);
}

/// Signs `psbt` with `keys` if required.
fn sign(mut psbt: Psbt, keys: BTreeMap<bitcoin::PublicKey, PrivateKey>) -> Psbt {
    let secp = Secp256k1::new();
    psbt.sign(&keys, &secp).unwrap();
    psbt
}

/// Finalizes a PSBT accord to the Input Finalizer role described in BIP 174.
/// This is just a test. For a production-ready PSBT Finalizer, use [rust-miniscript](https://docs.rs/miniscript/latest/miniscript/psbt/trait.PsbtExt.html#tymethod.finalize)
fn finalize_psbt(mut psbt: Psbt) -> Psbt {
    // Input 0: legacy UTXO

    let sigs: Vec<_> = psbt.inputs[0].partial_sigs.values().collect();
    let script_sig = script::Builder::new()
        .push_opcode(OP_0) // OP_CHECKMULTISIG bug pops +1 value when evaluating so push OP_0.
        .push_slice(sigs[0].serialize())
        .push_slice(sigs[1].serialize())
        .push_slice(
            <&PushBytes>::try_from(psbt.inputs[0].redeem_script.as_ref().unwrap().as_bytes())
                .unwrap(),
        )
        .into_script();

    psbt.inputs[0].final_script_sig = Some(script_sig);

    psbt.inputs[0].partial_sigs = BTreeMap::new();
    psbt.inputs[0].sighash_type = None;
    psbt.inputs[0].redeem_script = None;
    psbt.inputs[0].bip32_derivation = BTreeMap::new();

    // Input 1: SegWit UTXO

    let script_sig = script::Builder::new()
        .push_slice(
            <&PushBytes>::try_from(psbt.inputs[1].redeem_script.as_ref().unwrap().as_bytes())
                .unwrap(),
        )
        .into_script();

    psbt.inputs[1].final_script_sig = Some(script_sig);

    let script_witness = {
        let sigs: Vec<_> = psbt.inputs[1].partial_sigs.values().collect();
        let mut script_witness = Witness::new();
        script_witness.push([]); // Push 0x00 to the stack.
        script_witness.push(&sigs[1].to_vec());
        script_witness.push(&sigs[0].to_vec());
        script_witness.push(psbt.inputs[1].witness_script.clone().unwrap().as_bytes());

        script_witness
    };

    psbt.inputs[1].final_script_witness = Some(script_witness);

    psbt.inputs[1].partial_sigs = BTreeMap::new();
    psbt.inputs[1].sighash_type = None;
    psbt.inputs[1].redeem_script = None;
    psbt.inputs[1].witness_script = None;
    psbt.inputs[1].bip32_derivation = BTreeMap::new();

    psbt
}
