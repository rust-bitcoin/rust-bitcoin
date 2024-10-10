#![cfg(not(feature = "rand-std"))]

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::psbt::{GetKey, Input, KeyRequest, PsbtSighashType, SignError};
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute, script, Address, Network, OutPoint, PrivateKey, Psbt, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use secp256k1::{Keypair, Secp256k1, Signing, XOnlyPublicKey};
use units::Amount;

#[test]
fn psbt_sign_taproot() {
    struct Keystore {
        sk: PrivateKey,
        mfp: Fingerprint,
    }

    impl GetKey for Keystore {
        type Error = SignError;
        fn get_key<C: Signing>(
            &self,
            key_request: KeyRequest,
            _secp: &Secp256k1<C>,
        ) -> Result<Option<PrivateKey>, Self::Error> {
            match key_request {
                KeyRequest::Bip32((mfp, _)) => {
                    if mfp == self.mfp {
                        Ok(Some(self.sk))
                    } else {
                        Err(SignError::KeyNotFound)
                    }
                }
                _ => Err(SignError::KeyNotFound),
            }
        }
    }

    let secp = &Secp256k1::new();

    let sk_path = [
        ("dff1c8c2c016a572914b4c5adb8791d62b4768ae9d0a61be8ab94cf5038d7d90", "m/86'/1'/0'/0/0"),
        ("1ede31b0e7e47c2afc65ffd158b1b1b9d3b752bba8fd117dc8b9e944a390e8d9", "m/86'/1'/0'/0/1"),
        ("1fb777f1a6fb9b76724551f8bc8ad91b77f33b8c456d65d746035391d724922a", "m/86'/1'/0'/0/2"),
    ];
    let mfp = "73c5da0a";

    //
    // Step 0: Create P2TR address.
    //

    // Create three basic scripts to test script path spend.
    let script1 = create_basic_single_sig_script(secp, sk_path[0].0); // m/86'/1'/0'/0/0
    let script2 = create_basic_single_sig_script(secp, sk_path[1].0); // m/86'/1'/0'/0/1
    let script3 = create_basic_single_sig_script(secp, sk_path[2].0); // m/86'/1'/0'/0/2

    // Just use one of the secret keys for the key path spend.
    let kp = Keypair::from_seckey_str(secp, &sk_path[2].0).expect("failed to create keypair");

    let internal_key = kp.x_only_public_key().0; // Ignore the parity.

    let tree =
        create_taproot_tree(secp, script1.clone(), script2.clone(), script3.clone(), internal_key);

    let address = create_p2tr_address(tree.clone());
    assert_eq!(
        "tb1pytee2mxz0f4fkrsqqws2lsgnkp8nrw2atjkjy2n9gahggsphr0gszaxxmv",
        address.to_string()
    );

    // m/86'/1'/0'/0/7
    let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
    let to_address = Address::from_str(to_address).unwrap().assume_checked();

    // key path spend
    {
        //
        // Step 1: create psbt for key path spend.
        //
        let mut psbt_key_path_spend = create_psbt_for_taproot_key_path_spend(
            address.clone(),
            to_address.clone(),
            tree.clone(),
        );

        //
        // Step 2: sign psbt.
        //
        let keystore = Keystore {
            mfp: Fingerprint::from_str(mfp).unwrap(),
            sk: PrivateKey::new(kp.secret_key(), Network::Testnet(bitcoin::TestnetVersion::V3)),
        };
        let _ = psbt_key_path_spend.sign(&keystore, secp);

        let sig = "92864dc9e56b6260ecbd54ec16b94bb597a2e6be7cca0de89d75e17921e0e1528cba32dd04217175c237e1835b5db1c8b384401718514f9443dce933c6ba9c87";
        assert_eq!(sig, psbt_key_path_spend.inputs[0].tap_key_sig.unwrap().signature.to_string());

        //
        // Step 3: finalize psbt.
        //
        let final_psbt = finalize_psbt_for_key_path_spend(psbt_key_path_spend);
        let tx = final_psbt.extract_tx().unwrap();

        let tx_id = "5306516f2032d9f34c9f2f6d2b1b8ad2486ef1ba196d8d8d780e59773e48ad6d";
        assert_eq!(tx_id, tx.compute_txid().to_string());

        let tx_bytes = "020000000001013aee4d6b51da574900e56d173041115bd1e1d01d4697a845784cf716a10c98060000000000ffffffff0100190000000000002251202258f2d4637b2ca3fd27614868b33dee1a242b42582d5474f51730005fa99ce8014092864dc9e56b6260ecbd54ec16b94bb597a2e6be7cca0de89d75e17921e0e1528cba32dd04217175c237e1835b5db1c8b384401718514f9443dce933c6ba9c8700000000";
        let tx_hex = serialize_hex(&tx);
        assert_eq!(tx_bytes, tx_hex);
    }

    // script path spend
    {
        // use private key of path "m/86'/1'/0'/0/1" as signing key
        let kp = Keypair::from_seckey_str(secp, &sk_path[1].0).expect("failed to create keypair");
        let x_only_pubkey = kp.x_only_public_key().0;
        let signing_key_path = sk_path[1].1;

        let keystore = Keystore {
            mfp: Fingerprint::from_str(mfp).unwrap(),
            sk: PrivateKey::new(kp.secret_key(), Network::Testnet(bitcoin::TestnetVersion::V3)),
        };

        //
        // Step 1: create psbt for script path spend.
        //
        let mut psbt_script_path_spend = create_psbt_for_taproot_script_path_spend(
            address.clone(),
            to_address.clone(),
            tree.clone(),
            x_only_pubkey,
            signing_key_path,
            script2.clone(),
        );

        //
        // Step 2: sign psbt.
        //
        let _ = psbt_script_path_spend.sign(&keystore, secp);

        let sig = "9c1466e1631a58c55fcb8642ce5f7896314f4b565d92c5c80b17aa9abf56d22e0b5e5dcbcfe836bbd7d409491f58aa9e1f68a491ef8f05eef62fb50ffac85727";
        assert_eq!(
            sig,
            psbt_script_path_spend.inputs[0]
                .tap_script_sigs
                .get(&(x_only_pubkey, script2.clone().tapscript_leaf_hash()))
                .unwrap()
                .signature
                .to_string()
        );

        //
        // Step 3: finalize psbt.
        //
        let final_psbt = finalize_psbt_for_script_path_spend(psbt_script_path_spend);
        let tx = final_psbt.extract_tx().unwrap();

        let tx_id = "a51f723beffc810248809355ba9c9e4b39c6e55c08429f0aeaa79b73f18bc2a6";
        assert_eq!(tx_id, tx.compute_txid().to_string());

        let tx_hex = serialize_hex(&tx);
        let tx_bytes = "0200000000010176a3c94a6b21d742e8ca192130ad10fdfc4c83510cb6baba8572a5fc70677c9d0000000000ffffffff0170170000000000002251202258f2d4637b2ca3fd27614868b33dee1a242b42582d5474f51730005fa99ce803419c1466e1631a58c55fcb8642ce5f7896314f4b565d92c5c80b17aa9abf56d22e0b5e5dcbcfe836bbd7d409491f58aa9e1f68a491ef8f05eef62fb50ffac857270122203058679f6d60b87ef921d98a2a9a1f1e0779dae27bedbd1cdb2f147a07835ac9ac61c1b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d9b9d92a717ebeba858f75182936f0da5a7aecc434b0eebb2dc8a6af5409422ccf87f124e735a592a8ff390a68f6f05469ba8422e246dc78b0b57cd1576ffa98c00000000";
        assert_eq!(tx_bytes, tx_hex);
    }
}

fn create_basic_single_sig_script(secp: &Secp256k1<secp256k1::All>, sk: &str) -> ScriptBuf {
    let kp = Keypair::from_seckey_str(secp, sk).expect("failed to create keypair");
    let x_only_pubkey = kp.x_only_public_key().0;
    script::Builder::new()
        .push_slice(x_only_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn create_taproot_tree(
    secp: &Secp256k1<secp256k1::All>,
    script1: ScriptBuf,
    script2: ScriptBuf,
    script3: ScriptBuf,
    internal_key: XOnlyPublicKey,
) -> TaprootSpendInfo {
    let builder = TaprootBuilder::new();
    let builder = builder.add_leaf(2, script1).unwrap();
    let builder = builder.add_leaf(2, script2).unwrap();
    let builder = builder.add_leaf(1, script3).unwrap();
    builder.finalize(secp, internal_key).unwrap()
}

fn create_p2tr_address(tree: TaprootSpendInfo) -> Address {
    let output_key = tree.output_key();
    Address::p2tr_tweaked(output_key, Network::Testnet(bitcoin::TestnetVersion::V3))
}

fn create_psbt_for_taproot_key_path_spend(
    from_address: Address,
    to_address: Address,
    tree: TaprootSpendInfo,
) -> Psbt {
    let send_value = 6400;
    let out_puts = vec![TxOut {
        value: Amount::from_sat(send_value),
        script_pubkey: to_address.script_pubkey(),
    }];
    let prev_tx_id = "06980ca116f74c7845a897461dd0e1d15b114130176de5004957da516b4dee3a";

    let transaction = Transaction {
        version: Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: prev_tx_id.parse().unwrap(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xFFFFFFFF), // Ignore nSequence.
            witness: Witness::default(),
        }],
        output: out_puts,
    };

    let mut psbt = Psbt::from_unsigned_tx(transaction).unwrap();

    let mfp = "73c5da0a";
    let internal_key_path = "m/86'/1'/0'/0/2";

    let mut origins = BTreeMap::new();
    origins.insert(
        tree.internal_key(),
        (
            vec![],
            (
                Fingerprint::from_str(mfp).unwrap(),
                DerivationPath::from_str(internal_key_path).unwrap(),
            ),
        ),
    );

    let utxo_value = 6588;
    let mut input = Input {
        witness_utxo: {
            let script_pubkey = from_address.script_pubkey();
            Some(TxOut { value: Amount::from_sat(utxo_value), script_pubkey })
        },
        tap_key_origins: origins,
        ..Default::default()
    };
    let ty = PsbtSighashType::from_str("SIGHASH_DEFAULT").unwrap();
    input.sighash_type = Some(ty);
    input.tap_internal_key = Some(tree.internal_key());
    input.tap_merkle_root = tree.merkle_root();
    psbt.inputs = vec![input];
    psbt
}

fn finalize_psbt_for_key_path_spend(mut psbt: Psbt) -> Psbt {
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        input.final_script_witness = Some(script_witness);
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });
    psbt
}

fn create_psbt_for_taproot_script_path_spend(
    from_address: Address,
    to_address: Address,
    tree: TaprootSpendInfo,
    x_only_pubkey_of_signing_key: XOnlyPublicKey,
    signing_key_path: &str,
    use_script: ScriptBuf,
) -> Psbt {
    let utxo_value = 6280;
    let send_value = 6000;
    let mfp = "73c5da0a";

    let out_puts = vec![TxOut {
        value: Amount::from_sat(send_value),
        script_pubkey: to_address.script_pubkey(),
    }];
    let prev_tx_id = "9d7c6770fca57285babab60c51834cfcfd10ad302119cae842d7216b4ac9a376";
    let transaction = Transaction {
        version: Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: prev_tx_id.parse().unwrap(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xFFFFFFFF), // Ignore nSequence.
            witness: Witness::default(),
        }],
        output: out_puts,
    };

    let mut psbt = Psbt::from_unsigned_tx(transaction).unwrap();

    let mut origins = BTreeMap::new();
    origins.insert(
        x_only_pubkey_of_signing_key,
        (
            vec![use_script.tapscript_leaf_hash()],
            (
                Fingerprint::from_str(mfp).unwrap(),
                DerivationPath::from_str(signing_key_path).unwrap(),
            ),
        ),
    );

    let mut tap_scripts = BTreeMap::new();
    tap_scripts.insert(
        tree.control_block(&(use_script.clone(), LeafVersion::TapScript)).unwrap(),
        (use_script.clone(), LeafVersion::TapScript),
    );

    let mut input = Input {
        witness_utxo: {
            let script_pubkey = from_address.script_pubkey();
            Some(TxOut { value: Amount::from_sat(utxo_value), script_pubkey })
        },
        tap_key_origins: origins,
        tap_scripts,
        ..Default::default()
    };
    let ty = PsbtSighashType::from_str("SIGHASH_ALL").unwrap();
    input.sighash_type = Some(ty);
    input.tap_internal_key = Some(tree.internal_key());
    input.tap_merkle_root = tree.merkle_root();
    psbt.inputs = vec![input];
    psbt
}

fn finalize_psbt_for_script_path_spend(mut psbt: Psbt) -> Psbt {
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        for (_, signature) in input.tap_script_sigs.iter() {
            script_witness.push(signature.to_vec());
        }
        for (control_block, (script, _)) in input.tap_scripts.iter() {
            script_witness.push(script.to_bytes());
            script_witness.push(control_block.serialize());
        }
        input.final_script_witness = Some(script_witness);
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
        input.tap_script_sigs = BTreeMap::new();
        input.tap_scripts = BTreeMap::new();
        input.tap_key_sig = None;
    });
    psbt
}
