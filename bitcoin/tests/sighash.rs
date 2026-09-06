//! Tests for sighash computation. Data lives in `tests/data`, which is excluded when publishing.

#![cfg(feature = "serde")]

use bitcoin::sighash::{
    EcdsaSighashType, LegacySighash, Prevouts, SighashCache, TapSighash, TapSighashType,
};
use bitcoin::{Amount, ScriptPubKeyBuf, Transaction, TxOut};

#[test]
fn legacy_sighash() {
    use serde_json::Value;

    fn run_test_sighash(
        tx: &str,
        script: &str,
        input_index: usize,
        hash_type: i64,
        expected_result: &str,
    ) {
        let tx: Transaction =
            encoding::decode_from_slice(&hex::decode_to_vec(tx).unwrap()[..]).unwrap();
        let script = ScriptPubKeyBuf::from(hex::decode_to_vec(script).unwrap());
        let mut raw_expected = hex::decode_to_vec(expected_result).unwrap();
        raw_expected.reverse();
        let bytes = <[u8; 32]>::try_from(&raw_expected[..]).unwrap();
        let want = LegacySighash::from_byte_array(bytes);

        let cache = SighashCache::new(&tx);
        let got = cache
            .legacy_signature_hash(
                input_index,
                &script,
                EcdsaSighashType::from_consensus(hash_type as u32),
            )
            .unwrap();

        assert_eq!(got, want);
    }

    // These test vectors were stolen from libbtc, which is Copyright 2014 Jonas Schnelli MIT
    // They were transformed by replacing {...} with run_test_sighash(...), then the ones containing
    // OP_CODESEPARATOR in their pubkeys were removed
    let data = include_str!("data/legacy_sighash.json");

    let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
    for t in testdata.iter().skip(1) {
        let tx = t.get(0).unwrap().as_str().unwrap();
        let script = t.get(1).unwrap().as_str().unwrap_or("");
        let input_index = t.get(2).unwrap().as_u64().unwrap();
        let hash_type = t.get(3).unwrap().as_i64().unwrap();
        let expected_sighash = t.get(4).unwrap().as_str().unwrap();
        run_test_sighash(tx, script, input_index as usize, hash_type, expected_sighash);
    }
}

#[test]
fn bip_341_sighash_tests() {
    use hex::DisplayHex;

    fn sighash_deser_numeric<'de, D>(deserializer: D) -> Result<TapSighashType, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Deserialize, Error, Unexpected};

        let raw = u8::deserialize(deserializer)?;
        TapSighashType::from_consensus_u8(raw).map_err(|_| {
            D::Error::invalid_value(
                Unexpected::Unsigned(raw.into()),
                &"number in range 0-3 or 0x81-0x83",
            )
        })
    }

    fn tx_deser_hex<'de, D>(deserializer: D) -> Result<Transaction, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Deserialize, Error};

        let hex_str = String::deserialize(deserializer)?;
        encoding::decode_from_hex(&hex_str).map_err(D::Error::custom)
    }

    use bitcoin::key::{Keypair, PrivateKey, TapTweak, XOnlyPublicKey};
    use bitcoin::taproot::TapNodeHash;
    use secp256k1::SecretKey;

    #[derive(serde::Deserialize)]
    struct UtxoSpent {
        #[serde(rename = "scriptPubKey")]
        script_pubkey: ScriptPubKeyBuf,
        #[serde(rename = "amountSats")]
        #[serde(with = "bitcoin::amount::serde::as_sat")]
        amount: Amount,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsGiven {
        #[serde(deserialize_with = "tx_deser_hex")]
        raw_unsigned_tx: Transaction,
        utxos_spent: Vec<UtxoSpent>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsInputSpendingGiven {
        txin_index: usize,
        internal_privkey: SecretKey,
        merkle_root: Option<TapNodeHash>,
        #[serde(deserialize_with = "sighash_deser_numeric")]
        hash_type: TapSighashType,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsInputSpendingIntermediary {
        internal_pubkey: XOnlyPublicKey,
        tweaked_privkey: SecretKey,
        sig_msg: String,
        //precomputed_used: Vec<String>, // unused
        sig_hash: TapSighash,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsInputSpendingExpected {
        witness: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsInputSpending {
        given: KpsInputSpendingGiven,
        intermediary: KpsInputSpendingIntermediary,
        expected: KpsInputSpendingExpected,
        // auxiliary: KpsAuxiliary, //unused
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KeyPathSpending {
        given: KpsGiven,
        input_spending: Vec<KpsInputSpending>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestData {
        version: u64,
        key_path_spending: Vec<KeyPathSpending>,
        //script_pubkey: Vec<ScriptPubKey>, // unused
    }

    let json_str = include_str!("data/bip341_tests.json");
    let mut data = serde_json::from_str::<TestData>(json_str).expect("JSON was not well-formatted");

    assert_eq!(data.version, 1u64);
    let key_path = data.key_path_spending.remove(0);

    let raw_unsigned_tx = key_path.given.raw_unsigned_tx;
    let utxos = key_path
        .given
        .utxos_spent
        .into_iter()
        .map(|txo| TxOut { amount: txo.amount, script_pubkey: txo.script_pubkey })
        .collect::<Vec<_>>();

    let mut cache = SighashCache::new(&raw_unsigned_tx);

    for mut inp in key_path.input_spending {
        let tx_ind = inp.given.txin_index;
        let internal_priv_key = PrivateKey::from_secp(inp.given.internal_privkey);
        let merkle_root = inp.given.merkle_root;
        let hash_ty = inp.given.hash_type;

        let expected = inp.intermediary;
        let sig_str = inp.expected.witness.remove(0);
        let (expected_key_spend_sig, expected_hash_ty) = if sig_str.len() == 128 {
            (sig_str.parse::<secp256k1::schnorr::Signature>().unwrap(), TapSighashType::Default)
        } else {
            let hash_ty = u8::from_str_radix(&sig_str[128..130], 16).unwrap();
            let hash_ty = TapSighashType::from_consensus_u8(hash_ty).unwrap();
            (sig_str[..128].parse::<secp256k1::schnorr::Signature>().unwrap(), hash_ty)
        };

        // tests
        let keypair = Keypair::from_private_key(&internal_priv_key);
        let internal_key = XOnlyPublicKey::from_keypair(&keypair);
        let tweaked_keypair = keypair.tap_tweak(merkle_root);
        let mut sig_msg = Vec::new();
        cache
            .taproot_encode_signing_data_to(
                &mut sig_msg,
                tx_ind,
                &Prevouts::All(&utxos),
                None,
                None,
                hash_ty,
            )
            .unwrap();
        let sighash = cache
            .taproot_signature_hash(tx_ind, &Prevouts::All(&utxos), None, None, hash_ty)
            .unwrap();

        let tweaked_keypair = tweaked_keypair.into_keypair();
        let key_spend_sig = tweaked_keypair
            .raw_bip340_sign_with_aux_randomness(&sighash.to_byte_array(), &[0u8; 32]);

        assert_eq!(expected.internal_pubkey.with_parity(internal_key.parity()), internal_key);
        assert_eq!(expected.sig_msg, sig_msg.to_lower_hex_string());
        assert_eq!(expected.sig_hash, sighash);
        assert_eq!(expected_hash_ty, hash_ty);
        assert_eq!(expected_key_spend_sig, key_spend_sig);

        let tweaked_priv_key = tweaked_keypair.to_private_key();
        assert_eq!(PrivateKey::from_secp(expected.tweaked_privkey), tweaked_priv_key);
    }
}
