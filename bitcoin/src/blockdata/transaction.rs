// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transactions.
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.

/// Re-export everything from the [`primitives::transaction`] module.
#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::transaction::*;

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use hex::{test_hex_unwrap as hex, FromHex};
    use primitives::consensus::encode::{deserialize, serialize, Decodable, Encodable};
    use primitives::{absolute, Amount, FeeRate, ScriptBuf, SignedAmount, Transaction, Weight};
    use units::parse;

    use super::*;
    use crate::constants::WITNESS_SCALE_FACTOR;
    use crate::sighash::EcdsaSighashType;

    const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[test]
    fn encode_to_unsized_writer() {
        let mut buf = [0u8; 1024];
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        let size = tx.consensus_encode(&mut &mut buf[..]).unwrap();
        assert_eq!(size, SOME_TX.len() / 2);
        assert_eq!(raw_tx, &buf[..size]);
    }

    #[test]
    fn outpoint() {
        assert_eq!(OutPoint::from_str("i don't care"), Err(ParseOutPointError::Format));
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:1:1"
            ),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:"),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:11111111111"
            ),
            Err(ParseOutPointError::TooLong)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:01"
            ),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:+42"
            ),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            OutPoint::from_str("i don't care:1"),
            Err(ParseOutPointError::Txid("i don't care".parse::<Txid>().unwrap_err()))
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X:1"
            ),
            Err(ParseOutPointError::Txid(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X"
                    .parse::<Txid>()
                    .unwrap_err()
            ))
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:lol"
            ),
            Err(ParseOutPointError::Vout(parse::int::<u32, _>("lol").unwrap_err()))
        );

        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:42"
            ),
            Ok(OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 42,
            })
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0"
            ),
            Ok(OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 0,
            })
        );
    }

    #[test]
    fn txin() {
        let txin: Result<TxIn, _> = deserialize(&hex!("a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff"));
        assert!(txin.is_ok());
    }

    #[test]
    fn txin_default() {
        let txin = TxIn::default();
        assert_eq!(txin.previous_output, OutPoint::default());
        assert_eq!(txin.script_sig, ScriptBuf::new());
        assert_eq!(txin.sequence, Sequence::from_consensus(0xFFFFFFFF));
        assert_eq!(txin.previous_output, OutPoint::default());
        assert_eq!(txin.witness.len(), 0);
    }

    #[test]
    fn is_coinbase() {
        use crate::constants;
        use crate::network::Network;

        let genesis = constants::genesis_block(Network::Bitcoin);
        assert!(genesis.txdata[0].is_coinbase());
        let tx_bytes = hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000");
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        assert!(!tx.is_coinbase());
    }

    #[test]
    fn nonsegwit_transaction() {
        let tx_bytes = hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000");
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(realtx.version, Version::ONE);
        assert_eq!(realtx.input.len(), 1);
        // In particular this one is easy to get backward -- in bitcoin hashes are encoded
        // as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(
            format!("{:x}", realtx.input[0].previous_output.txid),
            "ce9ea9f6f5e422c6a9dbcddb3b9a14d1c78fab9ab520cb281aa2a74a09575da1".to_string()
        );
        assert_eq!(realtx.input[0].previous_output.vout, 1);
        assert_eq!(realtx.output.len(), 1);
        assert_eq!(realtx.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            format!("{:x}", realtx.compute_txid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        assert_eq!(
            format!("{:x}", realtx.compute_wtxid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        assert_eq!(realtx.weight().to_wu() as usize, tx_bytes.len() * WITNESS_SCALE_FACTOR);
        assert_eq!(realtx.total_size(), tx_bytes.len());
        assert_eq!(realtx.vsize(), tx_bytes.len());
        assert_eq!(realtx.base_size(), tx_bytes.len());
    }

    #[test]
    fn segwit_invalid_transaction() {
        let tx_bytes = hex!("0000fd000001021921212121212121212121f8b372b0239cc1dff600000000004f4f4f4f4f4f4f4f000000000000000000000000000000333732343133380d000000000000000000000000000000ff000000000009000dff000000000000000800000000000000000d");
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_err());
        assert!(tx.unwrap_err().to_string().contains("witness flag set but no witnesses present"));
    }

    #[test]
    fn segwit_transaction() {
        let tx_bytes = hex!(
            "02000000000101595895ea20179de87052b4046dfe6fd515860505d6511a9004cf12a1f93cac7c01000000\
            00ffffffff01deb807000000000017a9140f3444e271620c736808aa7b33e370bd87cb5a078702483045022\
            100fb60dad8df4af2841adc0346638c16d0b8035f5e3f3753b88db122e70c79f9370220756e6633b17fd271\
            0e626347d28d60b0a2d6cbb41de51740644b9fb3ba7751040121028fa937ca8cba2197a37c007176ed89410\
            55d3bcb8627d085e94553e62f057dcc00000000"
        );
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(realtx.version, Version::TWO);
        assert_eq!(realtx.input.len(), 1);
        // In particular this one is easy to get backward -- in bitcoin hashes are encoded
        // as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(
            format!("{:x}", realtx.input[0].previous_output.txid),
            "7cac3cf9a112cf04901a51d605058615d56ffe6d04b45270e89d1720ea955859".to_string()
        );
        assert_eq!(realtx.input[0].previous_output.vout, 1);
        assert_eq!(realtx.output.len(), 1);
        assert_eq!(realtx.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            format!("{:x}", realtx.compute_txid()),
            "f5864806e3565c34d1b41e716f72609d00b55ea5eac5b924c9719a842ef42206".to_string()
        );
        assert_eq!(
            format!("{:x}", realtx.compute_wtxid()),
            "80b7d8a82d5d5bf92905b06f2014dd699e03837ca172e3a59d51426ebbe3e7f5".to_string()
        );
        const EXPECTED_WEIGHT: Weight = Weight::from_wu(442);
        assert_eq!(realtx.weight(), EXPECTED_WEIGHT);
        assert_eq!(realtx.total_size(), tx_bytes.len());
        assert_eq!(realtx.vsize(), 111);

        let expected_strippedsize = (442 - realtx.total_size()) / 3;
        assert_eq!(realtx.base_size(), expected_strippedsize);

        // Construct a transaction without the witness data.
        let mut tx_without_witness = realtx;
        tx_without_witness.input.iter_mut().for_each(|input| input.witness.clear());
        assert_eq!(tx_without_witness.total_size(), tx_without_witness.total_size());
        assert_eq!(tx_without_witness.total_size(), expected_strippedsize);
    }

    // We temporarily abuse `Transaction` for testing consensus serde adapter.
    #[cfg(feature = "serde")]
    #[test]
    fn consensus_serde() {
        use crate::consensus::serde as con_serde;
        let json = "\"010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3603da1b0e00045503bd5704c7dd8a0d0ced13bb5785010800000000000a636b706f6f6c122f4e696e6a61506f6f6c2f5345475749542fffffffff02b4e5a212000000001976a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac0000000000000000266a24aa21a9edf91c46b49eb8a29089980f02ee6b57e7d63d33b18b4fddac2bcd7db2a39837040120000000000000000000000000000000000000000000000000000000000000000000000000\"";
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let tx =
            con_serde::With::<con_serde::Hex>::deserialize::<'_, Transaction, _>(&mut deserializer)
                .unwrap();
        let tx_bytes = Vec::from_hex(&json[1..(json.len() - 1)]).unwrap();
        let expected = deserialize::<Transaction>(&tx_bytes).unwrap();
        assert_eq!(tx, expected);
        let mut bytes = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut bytes);
        con_serde::With::<con_serde::Hex>::serialize(&tx, &mut serializer).unwrap();
        assert_eq!(bytes, json.as_bytes())
    }

    #[test]
    fn transaction_version() {
        let tx_bytes = hex!("ffffff7f0100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        assert_eq!(realtx.version, Version::non_standard(2147483647));

        let tx2_bytes = hex!("000000800100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
        let tx2: Result<Transaction, _> = deserialize(&tx2_bytes);
        assert!(tx2.is_ok());
        let realtx2 = tx2.unwrap();
        assert_eq!(realtx2.version, Version::non_standard(-2147483648));
    }

    #[test]
    fn tx_no_input_deserialization() {
        let tx_bytes = hex!(
            "010000000001000100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000"
        );
        let tx: Transaction = deserialize(&tx_bytes).expect("deserialize tx");

        assert_eq!(tx.input.len(), 0);
        assert_eq!(tx.output.len(), 1);

        let reser = serialize(&tx);
        assert_eq!(tx_bytes, reser);
    }

    #[test]
    fn ntxid() {
        let tx_bytes = hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000");
        let mut tx: Transaction = deserialize(&tx_bytes).unwrap();

        let old_ntxid = tx.compute_ntxid();
        assert_eq!(
            format!("{:x}", old_ntxid),
            "c3573dbea28ce24425c59a189391937e00d255150fa973d59d61caf3a06b601d"
        );
        // changing sigs does not affect it
        tx.input[0].script_sig = ScriptBuf::new();
        assert_eq!(old_ntxid, tx.compute_ntxid());
        // changing pks does
        tx.output[0].script_pubkey = ScriptBuf::new();
        assert!(old_ntxid != tx.compute_ntxid());
    }

    #[test]
    fn txid() {
        // segwit tx from Liquid integration tests, txid/hash from Core decoderawtransaction
        let tx_bytes = hex!(
            "01000000000102ff34f95a672bb6a4f6ff4a7e90fa8c7b3be7e70ffc39bc99be3bda67942e836c00000000\
             23220020cde476664d3fa347b8d54ef3aee33dcb686a65ced2b5207cbf4ec5eda6b9b46e4f414d4c934ad8\
             1d330314e888888e3bd22c7dde8aac2ca9227b30d7c40093248af7812201000000232200200af6f6a071a6\
             9d5417e592ed99d256ddfd8b3b2238ac73f5da1b06fc0b2e79d54f414d4c0ba0c8f505000000001976a914\
             dcb5898d9036afad9209e6ff0086772795b1441088ac033c0f000000000017a914889f8c10ff2bd4bb9dab\
             b68c5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87\
             033c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87033c0f000000000017a914\
             889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb6\
             8c5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c8703\
             3c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87033c0f000000000017a91488\
             9f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb68c\
             5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c870500\
             47304402200380b8663e727d7e8d773530ef85d5f82c0b067c97ae927800a0876a1f01d8e2022021ee611e\
             f6507dfd217add2cd60a8aea3cbcfec034da0bebf3312d19577b8c290147304402207bd9943ce1c2c5547b\
             120683fd05d78d23d73be1a5b5a2074ff586b9c853ed4202202881dcf435088d663c9af7b23efb3c03b9db\
             c0c899b247aa94a74d9b4b3c84f501483045022100ba12bba745af3f18f6e56be70f8382ca8e107d1ed5ce\
             aa3e8c360d5ecf78886f022069b38ebaac8fe6a6b97b497cbbb115f3176f7213540bef08f9292e5a72de52\
             de01695321023c9cd9c6950ffee24772be948a45dc5ef1986271e46b686cb52007bac214395a2102756e27\
             cb004af05a6e9faed81fd68ff69959e3c64ac8c9f6cd0e08fd0ad0e75d2103fa40da236bd82202a985a910\
             4e851080b5940812685769202a3b43e4a8b13e6a53ae050048304502210098b9687b81d725a7970d1eee91\
             ff6b89bc9832c2e0e3fb0d10eec143930b006f02206f77ce19dc58ecbfef9221f81daad90bb4f468df3912\
             12abc4f084fe2cc9bdef01483045022100e5479f81a3ad564103da5e2ec8e12f61f3ac8d312ab68763c1dd\
             d7bae94c20610220789b81b7220b27b681b1b2e87198897376ba9d033bc387f084c8b8310c8539c2014830\
             45022100aa1cc48a2d256c0e556616444cc08ae4959d464e5ffff2ae09e3550bdab6ce9f02207192d5e332\
             9a56ba7b1ead724634d104f1c3f8749fe6081e6233aee3e855817a016953210260de9cc68658c61af984e3\
             ab0281d17cfca1cc035966d335f474932d5e6c5422210355fbb768ce3ce39360277345dbb5f376e706459e\
             5a2b5e0e09a535e61690647021023222ceec58b94bd25925dd9743dae6b928737491bd940fc5dd7c6f5d5f\
             2adc1e53ae00000000"
        );
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        assert_eq!(
            format!("{:x}", tx.compute_wtxid()),
            "d6ac4a5e61657c4c604dcde855a1db74ec6b3e54f32695d72c5e11c7761ea1b4"
        );
        assert_eq!(
            format!("{:x}", tx.compute_txid()),
            "9652aa62b0e748caeec40c4cb7bc17c6792435cc3dfe447dd1ca24f912a1c6ec"
        );
        assert_eq!(format!("{:.10x}", tx.compute_txid()), "9652aa62b0");
        assert_eq!(tx.weight(), Weight::from_wu(2718));

        // non-segwit tx from my mempool
        let tx_bytes = hex!(
            "01000000010c7196428403d8b0c88fcb3ee8d64f56f55c8973c9ab7dd106bb4f3527f5888d000000006a47\
             30440220503a696f55f2c00eee2ac5e65b17767cd88ed04866b5637d3c1d5d996a70656d02202c9aff698f\
             343abb6d176704beda63fcdec503133ea4f6a5216b7f925fa9910c0121024d89b5a13d6521388969209df2\
             7a8469bd565aff10e8d42cef931fad5121bfb8ffffffff02b825b404000000001976a914ef79e7ee9fff98\
             bcfd08473d2b76b02a48f8c69088ac0000000000000000296a273236303039343836393731373233313237\
             3633313032313332353630353838373931323132373000000000"
        );
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        assert_eq!(
            format!("{:x}", tx.compute_wtxid()),
            "971ed48a62c143bbd9c87f4bafa2ef213cfa106c6e140f111931d0be307468dd"
        );
        assert_eq!(
            format!("{:x}", tx.compute_txid()),
            "971ed48a62c143bbd9c87f4bafa2ef213cfa106c6e140f111931d0be307468dd"
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn txn_encode_decode() {
        let tx_bytes = hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000");
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        serde_round_trip!(tx);
    }

    // Test decoding transaction `4be105f158ea44aec57bf12c5817d073a712ab131df6f37786872cfc70734188`
    // from testnet, which is the first BIP144-encoded transaction I encountered.
    #[test]
    #[cfg(feature = "serde")]
    fn segwit_tx_decode() {
        let tx_bytes = hex!("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3603da1b0e00045503bd5704c7dd8a0d0ced13bb5785010800000000000a636b706f6f6c122f4e696e6a61506f6f6c2f5345475749542fffffffff02b4e5a212000000001976a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac0000000000000000266a24aa21a9edf91c46b49eb8a29089980f02ee6b57e7d63d33b18b4fddac2bcd7db2a39837040120000000000000000000000000000000000000000000000000000000000000000000000000");
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        assert_eq!(tx.weight(), Weight::from_wu(780));
        serde_round_trip!(tx);

        let consensus_encoded = serialize(&tx);
        assert_eq!(consensus_encoded, tx_bytes);
    }

    #[test]
    fn sighashtype_fromstr_display() {
        let sighashtypes = vec![
            ("SIGHASH_ALL", EcdsaSighashType::All),
            ("SIGHASH_NONE", EcdsaSighashType::None),
            ("SIGHASH_SINGLE", EcdsaSighashType::Single),
            ("SIGHASH_ALL|SIGHASH_ANYONECANPAY", EcdsaSighashType::AllPlusAnyoneCanPay),
            ("SIGHASH_NONE|SIGHASH_ANYONECANPAY", EcdsaSighashType::NonePlusAnyoneCanPay),
            ("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY", EcdsaSighashType::SinglePlusAnyoneCanPay),
        ];
        for (s, sht) in sighashtypes {
            assert_eq!(sht.to_string(), s);
            assert_eq!(EcdsaSighashType::from_str(s).unwrap(), sht);
        }
        let sht_mistakes = vec![
            "SIGHASH_ALL | SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |SIGHASH_ANYONECANPAY",
            "SIGHASH_SINGLE| SIGHASH_ANYONECANPAY",
            "SIGHASH_ALL SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |",
            "SIGHASH_SIGNLE",
            "sighash_none",
            "Sighash_none",
            "SigHash_None",
            "SigHash_NONE",
        ];
        for s in sht_mistakes {
            assert_eq!(
                EcdsaSighashType::from_str(s).unwrap_err().to_string(),
                format!("unrecognized SIGHASH string '{}'", s)
            );
        }
    }

    #[test]
    fn huge_witness() {
        deserialize::<Transaction>(&hex!(include_str!("../../tests/data/huge_witness.hex").trim()))
            .unwrap();
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn transaction_verify() {
        use std::collections::HashMap;

        use crate::witness::Witness;

        // a random recent segwit transaction from blockchain using both old and segwit inputs
        let mut spending: Transaction = deserialize(hex!("020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700")
            .as_slice()).unwrap();
        let spent1: Transaction = deserialize(hex!("020000000001040aacd2c49f5f3c0968cfa8caf9d5761436d95385252e3abb4de8f5dcf8a582f20000000017160014bcadb2baea98af0d9a902e53a7e9adff43b191e9feffffff96cd3c93cac3db114aafe753122bd7d1afa5aa4155ae04b3256344ecca69d72001000000171600141d9984579ceb5c67ebfbfb47124f056662fe7adbfeffffffc878dd74d3a44072eae6178bb94b9253177db1a5aaa6d068eb0e4db7631762e20000000017160014df2a48cdc53dae1aba7aa71cb1f9de089d75aac3feffffffe49f99275bc8363f5f593f4eec371c51f62c34ff11cc6d8d778787d340d6896c0100000017160014229b3b297a0587e03375ab4174ef56eeb0968735feffffff03360d0f00000000001976a9149f44b06f6ee92ddbc4686f71afe528c09727a5c788ac24281b00000000001976a9140277b4f68ff20307a2a9f9b4487a38b501eb955888ac227c0000000000001976a9148020cd422f55eef8747a9d418f5441030f7c9c7788ac0247304402204aa3bd9682f9a8e101505f6358aacd1749ecf53a62b8370b97d59243b3d6984f02200384ad449870b0e6e89c92505880411285ecd41cf11e7439b973f13bad97e53901210205b392ffcb83124b1c7ce6dd594688198ef600d34500a7f3552d67947bbe392802473044022033dfd8d190a4ae36b9f60999b217c775b96eb10dee3a1ff50fb6a75325719106022005872e4e36d194e49ced2ebcf8bb9d843d842e7b7e0eb042f4028396088d292f012103c9d7cbf369410b090480de2aa15c6c73d91b9ffa7d88b90724614b70be41e98e0247304402207d952de9e59e4684efed069797e3e2d993e9f98ec8a9ccd599de43005fe3f713022076d190cc93d9513fc061b1ba565afac574e02027c9efbfa1d7b71ab8dbb21e0501210313ad44bc030cc6cb111798c2bf3d2139418d751c1e79ec4e837ce360cc03b97a024730440220029e75edb5e9413eb98d684d62a077b17fa5b7cc19349c1e8cc6c4733b7b7452022048d4b9cae594f03741029ff841e35996ef233701c1ea9aa55c301362ea2e2f68012103590657108a72feb8dc1dec022cf6a230bb23dc7aaa52f4032384853b9f8388baf9d20700")
            .as_slice()).unwrap();
        let spent2: Transaction = deserialize(hex!("0200000000010166c3d39490dc827a2594c7b17b7d37445e1f4b372179649cd2ce4475e3641bbb0100000017160014e69aa750e9bff1aca1e32e57328b641b611fc817fdffffff01e87c5d010000000017a914f3890da1b99e44cd3d52f7bcea6a1351658ea7be87024830450221009eb97597953dc288de30060ba02d4e91b2bde1af2ecf679c7f5ab5989549aa8002202a98f8c3bd1a5a31c0d72950dd6e2e3870c6c5819a6c3db740e91ebbbc5ef4800121023f3d3b8e74b807e32217dea2c75c8d0bd46b8665b3a2d9b3cb310959de52a09bc9d20700")
            .as_slice()).unwrap();
        let spent3: Transaction = deserialize(hex!("01000000027a1120a30cef95422638e8dab9dedf720ec614b1b21e451a4957a5969afb869d000000006a47304402200ecc318a829a6cad4aa9db152adbf09b0cd2de36f47b53f5dade3bc7ef086ca702205722cda7404edd6012eedd79b2d6f24c0a0c657df1a442d0a2166614fb164a4701210372f4b97b34e9c408741cd1fc97bcc7ffdda6941213ccfde1cb4075c0f17aab06ffffffffc23b43e5a18e5a66087c0d5e64d58e8e21fcf83ce3f5e4f7ecb902b0e80a7fb6010000006b483045022100f10076a0ea4b4cf8816ed27a1065883efca230933bf2ff81d5db6258691ff75202206b001ef87624e76244377f57f0c84bc5127d0dd3f6e0ef28b276f176badb223a01210309a3a61776afd39de4ed29b622cd399d99ecd942909c36a8696cfd22fc5b5a1affffffff0200127a000000000017a914f895e1dd9b29cb228e9b06a15204e3b57feaf7cc8769311d09000000001976a9144d00da12aaa51849d2583ae64525d4a06cd70fde88ac00000000")
            .as_slice()).unwrap();

        let mut spent = HashMap::new();
        spent.insert(spent1.compute_txid(), spent1);
        spent.insert(spent2.compute_txid(), spent2);
        spent.insert(spent3.compute_txid(), spent3);
        let mut spent2 = spent.clone();
        let mut spent3 = spent.clone();

        spending
            .verify(|point: &OutPoint| {
                if let Some(tx) = spent.remove(&point.txid) {
                    return tx.output.get(point.vout as usize).cloned();
                }
                None
            })
            .unwrap();

        // test that we fail with repeated use of same input
        let mut double_spending = spending.clone();
        let re_use = double_spending.input[0].clone();
        double_spending.input.push(re_use);

        assert!(double_spending
            .verify(|point: &OutPoint| {
                if let Some(tx) = spent2.remove(&point.txid) {
                    return tx.output.get(point.vout as usize).cloned();
                }
                None
            })
            .is_err());

        // test that we get a failure if we corrupt a signature
        let mut witness: Vec<_> = spending.input[1].witness.to_vec();
        witness[0][10] = 42;
        spending.input[1].witness = Witness::from_slice(&witness);

        let error = spending
            .verify(|point: &OutPoint| {
                if let Some(tx) = spent3.remove(&point.txid) {
                    return tx.output.get(point.vout as usize).cloned();
                }
                None
            })
            .err()
            .unwrap();

        match error {
            TxVerifyError::ScriptVerification(_) => {}
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn sequence_number() {
        let seq_final = Sequence::from_consensus(0xFFFFFFFF);
        let seq_non_rbf = Sequence::from_consensus(0xFFFFFFFE);
        let block_time_lock = Sequence::from_consensus(0xFFFF);
        let unit_time_lock = Sequence::from_consensus(0x40FFFF);
        let lock_time_disabled = Sequence::from_consensus(0x80000000);

        assert!(seq_final.is_final());
        assert!(!seq_final.is_rbf());
        assert!(!seq_final.is_relative_lock_time());
        assert!(!seq_non_rbf.is_rbf());
        assert!(block_time_lock.is_relative_lock_time());
        assert!(block_time_lock.is_height_locked());
        assert!(block_time_lock.is_rbf());
        assert!(unit_time_lock.is_relative_lock_time());
        assert!(unit_time_lock.is_time_locked());
        assert!(unit_time_lock.is_rbf());
        assert!(!lock_time_disabled.is_relative_lock_time());
    }

    #[test]
    fn sequence_from_hex_lower() {
        let sequence = Sequence::from_hex("0xffffffff").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_hex_upper() {
        let sequence = Sequence::from_hex("0XFFFFFFFF").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_unprefixed_hex_lower() {
        let sequence = Sequence::from_unprefixed_hex("ffffffff").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_unprefixed_hex_upper() {
        let sequence = Sequence::from_unprefixed_hex("FFFFFFFF").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_str_hex_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = Sequence::from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    fn effective_value_happy_path() {
        let value = Amount::from_str("1 cBTC").unwrap();
        let fee_rate = FeeRate::from_sat_per_kwu(10);
        let satisfaction_weight = Weight::from_wu(204);
        let effective_value = effective_value(fee_rate, satisfaction_weight, value).unwrap();

        // 10 sat/kwu * (204wu + BASE_WEIGHT) = 4 sats
        let expected_fee = SignedAmount::from_str("4 sats").unwrap();
        let expected_effective_value = value.to_signed().unwrap() - expected_fee;
        assert_eq!(effective_value, expected_effective_value);
    }

    #[test]
    fn effective_value_fee_rate_does_not_overflow() {
        let eff_value = effective_value(FeeRate::MAX, Weight::ZERO, Amount::ZERO);
        assert!(eff_value.is_none());
    }

    #[test]
    fn effective_value_weight_does_not_overflow() {
        let eff_value = effective_value(FeeRate::ZERO, Weight::MAX, Amount::ZERO);
        assert!(eff_value.is_none());
    }

    #[test]
    fn effective_value_value_does_not_overflow() {
        let eff_value = effective_value(FeeRate::ZERO, Weight::ZERO, Amount::MAX);
        assert!(eff_value.is_none());
    }

    #[test]
    fn txin_txout_weight() {
        // [(is_segwit, tx_hex, expected_weight)]
        let txs = [
                // one segwit input (P2WPKH)
                (true, "020000000001018a763b78d3e17acea0625bf9e52b0dc1beb2241b2502185348ba8ff4a253176e0100000000ffffffff0280d725000000000017a914c07ed639bd46bf7087f2ae1dfde63b815a5f8b488767fda20300000000160014869ec8520fa2801c8a01bfdd2e82b19833cd0daf02473044022016243edad96b18c78b545325aaff80131689f681079fb107a67018cb7fb7830e02205520dae761d89728f73f1a7182157f6b5aecf653525855adb7ccb998c8e6143b012103b9489bde92afbcfa85129a82ffa512897105d1a27ad9806bded27e0532fc84e700000000", Weight::from_wu(565)),
                // one segwit input (P2WSH)
                (true, "01000000000101a3ccad197118a2d4975fadc47b90eacfdeaf8268adfdf10ed3b4c3b7e1ad14530300000000ffffffff0200cc5501000000001976a91428ec6f21f4727bff84bb844e9697366feeb69f4d88aca2a5100d00000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220548f11130353b3a8f943d2f14260345fc7c20bde91704c9f1cbb5456355078cd0220383ed4ed39b079b618bcb279bbc1f2ca18cb028c4641cb522c9c5868c52a0dc20147304402203c332ecccb3181ca82c0600520ee51fee80d3b4a6ab110945e59475ec71e44ac0220679a11f3ca9993b04ccebda3c834876f353b065bb08f50076b25f5bb93c72ae1016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000", Weight::from_wu(766)),
                // one segwit input (P2WPKH) and two legacy inputs (P2PKH)
                (true, "010000000001036b6b6ac7e34e97c53c1cc74c99c7948af2e6aac75d8778004ae458d813456764000000006a473044022001deec7d9075109306320b3754188f81a8236d0d232b44bc69f8309115638b8f02204e17a5194a519cf994d0afeea1268740bdc10616b031a521113681cc415e815c012103488d3272a9fad78ee887f0684cb8ebcfc06d0945e1401d002e590c7338b163feffffffffc75bd7aa6424aee972789ec28ba181254ee6d8311b058d165bd045154d7660b0000000006b483045022100c8641bcbee3e4c47a00417875015d8c5d5ea918fb7e96f18c6ffe51bc555b401022074e2c46f5b1109cd79e39a9aa203eadd1d75356415e51d80928a5fb5feb0efee0121033504b4c6dfc3a5daaf7c425aead4c2dbbe4e7387ce8e6be2648805939ecf7054ffffffff494df3b205cd9430a26f8e8c0dc0bb80496fbc555a524d6ea307724bc7e60eee0100000000ffffffff026d861500000000001976a9145c54ed1360072ebaf56e87693b88482d2c6a101588ace407000000000000160014761e31e2629c6e11936f2f9888179d60a5d4c1f900000247304402201fa38a67a63e58b67b6cfffd02f59121ca1c8a1b22e1efe2573ae7e4b4f06c2b022002b9b431b58f6e36b3334fb14eaecee7d2f06967a77ef50d8d5f90dda1057f0c01210257dc6ce3b1100903306f518ee8fa113d778e403f118c080b50ce079fba40e09a00000000", Weight::from_wu(1755)),
                // three legacy inputs (P2PKH)
                (false, "0100000003e4d7be4314204a239d8e00691128dca7927e19a7339c7948bde56f669d27d797010000006b483045022100b988a858e2982e2daaf0755b37ad46775d6132057934877a5badc91dee2f66ff022020b967c1a2f0916007662ec609987e951baafa6d4fda23faaad70715611d6a2501210254a2dccd8c8832d4677dc6f0e562eaaa5d11feb9f1de2c50a33832e7c6190796ffffffff9e22eb1b3f24c260187d716a8a6c2a7efb5af14a30a4792a6eeac3643172379c000000006a47304402207df07f0cd30dca2cf7bed7686fa78d8a37fe9c2254dfdca2befed54e06b779790220684417b8ff9f0f6b480546a9e90ecee86a625b3ea1e4ca29b080da6bd6c5f67e01210254a2dccd8c8832d4677dc6f0e562eaaa5d11feb9f1de2c50a33832e7c6190796ffffffff1123df3bfb503b59769731da103d4371bc029f57979ebce68067768b958091a1000000006a47304402207a016023c2b0c4db9a7d4f9232fcec2193c2f119a69125ad5bcedcba56dd525e02206a734b3a321286c896759ac98ebfd9d808df47f1ce1fbfbe949891cc3134294701210254a2dccd8c8832d4677dc6f0e562eaaa5d11feb9f1de2c50a33832e7c6190796ffffffff0200c2eb0b000000001976a914e5eb3e05efad136b1405f5c2f9adb14e15a35bb488ac88cfff1b000000001976a9144846db516db3130b7a3c92253599edec6bc9630b88ac00000000", Weight::from_wu(2080)),
                // one segwit input (P2TR)
                (true, "01000000000101b5cee87f1a60915c38bb0bc26aaf2b67be2b890bbc54bb4be1e40272e0d2fe0b0000000000ffffffff025529000000000000225120106daad8a5cb2e6fc74783714273bad554a148ca2d054e7a19250e9935366f3033760000000000002200205e6d83c44f57484fd2ef2a62b6d36cdcd6b3e06b661e33fd65588a28ad0dbe060141df9d1bfce71f90d68bf9e9461910b3716466bfe035c7dbabaa7791383af6c7ef405a3a1f481488a91d33cd90b098d13cb904323a3e215523aceaa04e1bb35cdb0100000000", Weight::from_wu(617)),
                // one legacy input (P2PKH)
                (false, "0100000001c336895d9fa674f8b1e294fd006b1ac8266939161600e04788c515089991b50a030000006a47304402204213769e823984b31dcb7104f2c99279e74249eacd4246dabcf2575f85b365aa02200c3ee89c84344ae326b637101a92448664a8d39a009c8ad5d147c752cbe112970121028b1b44b4903c9103c07d5a23e3c7cf7aeb0ba45ddbd2cfdce469ab197381f195fdffffff040000000000000000536a4c5058325bb7b7251cf9e36cac35d691bd37431eeea426d42cbdecca4db20794f9a4030e6cb5211fabf887642bcad98c9994430facb712da8ae5e12c9ae5ff314127d33665000bb26c0067000bb0bf00322a50c300000000000017a9145ca04fdc0a6d2f4e3f67cfeb97e438bb6287725f8750c30000000000001976a91423086a767de0143523e818d4273ddfe6d9e4bbcc88acc8465003000000001976a914c95cbacc416f757c65c942f9b6b8a20038b9b12988ac00000000", Weight::from_wu(1396)),
            ];

        let empty_transaction_weight = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
        .weight();

        for (is_segwit, tx, expected_weight) in &txs {
            let txin_weight = if *is_segwit { TxIn::segwit_weight } else { TxIn::legacy_weight };
            let tx: Transaction = deserialize(Vec::from_hex(tx).unwrap().as_slice()).unwrap();
            assert_eq!(*is_segwit, tx.uses_segwit_serialization());

            let mut calculated_weight = empty_transaction_weight
                + tx.input.iter().fold(Weight::ZERO, |sum, i| sum + txin_weight(i))
                + tx.output.iter().fold(Weight::ZERO, |sum, o| sum + o.weight());

            // The empty tx uses segwit serialization but a legacy tx does not.
            if !tx.uses_segwit_serialization() {
                calculated_weight -= Weight::from_wu(2);
            }

            assert_eq!(calculated_weight, *expected_weight);
            assert_eq!(tx.weight(), *expected_weight);
        }
    }

    #[test]
    fn tx_sigop_count() {
        let tx_hexes = [
            // 0 sigops (p2pkh in + p2wpkh out)
            (
                "0200000001725aab4d23f76ad10bb569a68f8702ebfb8b076e015179ff9b9425234953\
                ac63000000006a47304402204cae7dc9bb68b588dd6b8afb8b881b752fd65178c25693e\
                a6d5d9a08388fd2a2022011c753d522d5c327741a6d922342c86e05c928309d7e566f68\
                8148432e887028012103f14b11cfb58b113716e0fa277ab4a32e4d3ed64c6b09b1747ef\
                7c828d5b06a94fdffffff01e5d4830100000000160014e98527b55cae861e5b9c3a6794\
                86514c012d6fce00000000",
                0,                                             // Expected (Some)
                return_none as fn(&OutPoint) -> Option<TxOut>, // spent fn
                0,                                             // Expected (None)
            ),
            // 5 sigops (p2wpkh in + p2pkh out (x4))
            (
                "020000000001018c47330b1c4d30e7e2244e8ccb56d411b71e10073bb42fa1813f3f01\
                e144cc4d0100000000fdffffff01f7e30300000000001976a9143b49fd16f7562cfeedc\
                6a4ba84805f8c2f8e1a2c88ac024830450221009a4dbf077a63f6e4c3628a5fef2a09ec\
                6f7ca4a4d95bc8bb69195b6b671e9272022074da9ffff5a677fc7b37d66bb4ff1f316c9\
                dbacb92058291d84cd4b83f7c63c9012103d013e9e53c9ca8dd2ddffab1e9df27811503\
                feea7eb0700ff058851bbb37d99000000000",
                5,
                return_p2wpkh,
                4,
            ),
            // 8 sigops (P2WSH 3-of-4 MS (4) in + P2WSH out + P2PKH out (1x4))
            (
                "01000000000101e70d7b4d957122909a665070b0c5bbb693982d09e4e66b9e6b7a8390\
                ce65ef1f0100000000ffffffff02095f2b0000000000220020800a016ea57a08f30c273\
                ae7624f8f91c505ccbd3043829349533f317168248c52594500000000001976a914607f\
                643372477c044c6d40b814288e40832a602688ac05004730440220282943649e687b5a3\
                bda9403c16f363c2ee2be0ec43fb8df40a08b96a4367d47022014e8f36938eef41a09ee\
                d77a815b0fa120a35f25e3a185310f050959420cee360147304402201e555f894036dd5\
                78045701e03bf10e093d7e93cd9997e44c1fc65a7b669852302206893f7261e52c9d779\
                5ba39d99aad30663da43ed675c389542805469fa8eb26a014730440220510fc99bc37d6\
                dbfa7e8724f4802cebdb17b012aaf70ce625e22e6158b139f40022022e9b811751d491f\
                bdec7691b697e88ba84315f6739b9e3bd4425ac40563aed2018b5321029ddecf0cc2013\
                514961550e981a0b8b60e7952f70561a5bb552aa7f075e71e3c2103316195a59c35a3b2\
                7b6dfcc3192cc10a7a6bbccd5658dfbe98ca62a13d6a02c121034629d906165742def4e\
                f53c6dade5dcbf88b775774cad151e35ae8285e613b0221035826a29938de2076950811\
                13c58bcf61fe6adacc3aacceb21c4827765781572d54ae00000000",
                8,
                return_p2wsh,
                4,
            ),
            // 5 sigops (P2SH-P2WPKH in (1), 2 P2SH outs (0), 1 P2PKH out (1x4))
            (
                "010000000001018aec7e0729ba5a2d284303c89b3f397e92d54472a225d28eb0ae2fa6\
                5a7d1a2e02000000171600145ad5db65f313ab76726eb178c2fd8f21f977838dfdfffff\
                f03102700000000000017a914dca89e03ba124c2c70e55533f91100f2d9dab04587f2d7\
                1d00000000001976a91442a34f4b0a65bc81278b665d37fd15910d261ec588ac292c3b0\
                00000000017a91461978dcebd0db2da0235c1ba3e8087f9fd74c57f8702473044022000\
                9226f8def30a8ffa53e55ca5d71a72a64cd20ae7f3112562e3413bd0731d2c0220360d2\
                20435e67eef7f2bf0258d1dded706e3824f06d961ba9eeaed300b16c2cc012103180cff\
                753d3e4ee1aa72b2b0fd72ce75956d04f4c19400a3daed0b18c3ab831e00000000",
                5,
                return_p2sh,
                4,
            ),
            // 12 sigops (1 P2SH 2-of-3 MS in (3x4), P2SH outs (0))
            (
                "010000000115fe9ec3dc964e41f5267ea26cfe505f202bf3b292627496b04bece84da9\
                b18903000000fc004730440220442827f1085364bda58c5884cee7b289934083362db6d\
                fb627dc46f6cdbf5793022078cfa524252c381f2a572f0c41486e2838ca94aa268f2384\
                d0e515744bf0e1e9014730440220160e49536bb29a49c7626744ee83150174c22fa40d5\
                8fb4cd554a907a6a7b825022045f6cf148504b334064686795f0968c689e542f475b8ef\
                5a5fa42383948226a3014c69522103e54bc61efbcb8eeff3a5ab2a92a75272f5f6820e3\
                8e3d28edb54beb06b86c0862103a553e30733d7a8df6d390d59cc136e2c9d9cf4e808f3\
                b6ab009beae68dd60822210291c5a54bb8b00b6f72b90af0ac0ecaf78fab026d8eded28\
                2ad95d4d65db268c953aeffffffff024c4f0d000000000017a9146ebf0484bd5053f727\
                c755a750aa4c815dfa112887a06b12020000000017a91410065dd50b3a7f299fef3b1c5\
                3b8216399916ab08700000000",
                12,
                return_p2sh,
                0,
            ),
            // 3 sigops (1 P2SH-P2WSH 2-of-3 MS in (3), P2SH + P2WSH outs (0))
            (
                "0100000000010117a31277a8ba3957be351fe4cffd080e05e07f9ee1594d638f55dd7d\
                707a983c01000000232200203a33fc9628c29f36a492d9fd811fd20231fbd563f7863e7\
                9c4dc0ed34ea84b15ffffffff033bed03000000000017a914fb00d9a49663fd8ae84339\
                8ae81299a1941fb8d287429404000000000017a9148fe08d81882a339cf913281eca8af\
                39110507c798751ab1300000000002200208819e4bac0109b659de6b9168b83238a050b\
                ef16278e470083b39d28d2aa5a6904004830450221009faf81f72ec9b14a39f0f0e12f0\
                1a7175a4fe3239cd9a015ff2085985a9b0e3f022059e1aaf96c9282298bdc9968a46d8a\
                d28e7299799835cf982b02c35e217caeae0147304402202b1875355ee751e0c8b21990b\
                7ea73bd84dfd3bd17477b40fc96552acba306ad02204913bc43acf02821a3403132aa0c\
                33ac1c018d64a119f6cb55dfb8f408d997ef01695221023c15bf3436c0b4089e0ed0428\
                5101983199d0967bd6682d278821c1e2ac3583621034d924ccabac6d190ce8343829834\
                cac737aa65a9abe521bcccdcc3882d97481f21035d01d092bb0ebcb793ba3ffa0aeb143\
                2868f5277d5d3d2a7d2bc1359ec13abbd53aee1560c00",
                3,
                return_p2sh,
                0,
            ),
            // 80 sigops (1 P2PKH ins (0), 1 BARE MS outs (20x4))
            (
                "0100000001628c1726fecd23331ae9ff2872341b82d2c03180aa64f9bceefe457448db\
                e579020000006a47304402204799581a5b34ae5adca21ef22c55dbfcee58527127c95d0\
                1413820fe7556ed970220391565b24dc47ce57fe56bf029792f821a392cdb5a3d45ed85\
                c158997e7421390121037b2fb5b602e51c493acf4bf2d2423bcf63a09b3b99dfb7bd3c8\
                d74733b5d66f5ffffffff011c0300000000000069512103a29472a1848105b2225f0eca\
                5c35ada0b0abbc3c538818a53eca177f4f4dcd9621020c8fd41b65ae6b980c072c5a9f3\
                aec9f82162c92eb4c51d914348f4390ac39122102222222222222222222222222222222\
                222222222222222222222222222222222253ae00000000",
                80,
                return_none,
                80,
            ),
        ];

        // All we need is to trigger 3 cases for prevout
        fn return_p2sh(_outpoint: &OutPoint) -> Option<TxOut> {
            Some(
                deserialize(&hex!(
                    "cc721b000000000017a91428203c10cc8f18a77412caaa83dabaf62b8fbb0f87"
                ))
                .unwrap(),
            )
        }
        fn return_p2wpkh(_outpoint: &OutPoint) -> Option<TxOut> {
            Some(
                deserialize(&hex!(
                    "e695779d000000001600141c6977423aa4b82a0d7f8496cdf3fc2f8b4f580c"
                ))
                .unwrap(),
            )
        }
        fn return_p2wsh(_outpoint: &OutPoint) -> Option<TxOut> {
            Some(
                deserialize(&hex!(
                    "66b51e0900000000220020dbd6c9d5141617eff823176aa226eb69153c1e31334ac37469251a2539fc5c2b"
                ))
                .unwrap(),
            )
        }
        fn return_none(_outpoint: &OutPoint) -> Option<TxOut> { None }

        for (hx, expected, spent_fn, expected_none) in tx_hexes.iter() {
            let tx_bytes = hex!(hx);
            let tx: Transaction = deserialize(&tx_bytes).unwrap();
            assert_eq!(tx.total_sigop_cost(spent_fn), *expected);
            assert_eq!(tx.total_sigop_cost(return_none), *expected_none);
        }
    }

    #[test]
    fn weight_predictions() {
        // TXID 3d3381f968e3a73841cba5e73bf47dcea9f25a9f7663c51c81f1db8229a309a0
        let tx_raw = hex!(
            "01000000000103fc9aa70afba04da865f9821734b556cca9fb5710\
             fc1338b97fba811033f755e308000000000000000019b37457784d\
             d04936f011f733b8016c247a9ef08d40007a54a5159d1fc62ee216\
             00000000000000004c4f2937c6ccf8256d9711a19df1ae62172297\
             0bf46be925ff15f490efa1633d01000000000000000002c0e1e400\
             0000000017a9146983f776902c1d1d0355ae0962cb7bc69e9afbde\
             8706a1e600000000001600144257782711458506b89f255202d645\
             e25c41144702483045022100dcada0499865a49d0aab8cb113c5f8\
             3fd5a97abc793f97f3f53aa4b9d1192ed702202094c7934666a30d\
             6adb1cc9e3b6bc14d2ffebd3200f3908c40053ef2df640b5012103\
             15434bb59b615a383ae87316e784fc11835bb97fab33fdd2578025\
             e9968d516e0247304402201d90b3197650569eba4bc0e0b1e2dca7\
             7dfac7b80d4366f335b67e92e0546e4402203b4be1d443ad7e3a5e\
             a92aafbcdc027bf9ccf5fe68c0bc8f3ebb6ab806c5464c012103e0\
             0d92b0fe60731a54fdbcc6920934159db8ffd69d55564579b69a22\
             ec5bb7530247304402205ab83b734df818e64d8b9e86a8a75f9d00\
             5c0c6e1b988d045604853ab9ccbde002205a580235841df609d6bd\
             67534bdcd301999b18e74e197e9e476cdef5fdcbf822012102ebb3\
             e8a4638ede4721fb98e44e3a3cd61fecfe744461b85e0b6a6a1017\
             5d5aca00000000"
        );

        let tx = Transaction::consensus_decode::<&[u8]>(&mut tx_raw.as_ref()).unwrap();
        let input_weights = vec![
            InputWeightPrediction::P2WPKH_MAX,
            InputWeightPrediction::ground_p2wpkh(1),
            InputWeightPrediction::ground_p2wpkh(1),
        ];
        // Outputs: [P2SH, P2WPKH]

        // Confirm the transaction's predicted weight matches its actual weight.
        let predicted = predict_weight(input_weights, tx.script_pubkey_lens());
        let expected = tx.weight();
        assert_eq!(predicted, expected);

        // Confirm signature grinding input weight predictions are aligned with constants.
        assert_eq!(
            InputWeightPrediction::ground_p2wpkh(0).weight(),
            InputWeightPrediction::P2WPKH_MAX.weight()
        );
        assert_eq!(
            InputWeightPrediction::ground_p2pkh_compressed(0).weight(),
            InputWeightPrediction::P2PKH_COMPRESSED_MAX.weight()
        );
    }

    #[test]
    fn sequence_debug_output() {
        let seq = Sequence::from_seconds_floor(1000);
        println!("{:?}", seq)
    }

    #[test]
    fn outpoint_format() {
        let outpoint = OutPoint::default();

        let debug = "OutPoint { txid: 0000000000000000000000000000000000000000000000000000000000000000, vout: 4294967295 }";
        assert_eq!(debug, format!("{:?}", &outpoint));

        let display = "0000000000000000000000000000000000000000000000000000000000000000:4294967295";
        assert_eq!(display, format!("{}", &outpoint));

        let pretty_debug = "OutPoint {\n    txid: 0000000000000000000000000000000000000000000000000000000000000000,\n    vout: 4294967295,\n}";
        assert_eq!(pretty_debug, format!("{:#?}", &outpoint));

        let debug_txid = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(debug_txid, format!("{:?}", &outpoint.txid));

        let display_txid = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(display_txid, format!("{}", &outpoint.txid));

        let pretty_txid = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(pretty_txid, format!("{:#}", &outpoint.txid));
    }
}

#[cfg(bench)]
mod benches {
    use hex::test_hex_unwrap as hex;
    use io::sink;
    use test::{black_box, Bencher};

    use super::Transaction;
    use crate::consensus::{deserialize, Encodable};

    const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[bench]
    pub fn bench_transaction_size(bh: &mut Bencher) {
        let raw_tx = hex!(SOME_TX);

        let mut tx: Transaction = deserialize(&raw_tx).unwrap();

        bh.iter(|| {
            black_box(black_box(&mut tx).total_size());
        });
    }

    #[bench]
    pub fn bench_transaction_serialize(bh: &mut Bencher) {
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = deserialize(&raw_tx).unwrap();

        let mut data = Vec::with_capacity(raw_tx.len());

        bh.iter(|| {
            let result = tx.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_transaction_serialize_logic(bh: &mut Bencher) {
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = deserialize(&raw_tx).unwrap();

        bh.iter(|| {
            let size = tx.consensus_encode(&mut sink());
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_transaction_deserialize(bh: &mut Bencher) {
        let raw_tx = hex!(SOME_TX);

        bh.iter(|| {
            let tx: Transaction = deserialize(&raw_tx).unwrap();
            black_box(&tx);
        });
    }
}
