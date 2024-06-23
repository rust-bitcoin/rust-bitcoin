// SPDX-License-Identifier: CC0-1.0

//! Address tests.

use bitcoin_primitives::consensus::params;
use bitcoin_primitives::network::Network::{Bitcoin, Testnet};
use bitcoin_primitives::PrivateKey;
use hex_lit::hex;

use super::*;

fn roundtrips(addr: &Address, network: Network) {
    assert_eq!(
        Address::from_str(&addr.to_string()).unwrap().assume_checked(),
        *addr,
        "string round-trip failed for {}",
        addr,
    );
    assert_eq!(
        Address::from_script(&addr.script_pubkey(), network)
            .expect("failed to create inner address from script_pubkey"),
        *addr,
        "script round-trip failed for {}",
        addr,
    );

    #[cfg(feature = "serde")]
    {
        let ser = serde_json::to_string(addr).expect("failed to serialize address");
        let back: Address<NetworkUnchecked> =
            serde_json::from_str(&ser).expect("failed to deserialize address");
        assert_eq!(back.assume_checked(), *addr, "serde round-trip failed for {}", addr)
    }
}

#[test]
fn test_p2pkh_address_58() {
    let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<PubkeyHash>().unwrap();
    let addr = Address::p2pkh(hash, NetworkKind::Main);

    assert_eq!(
        addr.script_pubkey(),
        ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac").unwrap()
    );
    assert_eq!(&addr.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
    assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
    roundtrips(&addr, Bitcoin);
}

#[test]
fn test_p2pkh_from_key() {
    let key = "048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183".parse::<PublicKey>().unwrap();
    let addr = Address::p2pkh(key, NetworkKind::Main);
    assert_eq!(&addr.to_string(), "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY");

    let key = "03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f"
        .parse::<PublicKey>()
        .unwrap();
    let addr = Address::p2pkh(key, NetworkKind::Test);
    assert_eq!(&addr.to_string(), "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC");
    assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
    roundtrips(&addr, Testnet);
}

#[test]
fn test_p2sh_address_58() {
    let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<ScriptHash>().unwrap();
    let addr = Address::p2sh_from_hash(hash, NetworkKind::Main);

    assert_eq!(
        addr.script_pubkey(),
        ScriptBuf::from_hex("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087").unwrap(),
    );
    assert_eq!(&addr.to_string(), "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k");
    assert_eq!(addr.address_type(), Some(AddressType::P2sh));
    roundtrips(&addr, Bitcoin);
}

#[test]
fn test_p2sh_parse() {
    let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae").unwrap();
    let addr = Address::p2sh(&script, NetworkKind::Test).unwrap();
    assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
    assert_eq!(addr.address_type(), Some(AddressType::P2sh));
    roundtrips(&addr, Testnet);
}

#[test]
fn test_p2sh_parse_for_large_script() {
    let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123").unwrap();
    assert_eq!(
        Address::p2sh(&script, NetworkKind::Test),
        Err(script::RedeemScriptSizeError { size: script.len() })
    );
}

#[test]
fn test_p2wpkh() {
    // stolen from Bitcoin transaction: b3c8c2b6cfc335abbcb2c7823a8453f55d64b2b5125a9a61e8737230cdb8ce20
    let key = "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc"
        .parse::<CompressedPublicKey>()
        .unwrap();
    let addr = Address::p2wpkh(key, KnownHrp::Mainnet);
    assert_eq!(&addr.to_string(), "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw");
    assert_eq!(addr.address_type(), Some(AddressType::P2wpkh));
    roundtrips(&addr, Bitcoin);
}

#[test]
fn test_p2wsh() {
    // stolen from Bitcoin transaction 5df912fda4becb1c29e928bec8d64d93e9ba8efa9b5b405bd683c86fd2c65667
    let script = ScriptBuf::from_hex("52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae").unwrap();
    let addr = Address::p2wsh(&script, KnownHrp::Mainnet).expect("script is valid");
    assert_eq!(&addr.to_string(), "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej");
    assert_eq!(addr.address_type(), Some(AddressType::P2wsh));
    roundtrips(&addr, Bitcoin);
}

#[test]
fn test_p2shwpkh() {
    // stolen from Bitcoin transaction: ad3fd9c6b52e752ba21425435ff3dd361d6ac271531fc1d2144843a9f550ad01
    let key = "026c468be64d22761c30cd2f12cbc7de255d592d7904b1bab07236897cc4c2e766"
        .parse::<CompressedPublicKey>()
        .unwrap();
    let addr = Address::p2shwpkh(key, NetworkKind::Main);
    assert_eq!(&addr.to_string(), "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE");
    assert_eq!(addr.address_type(), Some(AddressType::P2sh));
    roundtrips(&addr, Bitcoin);
}

#[test]
fn test_p2shwsh() {
    // stolen from Bitcoin transaction f9ee2be4df05041d0e0a35d7caa3157495ca4f93b233234c9967b6901dacf7a9
    let script = ScriptBuf::from_hex("522103e5529d8eaa3d559903adb2e881eb06c86ac2574ffa503c45f4e942e2a693b33e2102e5f10fcdcdbab211e0af6a481f5532536ec61a5fdbf7183770cf8680fe729d8152ae").unwrap();
    let addr = Address::p2shwsh(&script, NetworkKind::Main).expect("script is valid");
    assert_eq!(&addr.to_string(), "36EqgNnsWW94SreZgBWc1ANC6wpFZwirHr");
    assert_eq!(addr.address_type(), Some(AddressType::P2sh));
    roundtrips(&addr, Bitcoin);
}

#[test]
fn test_non_existent_segwit_version() {
    // 40-byte program
    let program =
        hex!("654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4");
    let program = WitnessProgram::new(WitnessVersion::V13, &program).expect("valid program");

    let addr = Address::from_witness_program(program, KnownHrp::Mainnet);
    roundtrips(&addr, Bitcoin);
}

#[test]
fn test_address_debug() {
    // This is not really testing output of Debug but the ability and proper functioning
    // of Debug derivation on structs generic in NetworkValidation.
    #[derive(Debug)]
    #[allow(unused)]
    struct Test<V: NetworkValidation> {
        address: Address<V>,
    }

    let addr_str = "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k";
    let unchecked = Address::from_str(addr_str).unwrap();

    assert_eq!(
        format!("{:?}", Test { address: unchecked.clone() }),
        format!("Test {{ address: Address<NetworkUnchecked>({}) }}", addr_str)
    );

    assert_eq!(
        format!("{:?}", Test { address: unchecked.assume_checked() }),
        format!("Test {{ address: {} }}", addr_str)
    );
}

#[test]
fn test_address_type() {
    let addresses = [
        ("1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY", Some(AddressType::P2pkh)),
        ("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k", Some(AddressType::P2sh)),
        ("bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw", Some(AddressType::P2wpkh)),
        (
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
            Some(AddressType::P2wsh),
        ),
        ("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", Some(AddressType::P2tr)),
        // Related to future extensions, addresses are valid but have no type
        // segwit v1 and len != 32
        ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", None),
        // segwit v2
        ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", None),
    ];
    for (address, expected_type) in &addresses {
        let addr =
            Address::from_str(address).unwrap().require_network(Network::Bitcoin).expect("mainnet");
        assert_eq!(&addr.address_type(), expected_type);
    }
}

#[test]
#[cfg(feature = "serde")]
fn test_json_serialize() {
    use serde_json;

    let addr = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM").unwrap().assume_checked();
    let json = serde_json::to_value(&addr).unwrap();
    assert_eq!(json, serde_json::Value::String("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".to_owned()));
    let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
    assert_eq!(addr.to_string(), into.to_string());
    assert_eq!(
        into.script_pubkey(),
        ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac").unwrap()
    );

    let addr = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap().assume_checked();
    let json = serde_json::to_value(&addr).unwrap();
    assert_eq!(json, serde_json::Value::String("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k".to_owned()));
    let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
    assert_eq!(addr.to_string(), into.to_string());
    assert_eq!(
        into.script_pubkey(),
        ScriptBuf::from_hex("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087").unwrap()
    );

    let addr: Address<NetworkUnchecked> =
        Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
            .unwrap();
    let json = serde_json::to_value(addr).unwrap();
    assert_eq!(
        json,
        serde_json::Value::String(
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
        )
    );

    let addr = Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        .unwrap()
        .assume_checked();
    let json = serde_json::to_value(&addr).unwrap();
    assert_eq!(
        json,
        serde_json::Value::String(
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
        )
    );
    let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
    assert_eq!(addr.to_string(), into.to_string());
    assert_eq!(
        into.script_pubkey(),
        ScriptBuf::from_hex("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
            .unwrap()
    );

    let addr =
        Address::from_str("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl").unwrap().assume_checked();
    let json = serde_json::to_value(&addr).unwrap();
    assert_eq!(
        json,
        serde_json::Value::String("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl".to_owned())
    );
    let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
    assert_eq!(addr.to_string(), into.to_string());
    assert_eq!(
        into.script_pubkey(),
        ScriptBuf::from_hex("001454d26dddb59c7073c6a197946ea1841951fa7a74").unwrap()
    );
}

#[test]
fn test_qr_string() {
    for el in ["132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM", "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k"].iter() {
        let addr =
            Address::from_str(el).unwrap().require_network(Network::Bitcoin).expect("mainnet");
        assert_eq!(addr.to_qr_uri(), format!("bitcoin:{}", el));
    }

    for el in [
        "bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl",
        "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
    ]
    .iter()
    {
        let addr = Address::from_str(el).unwrap().assume_checked();
        assert_eq!(addr.to_qr_uri(), format!("bitcoin:{}", el.to_ascii_uppercase()));
    }
}

#[test]
fn p2tr_from_untweaked() {
    //Test case from BIP-086
    let internal_key = XOnlyPublicKey::from_str(
        "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
    )
    .unwrap();
    let secp = Secp256k1::verification_only();
    let address = Address::p2tr(&secp, internal_key, None, KnownHrp::Mainnet);
    assert_eq!(
        address.to_string(),
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
    assert_eq!(address.address_type(), Some(AddressType::P2tr));
    roundtrips(&address, Bitcoin);
}

#[test]
fn test_is_related_to_pubkey_p2wpkh() {
    let address_string = "bc1qhvd6suvqzjcu9pxjhrwhtrlj85ny3n2mqql5w4";
    let address = Address::from_str(address_string)
        .expect("address")
        .require_network(Network::Bitcoin)
        .expect("mainnet");

    let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
    let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

    let result = address.is_related_to_pubkey(pubkey);
    assert!(result);

    let unused_pubkey =
        PublicKey::from_str("02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c")
            .expect("pubkey");
    assert!(!address.is_related_to_pubkey(unused_pubkey))
}

#[test]
fn test_is_related_to_pubkey_p2shwpkh() {
    let address_string = "3EZQk4F8GURH5sqVMLTFisD17yNeKa7Dfs";
    let address = Address::from_str(address_string)
        .expect("address")
        .require_network(Network::Bitcoin)
        .expect("mainnet");

    let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
    let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

    let result = address.is_related_to_pubkey(pubkey);
    assert!(result);

    let unused_pubkey =
        PublicKey::from_str("02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c")
            .expect("pubkey");
    assert!(!address.is_related_to_pubkey(unused_pubkey))
}

#[test]
fn test_is_related_to_pubkey_p2pkh() {
    let address_string = "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx";
    let address = Address::from_str(address_string)
        .expect("address")
        .require_network(Network::Bitcoin)
        .expect("mainnet");

    let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
    let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

    let result = address.is_related_to_pubkey(pubkey);
    assert!(result);

    let unused_pubkey =
        PublicKey::from_str("02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c")
            .expect("pubkey");
    assert!(!address.is_related_to_pubkey(unused_pubkey))
}

#[test]
fn test_is_related_to_pubkey_p2pkh_uncompressed_key() {
    let address_string = "msvS7KzhReCDpQEJaV2hmGNvuQqVUDuC6p";
    let address = Address::from_str(address_string)
        .expect("address")
        .require_network(Network::Testnet)
        .expect("testnet");

    let pubkey_string = "04e96e22004e3db93530de27ccddfdf1463975d2138ac018fc3e7ba1a2e5e0aad8e424d0b55e2436eb1d0dcd5cb2b8bcc6d53412c22f358de57803a6a655fbbd04";
    let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

    let result = address.is_related_to_pubkey(pubkey);
    assert!(result);

    let unused_pubkey =
        PublicKey::from_str("02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c")
            .expect("pubkey");
    assert!(!address.is_related_to_pubkey(unused_pubkey))
}

#[test]
fn test_is_related_to_pubkey_p2tr() {
    let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
    let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
    let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
    let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
    let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

    assert_eq!(
        address,
        Address::from_str("bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e")
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet")
    );

    let result = address.is_related_to_pubkey(pubkey);
    assert!(result);

    let unused_pubkey =
        PublicKey::from_str("02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c")
            .expect("pubkey");
    assert!(!address.is_related_to_pubkey(unused_pubkey));
}

#[test]
fn test_is_related_to_xonly_pubkey() {
    let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
    let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
    let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
    let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
    let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

    assert_eq!(
        address,
        Address::from_str("bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e")
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet")
    );

    let result = address.is_related_to_xonly_pubkey(xonly_pubkey);
    assert!(result);
}

#[test]
fn test_fail_address_from_script() {
    use bitcoin_primitives::witness_program;

    let bad_p2wpkh = ScriptBuf::from_hex("0014dbc5b0a8f9d4353b4b54c3db48846bb15abfec").unwrap();
    let bad_p2wsh =
        ScriptBuf::from_hex("00202d4fa2eb233d008cc83206fa2f4f2e60199000f5b857a835e3172323385623")
            .unwrap();
    let invalid_segwitv0_script =
        ScriptBuf::from_hex("001161458e330389cd0437ee9fe3641d70cc18").unwrap();
    let expected = Err(FromScriptError::UnrecognizedScript);

    assert_eq!(Address::from_script(&bad_p2wpkh, Network::Bitcoin), expected);
    assert_eq!(Address::from_script(&bad_p2wsh, Network::Bitcoin), expected);
    assert_eq!(
        Address::from_script(&invalid_segwitv0_script, &params::MAINNET),
        Err(FromScriptError::WitnessProgram(witness_program::Error::InvalidSegwitV0Length(17)))
    );
}

#[test]
fn valid_address_parses_correctly() {
    let addr = AddressType::from_str("p2tr").expect("false negative while parsing address");
    assert_eq!(addr, AddressType::P2tr);
}

#[test]
fn invalid_address_parses_error() {
    let got = AddressType::from_str("invalid");
    let want = Err(UnknownAddressTypeError("invalid".to_string()));
    assert_eq!(got, want);
}

#[test]
fn test_matches_script_pubkey() {
    let addresses = [
        "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY",
        "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx",
        "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k",
        "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE",
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        "bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e",
    ];
    for addr in &addresses {
        let addr = Address::from_str(addr).unwrap().require_network(Network::Bitcoin).unwrap();
        for another in &addresses {
            let another =
                Address::from_str(another).unwrap().require_network(Network::Bitcoin).unwrap();
            assert_eq!(addr.matches_script_pubkey(&another.script_pubkey()), addr == another);
        }
    }
}

#[test]
fn test_key_derivation() {
    // testnet compressed
    let sk = PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
    assert_eq!(sk.network, NetworkKind::Test);
    assert!(sk.compressed);
    assert_eq!(&sk.to_wif(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

    let secp = Secp256k1::new();
    let pk = Address::p2pkh(sk.public_key(&secp), sk.network);
    assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

    // test string conversion
    assert_eq!(&sk.to_string(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
    let sk_str =
        PrivateKey::from_str("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
    assert_eq!(&sk.to_wif(), &sk_str.to_wif());

    // mainnet uncompressed
    let sk = PrivateKey::from_wif("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
    assert_eq!(sk.network, NetworkKind::Main);
    assert!(!sk.compressed);
    assert_eq!(&sk.to_wif(), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");

    let secp = Secp256k1::new();
    let mut pk = sk.public_key(&secp);
    assert!(!pk.compressed);
    assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
    assert_eq!(pk, PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap());
    let addr = Address::p2pkh(pk, sk.network);
    assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
    pk.compressed = true;
    assert_eq!(
        &pk.to_string(),
        "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
    );
    assert_eq!(
        pk,
        PublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af")
            .unwrap()
    );
}

#[test]
fn bip_341_tests() {
    use bitcoin_primitives::hex::FromHex;
    use bitcoin_primitives::taproot::{
        ControlBlock, LeafVersion, TapLeafHash, TapTweak, TapTweakHash, TaprootBuilder,
        XOnlyPublicKey,
    };
    use bitcoin_primitives::{secp256k1, ScriptBuf};

    use crate::Address;

    fn process_script_trees(
        v: &serde_json::Value,
        mut builder: TaprootBuilder,
        leaves: &mut Vec<(ScriptBuf, LeafVersion)>,
        depth: u8,
    ) -> TaprootBuilder {
        if v.is_null() {
            // nothing to push
        } else if v.is_array() {
            for leaf in v.as_array().unwrap() {
                builder = process_script_trees(leaf, builder, leaves, depth + 1);
            }
        } else {
            let script = ScriptBuf::from_hex(v["script"].as_str().unwrap()).unwrap();
            let ver =
                LeafVersion::from_consensus(v["leafVersion"].as_u64().unwrap() as u8).unwrap();
            leaves.push((script.clone(), ver));
            builder = builder.add_leaf_with_ver(depth, script, ver).unwrap();
        }
        builder
    }

    let data = bip_341_read_json();
    // Check the version of data
    assert!(data["version"] == 1);
    let secp = &secp256k1::Secp256k1::verification_only();

    for arr in data["scriptPubKey"].as_array().unwrap() {
        let internal_key =
            XOnlyPublicKey::from_str(arr["given"]["internalPubkey"].as_str().unwrap()).unwrap();
        // process the tree
        let script_tree = &arr["given"]["scriptTree"];
        let mut merkle_root = None;
        if script_tree.is_null() {
            assert!(arr["intermediary"]["merkleRoot"].is_null());
        } else {
            merkle_root = Some(
                TapNodeHash::from_str(arr["intermediary"]["merkleRoot"].as_str().unwrap()).unwrap(),
            );
            let leaf_hashes = arr["intermediary"]["leafHashes"].as_array().unwrap();
            let ctrl_blks = arr["expected"]["scriptPathControlBlocks"].as_array().unwrap();
            let mut builder = TaprootBuilder::new();
            let mut leaves = vec![];
            builder = process_script_trees(script_tree, builder, &mut leaves, 0);
            let spend_info = builder.finalize(secp, internal_key).unwrap();
            for (i, script_ver) in leaves.iter().enumerate() {
                let expected_leaf_hash = leaf_hashes[i].as_str().unwrap();
                let expected_ctrl_blk = ControlBlock::decode(
                    &Vec::<u8>::from_hex(ctrl_blks[i].as_str().unwrap()).unwrap(),
                )
                .unwrap();

                let leaf_hash = TapLeafHash::from_script(&script_ver.0, script_ver.1);
                let ctrl_blk = spend_info.control_block(script_ver).unwrap();
                assert_eq!(leaf_hash.to_string(), expected_leaf_hash);
                assert_eq!(ctrl_blk, expected_ctrl_blk);
            }
        }
        let expected_output_key =
            XOnlyPublicKey::from_str(arr["intermediary"]["tweakedPubkey"].as_str().unwrap())
                .unwrap();
        let expected_tweak =
            TapTweakHash::from_str(arr["intermediary"]["tweak"].as_str().unwrap()).unwrap();
        let expected_spk =
            ScriptBuf::from_hex(arr["expected"]["scriptPubKey"].as_str().unwrap()).unwrap();
        let expected_addr = Address::from_str(arr["expected"]["bip350Address"].as_str().unwrap())
            .unwrap()
            .assume_checked();

        let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
        let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
        let addr = Address::p2tr(secp, internal_key, merkle_root, KnownHrp::Mainnet);
        let spk = addr.script_pubkey();

        assert_eq!(expected_output_key, output_key.to_inner());
        assert_eq!(expected_tweak, tweak);
        assert_eq!(expected_addr, addr);
        assert_eq!(expected_spk, spk);
    }
}

fn bip_341_read_json() -> serde_json::Value {
    let json_str = include_str!("../../bitcoin/tests/data/bip341_tests.json");
    serde_json::from_str(json_str).expect("JSON was not well-formatted")
}
