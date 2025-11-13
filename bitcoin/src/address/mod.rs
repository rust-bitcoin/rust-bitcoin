// SPDX-License-Identifier: CC0-1.0

//! Bitcoin addresses.
//!
//! Support for segwit and legacy addresses (bech32 and base58 respectively).
//!
//! # Examples
//!
//! ### Creating a new address from a randomly-generated key pair.
//!
//! ```rust
//! #[cfg(all(feature = "rand", feature = "std"))] {
//! use bitcoin::secp256k1::rand;
//! use bitcoin::{Address, Network, PublicKey};
//!
//! // Generate random key pair.
//! let (_sk, pk) = secp256k1::generate_keypair(&mut rand::rng());
//! let public_key = PublicKey::new(pk); // Or `PublicKey::from(pk)`.
//!
//! // Generate a mainnet pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Bitcoin);
//! }
//! ```
//!
//! ### Using an `Address` as a struct field.
//!
//! ```rust
//! # #[cfg(feature = "serde")] {
//! # use serde::{self, Deserialize, Serialize};
//! use bitcoin::address::{Address, NetworkValidation, NetworkValidationUnchecked};
//! #[derive(Serialize, Deserialize)]
//! struct Foo<V>
//!     where V: NetworkValidation,
//! {
//!     #[serde(bound(deserialize = "V: NetworkValidationUnchecked"))]
//!     address: Address<V>,
//! }
//! # }
//! ```

pub use addresses::address::*;

use crate::crypto::key::{CompressedPublicKey, PubkeyHash};
use crate::crypto::WitnessProgramExt as _;
use crate::network::{Network, NetworkKind};
use crate::script::witness_program::WitnessProgram;
use crate::script::witness_version::WitnessVersion;
use crate::script::{
    self, RedeemScriptSizeError, Script, ScriptExt as _, ScriptHash, ScriptHashableTag,
    ScriptPubKey, ScriptPubKeyBuf, ScriptPubKeyBufExt as _, ScriptPubKeyExt as _, WScriptHash,
    WitnessScript, WitnessScriptExt as _, WitnessScriptSizeError,
};

/// Extension trait providing script helpers for [`Address`].
pub trait AddressScriptExt: Sized {
    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] from a script.
    fn p2sh<T: ScriptHashableTag>(
        redeem_script: &Script<T>,
        network: impl Into<NetworkKind>,
    ) -> Result<Self, RedeemScriptSizeError>;

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] from a script hash.
    fn p2sh_from_hash(hash: ScriptHash, network: impl Into<NetworkKind>) -> Self;

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] that embeds a P2WPKH.
    fn p2shwpkh(pk: CompressedPublicKey, network: impl Into<NetworkKind>) -> Self;

    /// Constructs a new pay-to-witness-script-hash (P2WSH) [`Address`] from a witness script.
    fn p2wsh(
        witness_script: &WitnessScript,
        hrp: impl Into<KnownHrp>,
    ) -> Result<Self, WitnessScriptSizeError>;

    /// Constructs a new pay-to-witness-script-hash (P2WSH) [`Address`] from a witness script hash.
    fn p2wsh_from_hash(hash: WScriptHash, hrp: impl Into<KnownHrp>) -> Self;

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] that embeds a P2WSH.
    fn p2shwsh(
        witness_script: &WitnessScript,
        network: impl Into<NetworkKind>,
    ) -> Result<Self, WitnessScriptSizeError>;

    /// Constructs a new [`Address`] from an output script (`scriptPubkey`).
    fn from_script(
        script: &ScriptPubKey,
        params: impl AsRef<Network>,
    ) -> Result<Self, FromScriptError>;

    /// Generates a script pubkey spending to this address.
    fn script_pubkey(&self) -> ScriptPubKeyBuf;

    /// Returns true if the address creates a particular script.
    fn matches_script_pubkey(&self, script: &ScriptPubKey) -> bool;
}

impl AddressScriptExt for Address {
    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] from a script.
    ///
    /// This address type was introduced with BIP-0016 and is the popular type to implement multi-sig
    /// these days.
    fn p2sh<T: ScriptHashableTag>(
        redeem_script: &Script<T>,
        network: impl Into<NetworkKind>,
    ) -> Result<Self, RedeemScriptSizeError> {
        let hash = redeem_script.script_hash()?;
        Ok(Self::p2sh_from_hash(hash, network))
    }

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] from a script hash.
    ///
    /// # Warning
    ///
    /// The `hash` pre-image (redeem script) must not exceed 520 bytes in length
    /// otherwise outputs created from the returned address will be un-spendable.
    fn p2sh_from_hash(hash: ScriptHash, network: impl Into<NetworkKind>) -> Self {
        Self::p2sh_from_hash(hash, network)
    }

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] that embeds a
    /// pay-to-witness-public-key-hash (P2WPKH).
    ///
    /// This is a SegWit address type that looks familiar (as p2sh) to legacy clients.
    fn p2shwpkh(pk: CompressedPublicKey, network: impl Into<NetworkKind>) -> Self {
        let builder = ScriptPubKey::builder().push_int_unchecked(0).push_slice(pk.wpubkey_hash());
        let script_hash = builder.as_script().script_hash().expect("script is less than 520 bytes");
        Self::p2sh_from_hash(script_hash, network)
    }

    /// Constructs a new pay-to-witness-script-hash (P2WSH) [`Address`] from a witness script.
    fn p2wsh(
        witness_script: &WitnessScript,
        hrp: impl Into<KnownHrp>,
    ) -> Result<Self, WitnessScriptSizeError> {
        let program = WitnessProgram::p2wsh(witness_script)?;
        Ok(Self::from_witness_program(program, hrp))
    }

    /// Constructs a new pay-to-witness-script-hash (P2WSH) [`Address`] from a witness script hash.
    fn p2wsh_from_hash(hash: WScriptHash, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wsh_from_hash(hash);
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] that embeds a
    /// pay-to-witness-script-hash (P2WSH).
    ///
    /// This is a SegWit address type that looks familiar (as p2sh) to legacy clients.
    fn p2shwsh(
        witness_script: &WitnessScript,
        network: impl Into<NetworkKind>,
    ) -> Result<Self, WitnessScriptSizeError> {
        let hash = witness_script.wscript_hash()?;
        let builder = ScriptPubKey::builder().push_int_unchecked(0).push_slice(hash);
        let script_hash = builder.as_script().script_hash().expect("script is less than 520 bytes");
        Ok(Self::p2sh_from_hash(script_hash, network))
    }

    /// Constructs a new [`Address`] from an output script (`scriptPubkey`).
    fn from_script(
        script: &ScriptPubKey,
        network: impl AsRef<Network>,
    ) -> Result<Self, FromScriptError> {
        let network = *AsRef::<Network>::as_ref(&network);
        if script.is_p2pkh() {
            let bytes = script.as_bytes()[3..23].try_into().expect("statically 20B long");
            let hash = PubkeyHash::from_byte_array(bytes);
            Ok(Self::p2pkh(hash, network))
        } else if script.is_p2sh() {
            let bytes = script.as_bytes()[2..22].try_into().expect("statically 20B long");
            let hash = ScriptHash::from_byte_array(bytes);
            Ok(Self::p2sh_from_hash(hash, network))
        } else if script.is_witness_program() {
            let opcode = script.first_opcode().expect("is_witness_program guarantees len > 4");

            let version = WitnessVersion::try_from(opcode)?;
            let program = WitnessProgram::new(version, &script.as_bytes()[2..])?;
            Ok(Self::from_witness_program(program, network))
        } else {
            Err(FromScriptError::UnrecognizedScript)
        }
    }

    /// Generates a script pubkey spending to this address.
    fn script_pubkey(&self) -> ScriptPubKeyBuf {
        if let Some(hash) = self.pubkey_hash() {
            ScriptPubKeyBuf::new_p2pkh(hash)
        } else if let Some(hash) = self.script_hash() {
            ScriptPubKeyBuf::new_p2sh(hash)
        } else if let Some(program) = self.witness_program() {
            let prog = script::witness_program::WitnessProgramExt::program(&program);
            let version = program.version();
            script::new_witness_program_unchecked(version, prog)
        } else {
            unreachable!("Address must be either P2PKH, P2SH, or SegWit")
        }
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    fn matches_script_pubkey(&self, script: &ScriptPubKey) -> bool {
        if let Some(hash) = self.pubkey_hash() {
            script.is_p2pkh()
                && &script.as_bytes()[3..23] == <PubkeyHash as AsRef<[u8; 20]>>::as_ref(&hash)
        } else if let Some(hash) = self.script_hash() {
            script.is_p2sh()
                && &script.as_bytes()[2..22] == <ScriptHash as AsRef<[u8; 20]>>::as_ref(&hash)
        } else if let Some(program) = self.witness_program() {
            script.is_witness_program() && &script.as_bytes()[2..] == program.program()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto::{TweakedPublicKey, XOnlyPublicKey};
    use hex_lit::hex;

    use super::*;
    use crate::network::Network::{self, Bitcoin, Testnet};
    use crate::network::{params, TestnetVersion};
    use crate::script::{RedeemScriptBuf, ScriptBufExt as _, WitnessScriptBuf};
    use crate::PublicKey;

    fn roundtrips(addr: &Address, network: Network) {
        assert_eq!(
            addr.to_string().parse::<Address<_>>().unwrap().assume_checked(),
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
    fn p2pkh_address_58() {
        let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<PubkeyHash>().unwrap();
        let addr = Address::p2pkh(hash, NetworkKind::Main);

        assert_eq!(
            addr.script_pubkey(),
            ScriptPubKeyBuf::from_hex_no_length_prefix(
                "76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac"
            )
            .unwrap()
        );
        assert_eq!(&addr.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn p2pkh_from_key() {
        let key = "048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183".parse::<PublicKey>().unwrap();
        let addr = Address::p2pkh(key, NetworkKind::Main);
        assert_eq!(&addr.to_string(), "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY");

        let key = "03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f"
            .parse::<PublicKey>()
            .unwrap();
        let addr = Address::p2pkh(key, NetworkKind::Test);
        assert_eq!(&addr.to_string(), "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Testnet(TestnetVersion::V3));
    }

    #[test]
    fn p2sh_address_58() {
        let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<ScriptHash>().unwrap();
        let addr = Address::p2sh_from_hash(hash, NetworkKind::Main);

        assert_eq!(
            addr.script_pubkey(),
            ScriptPubKeyBuf::from_hex_no_length_prefix(
                "a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087"
            )
            .unwrap(),
        );
        assert_eq!(&addr.to_string(), "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn p2sh_parse() {
        let script = RedeemScriptBuf::from_hex_no_length_prefix("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae").unwrap();
        let addr = Address::p2sh(&script, NetworkKind::Test).unwrap();
        assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Testnet(TestnetVersion::V3));
    }

    #[test]
    fn p2sh_parse_for_large_script() {
        let script = RedeemScriptBuf::from_hex_no_length_prefix("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123").unwrap();
        let res = Address::p2sh(&script, NetworkKind::Test);
        assert_eq!(res.unwrap_err().invalid_size(), script.len())
    }

    #[test]
    fn p2wpkh() {
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
    fn p2wsh() {
        // stolen from Bitcoin transaction 5df912fda4becb1c29e928bec8d64d93e9ba8efa9b5b405bd683c86fd2c65667
        let script = WitnessScriptBuf::from_hex_no_length_prefix("52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae").unwrap();
        let addr = Address::p2wsh(&script, KnownHrp::Mainnet).expect("script is valid");
        assert_eq!(
            &addr.to_string(),
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
        );
        assert_eq!(addr.address_type(), Some(AddressType::P2wsh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn p2shwpkh() {
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
    fn p2shwsh() {
        // stolen from Bitcoin transaction f9ee2be4df05041d0e0a35d7caa3157495ca4f93b233234c9967b6901dacf7a9
        let script = WitnessScriptBuf::from_hex_no_length_prefix("522103e5529d8eaa3d559903adb2e881eb06c86ac2574ffa503c45f4e942e2a693b33e2102e5f10fcdcdbab211e0af6a481f5532536ec61a5fdbf7183770cf8680fe729d8152ae").unwrap();
        let addr = Address::p2shwsh(&script, NetworkKind::Main).expect("script is valid");
        assert_eq!(&addr.to_string(), "36EqgNnsWW94SreZgBWc1ANC6wpFZwirHr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn non_existent_segwit_version() {
        // 40-byte program
        let program = hex!(
            "654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4"
        );
        let program = WitnessProgram::new(WitnessVersion::V13, &program).expect("valid program");

        let addr = Address::from_witness_program(program, KnownHrp::Mainnet);
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn address_debug() {
        // This is not really testing output of Debug but the ability and proper functioning
        // of Debug derivation on structs generic in NetworkValidation.
        #[derive(Debug)]
        #[allow(unused)]
        struct Test<V: NetworkValidation> {
            address: Address<V>,
        }

        let addr_str = "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k";
        let unchecked = addr_str.parse::<Address<_>>().unwrap();

        assert_eq!(
            format!("{:?}", Test { address: unchecked }),
            format!("Test {{ address: Address<NetworkUnchecked>({}) }}", addr_str)
        );

        assert_eq!(
            format!("{:?}", Test { address: unchecked.assume_checked() }),
            format!("Test {{ address: {} }}", addr_str)
        );
    }

    #[test]
    fn address_type() {
        let addresses = [
            ("1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY", Some(AddressType::P2pkh)),
            ("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k", Some(AddressType::P2sh)),
            ("bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw", Some(AddressType::P2wpkh)),
            (
                "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
                Some(AddressType::P2wsh),
            ),
            (
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                Some(AddressType::P2tr),
            ),
            // Related to future extensions, addresses are valid but have no type
            // SegWit v1 and len != 32
            ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", None),
            // SegWit v2
            ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", None),
        ];
        for (address, expected_type) in &addresses {
            let addr = address
                .parse::<Address<_>>()
                .unwrap()
                .require_network(Network::Bitcoin)
                .expect("mainnet");
            assert_eq!(&addr.address_type(), expected_type);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn json_serialize() {
        use serde_json;

        let addr =
            "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>().unwrap().assume_checked();
        let json = serde_json::to_value(addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptPubKeyBuf::from_hex_no_length_prefix(
                "76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac"
            )
            .unwrap()
        );

        let addr =
            "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k".parse::<Address<_>>().unwrap().assume_checked();
        let json = serde_json::to_value(addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptPubKeyBuf::from_hex_no_length_prefix(
                "a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087"
            )
            .unwrap()
        );

        let addr: Address<NetworkUnchecked> =
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
                .parse::<Address<_>>()
                .unwrap();
        let json = serde_json::to_value(addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
            )
        );

        let addr = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
            .parse::<Address<_>>()
            .unwrap()
            .assume_checked();
        let json = serde_json::to_value(addr).unwrap();
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
            ScriptPubKeyBuf::from_hex_no_length_prefix(
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
            )
            .unwrap()
        );

        let addr = "bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl"
            .parse::<Address<_>>()
            .unwrap()
            .assume_checked();
        let json = serde_json::to_value(addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptPubKeyBuf::from_hex_no_length_prefix(
                "001454d26dddb59c7073c6a197946ea1841951fa7a74"
            )
            .unwrap()
        );
    }

    #[test]
    fn qr_string() {
        for el in
            ["132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM", "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k"].iter()
        {
            let addr = el
                .parse::<Address<_>>()
                .unwrap()
                .require_network(Network::Bitcoin)
                .expect("mainnet");
            assert_eq!(addr.to_qr_uri(), format!("bitcoin:{}", el));
        }

        for el in [
            "bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl",
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
        ]
        .iter()
        {
            let addr = el.parse::<Address<_>>().unwrap().assume_checked();
            assert_eq!(addr.to_qr_uri(), format!("bitcoin:{}", el.to_ascii_uppercase()));
        }
    }

    #[test]
    fn p2tr_from_untweaked() {
        //Test case from BIP-086
        let internal_key = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
            .parse::<XOnlyPublicKey>()
            .unwrap();
        let address = Address::p2tr(internal_key, None, KnownHrp::Mainnet);
        assert_eq!(
            address.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(address.address_type(), Some(AddressType::P2tr));
        roundtrips(&address, Bitcoin);
    }

    #[test]
    fn is_related_to_pubkey_p2wpkh() {
        let address_string = "bc1qhvd6suvqzjcu9pxjhrwhtrlj85ny3n2mqql5w4";
        let address = address_string
            .parse::<Address<_>>()
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<PublicKey>().expect("pubkey");

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<PublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey))
    }

    #[test]
    fn is_related_to_pubkey_p2shwpkh() {
        let address_string = "3EZQk4F8GURH5sqVMLTFisD17yNeKa7Dfs";
        let address = address_string
            .parse::<Address<_>>()
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<PublicKey>().expect("pubkey");

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<PublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey))
    }

    #[test]
    fn is_related_to_pubkey_p2pkh() {
        let address_string = "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx";
        let address = address_string
            .parse::<Address<_>>()
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<PublicKey>().expect("pubkey");

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<PublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey))
    }

    #[test]
    fn is_related_to_pubkey_p2pkh_uncompressed_key() {
        let address_string = "msvS7KzhReCDpQEJaV2hmGNvuQqVUDuC6p";
        let address = address_string
            .parse::<Address<_>>()
            .expect("address")
            .require_network(Network::Testnet(TestnetVersion::V3))
            .expect("testnet");

        let pubkey_string = "04e96e22004e3db93530de27ccddfdf1463975d2138ac018fc3e7ba1a2e5e0aad8e424d0b55e2436eb1d0dcd5cb2b8bcc6d53412c22f358de57803a6a655fbbd04";
        let pubkey = pubkey_string.parse::<PublicKey>().expect("pubkey");

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<PublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey))
    }

    #[test]
    fn is_related_to_pubkey_p2tr() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<PublicKey>().expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

        assert_eq!(
            address,
            "bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e"
                .parse::<Address<_>>()
                .expect("address")
                .require_network(Network::Bitcoin)
                .expect("mainnet")
        );

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<PublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey));
    }

    #[test]
    fn is_related_to_xonly_pubkey() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<PublicKey>().expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

        assert_eq!(
            address,
            "bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e"
                .parse::<Address<_>>()
                .expect("address")
                .require_network(Network::Bitcoin)
                .expect("mainnet")
        );

        let result = address.is_related_to_xonly_pubkey(xonly_pubkey);
        assert!(result);
    }

    #[test]
    fn fail_address_from_script() {
        use crate::witness_program;

        let bad_p2wpkh = ScriptPubKeyBuf::from_hex_no_length_prefix(
            "15000014dbc5b0a8f9d4353b4b54c3db48846bb15abfec",
        )
        .unwrap();
        let bad_p2wsh = ScriptPubKeyBuf::from_hex_no_length_prefix(
            "00202d4fa2eb233d008cc83206fa2f4f2e60199000f5b857a835e3172323385623",
        )
        .unwrap();
        let invalid_segwitv0_script =
            ScriptPubKeyBuf::from_hex_no_length_prefix("001161458e330389cd0437ee9fe3641d70cc18")
                .unwrap();
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
        let addr = "p2tr".parse::<AddressType>().expect("false negative while parsing address");
        assert_eq!(addr, AddressType::P2tr);
    }

    #[test]
    fn invalid_address_parses_error() {
        let addr = "invalid".parse::<AddressType>();
        assert!(addr.is_err());
    }

    #[test]
    fn matches_script_pubkey() {
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
            let addr =
                addr.parse::<Address<_>>().unwrap().require_network(Network::Bitcoin).unwrap();
            for another in &addresses {
                let another = another
                    .parse::<Address<_>>()
                    .unwrap()
                    .require_network(Network::Bitcoin)
                    .unwrap();
                assert_eq!(addr.matches_script_pubkey(&another.script_pubkey()), addr == another);
            }
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_address_usage_in_struct() {
        use serde::{self, Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct Foo<V>
        where
            V: NetworkValidation,
        {
            #[serde(bound(deserialize = "V: NetworkValidationUnchecked"))]
            address: Address<V>,
        }

        let addr_str = "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k";
        let unchecked = addr_str.parse::<Address<_>>().unwrap();

        // Serialize with an unchecked address.
        let foo_unchecked = Foo { address: unchecked };
        let ser = serde_json::to_string(&foo_unchecked).expect("failed to serialize");
        let rinsed: Foo<NetworkUnchecked> =
            serde_json::from_str(&ser).expect("failed to deserialize");
        assert_eq!(rinsed, foo_unchecked);

        // Serialize with a checked address.
        let foo_checked = Foo { address: unchecked.assume_checked() };
        let ser = serde_json::to_string(&foo_checked).expect("failed to serialize");
        let rinsed: Foo<NetworkUnchecked> =
            serde_json::from_str(&ser).expect("failed to deserialize");
        assert_eq!(&rinsed.address, foo_checked.address.as_unchecked());
        assert_eq!(rinsed, foo_unchecked);
    }

    #[test]
    fn pay_to_anchor_address_regtest() {
        // Verify that P2A uses the expected address for regtest.
        // This test-vector is borrowed from the bitcoin source code.
        let address_str = "bcrt1pfeesnyr2tx";

        let script = ScriptPubKeyBuf::new_p2a();
        let address_unchecked = address_str.parse().unwrap();
        let address = Address::from_script(&script, Network::Regtest).unwrap();
        assert_eq!(address.as_unchecked(), &address_unchecked);
        assert_eq!(address.to_string(), address_str);

        // Verify that the address is considered standard
        // and that the output type is P2A.
        assert!(address.is_spend_standard());
        assert_eq!(address.address_type(), Some(AddressType::P2a));
    }

    #[test]
    fn base58_invalid_payload_length_reports_decoded_size() {
        use crate::constants::PUBKEY_ADDRESS_PREFIX_MAIN;

        let mut payload = [0u8; 22]; // Invalid: should be 21
        payload[0] = PUBKEY_ADDRESS_PREFIX_MAIN;
        let encoded = base58::encode_check(&payload);

        let err = Address::<NetworkUnchecked>::from_base58_str(&encoded).unwrap_err();
        match err {
            Base58Error::InvalidBase58PayloadLength(inner) => {
                assert_eq!(inner.invalid_base58_payload_length(), 22); // Payload size
                assert_ne!(inner.invalid_base58_payload_length(), encoded.len()); // Not string size
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
