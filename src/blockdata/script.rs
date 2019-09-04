// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Script
//!
//! Scripts define Bitcoin's digital signature scheme: a signature is formed
//! from a script (the second half of which is defined by a coin to be spent,
//! and the first half provided by the spending transaction), and is valid
//! iff the script leaves `TRUE` on the stack after being evaluated.
//! Bitcoin's script is a stack-based assembly language similar in spirit to
//! Forth.
//!
//! This module provides the structures and functions needed to support scripts.
//!

use consensus::encode::{Decodable, Encodable};
use consensus::encode::{self, Decoder, Encoder};

pub use bitcoin::Script;
pub use bitcoin::blockdata::script::{Builder, Error, Instruction, Instructions};

pub use bitcoin::blockdata::script::{read_scriptint, read_scriptbool, read_uint};

// Network serialization
impl<S: Encoder> Encodable<S> for Script {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self[..].consensus_encode(s)
    }
}

impl<D: Decoder> Decodable<D> for Script {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Script, encode::Error> {
        Ok(Script::from(<Vec<u8>>::consensus_decode(d)?))
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use hex::decode as hex_decode;

    use super::*;

    use consensus::encode::{deserialize, serialize};
    use blockdata::opcodes;
    use util::key::PublicKey;

    #[test]
    fn script() {
        let mut comp = vec![];
        let mut script = Builder::new();
        assert_eq!(&script[..], &comp[..]);

        // small ints
        script = script.push_int(1);  comp.push(81u8); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(0);  comp.push(0u8);  assert_eq!(&script[..], &comp[..]);
        script = script.push_int(4);  comp.push(84u8); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(-1); comp.push(79u8); assert_eq!(&script[..], &comp[..]);
        // forced scriptint
        script = script.push_scriptint(4); comp.extend([1u8, 4].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        // big ints
        script = script.push_int(17); comp.extend([1u8, 17].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(10000); comp.extend([2u8, 16, 39].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        // notice the sign bit set here, hence the extra zero/128 at the end
        script = script.push_int(10000000); comp.extend([4u8, 128, 150, 152, 0].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(-10000000); comp.extend([4u8, 128, 150, 152, 128].iter().cloned()); assert_eq!(&script[..], &comp[..]);

        // data
        script = script.push_slice("NRA4VR".as_bytes()); comp.extend([6u8, 78, 82, 65, 52, 86, 82].iter().cloned()); assert_eq!(&script[..], &comp[..]);

        // keys
        let keystr = "21032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
        let key = PublicKey::from_str(&keystr[2..]).unwrap();
        script = script.push_key(&key); comp.extend(hex_decode(keystr).unwrap().iter().cloned()); assert_eq!(&script[..], &comp[..]);
        let keystr = "41042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
        let key = PublicKey::from_str(&keystr[2..]).unwrap();
        script = script.push_key(&key); comp.extend(hex_decode(keystr).unwrap().iter().cloned()); assert_eq!(&script[..], &comp[..]);

        // opcodes
        script = script.push_opcode(opcodes::all::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(&script[..], &comp[..]);
        script = script.push_opcode(opcodes::all::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(&script[..], &comp[..]);
    }

    #[test]
    fn script_builder() {
        // from txid 3bb5e6434c11fb93f64574af5d116736510717f2c595eb45b52c28e31622dfff which was in my mempool when I wrote the test
        let script = Builder::new().push_opcode(opcodes::all::OP_DUP)
                                   .push_opcode(opcodes::all::OP_HASH160)
                                   .push_slice(&hex_decode("16e1ae70ff0fa102905d4af297f6912bda6cce19").unwrap())
                                   .push_opcode(opcodes::all::OP_EQUALVERIFY)
                                   .push_opcode(opcodes::all::OP_CHECKSIG)
                                   .into_script();
        assert_eq!(&format!("{:x}", script), "76a91416e1ae70ff0fa102905d4af297f6912bda6cce1988ac");
    }

    #[test]
    fn script_serialize() {
        let hex_script = hex_decode("6c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52").unwrap();
        let script: Result<Script, _> = deserialize(&hex_script);
        assert!(script.is_ok());
        assert_eq!(serialize(&script.unwrap()), hex_script);
    }

    #[test]
    fn provably_unspendable_test() {
        // p2pk
        assert_eq!(hex_script!("410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac").is_provably_unspendable(), false);
        assert_eq!(hex_script!("4104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac").is_provably_unspendable(), false);
        // p2pkhash
        assert_eq!(hex_script!("76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac").is_provably_unspendable(), false);
        assert_eq!(hex_script!("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87").is_provably_unspendable(), true);
    }

    #[test]
    fn op_return_test() {
        assert_eq!(hex_script!("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87").is_op_return(), true);
        assert_eq!(hex_script!("76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac").is_op_return(), false);
        assert_eq!(hex_script!("").is_op_return(), false);
    }

    #[test]
    #[cfg(all(feature = "serde", feature = "strason"))]
    fn script_json_serialize() {
        use strason::Json;

        let original = hex_script!("827651a0698faaa9a8a7a687");
        let json = Json::from_serialize(&original).unwrap();
        assert_eq!(json.to_bytes(), b"\"827651a0698faaa9a8a7a687\"");
        assert_eq!(json.string(), Some("827651a0698faaa9a8a7a687"));
        let des = json.into_deserialize().unwrap();
        assert_eq!(original, des);
    }

    #[test]
    fn script_asm() {
        assert_eq!(hex_script!("6363636363686868686800").asm(),
                   "OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0");
        assert_eq!(hex_script!("6363636363686868686800").asm(),
                   "OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0");
        assert_eq!(hex_script!("2102715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699ac").asm(),
                   "OP_PUSHBYTES_33 02715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699 OP_CHECKSIG");
        // Elements Alpha peg-out transaction with some signatures removed for brevity. Mainly to test PUSHDATA1
        assert_eq!(hex_script!("0047304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401004cf1552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae").asm(),
                   "OP_0 OP_PUSHBYTES_71 304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401 OP_0 OP_PUSHDATA1 552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae");
    }

    #[test]
    fn script_p2sh_p2p2k_template() {
        // random outputs I picked out of the mempool
        assert!(hex_script!("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").is_p2pkh());
        assert!(!hex_script!("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").is_p2sh());
        assert!(!hex_script!("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ad").is_p2pkh());
        assert!(!hex_script!("").is_p2pkh());
        assert!(hex_script!("a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87").is_p2sh());
        assert!(!hex_script!("a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87").is_p2pkh());
        assert!(!hex_script!("a314acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87").is_p2sh());
    }

    #[test]
    fn script_p2pk() {
        assert!(hex_script!("21021aeaf2f8638a129a3156fbe7e5ef635226b0bafd495ff03afe2c843d7e3a4b51ac").is_p2pk());
        assert!(hex_script!("410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac").is_p2pk());
    }

    #[test]
    fn p2sh_p2wsh_conversion() {
        // Test vectors taken from Core tests/data/script_tests.json
        // bare p2wsh
        let redeem_script = hex_script!("410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac");
        let expected_witout = hex_script!("0020b95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64");
        assert!(redeem_script.to_v0_p2wsh().is_v0_p2wsh());
        assert_eq!(redeem_script.to_v0_p2wsh(), expected_witout);

        // p2sh
        let redeem_script = hex_script!("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
        let expected_p2shout = hex_script!("a91491b24bf9f5288532960ac687abb035127b1d28a587");
        assert!(redeem_script.to_p2sh().is_p2sh());
        assert_eq!(redeem_script.to_p2sh(), expected_p2shout);

        // p2sh-p2wsh
        let redeem_script = hex_script!("410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac");
        let expected_witout = hex_script!("0020b95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64");
        let expected_out = hex_script!("a914f386c2ba255cc56d20cfa6ea8b062f8b5994551887");
        assert!(redeem_script.to_p2sh().is_p2sh());
        assert!(redeem_script.to_p2sh().to_v0_p2wsh().is_v0_p2wsh());
        assert_eq!(redeem_script.to_v0_p2wsh(), expected_witout);
        assert_eq!(redeem_script.to_v0_p2wsh().to_p2sh(), expected_out);
    }

    #[test]
    fn test_iterator() {
        let zero = hex_script!("00");
        let zeropush = hex_script!("0100");

        let nonminimal = hex_script!("4c0169b2");      // PUSHDATA1 for no reason
        let minimal = hex_script!("0169b2");           // minimal
        let nonminimal_alt = hex_script!("026900b2");  // non-minimal number but minimal push (should be OK)

        let v_zero: Vec<Instruction> = zero.iter(true).collect();
        let v_zeropush: Vec<Instruction> = zeropush.iter(true).collect();

        let v_min: Vec<Instruction> = minimal.iter(true).collect();
        let v_nonmin: Vec<Instruction> = nonminimal.iter(true).collect();
        let v_nonmin_alt: Vec<Instruction> = nonminimal_alt.iter(true).collect();
        let slop_v_min: Vec<Instruction> = minimal.iter(false).collect();
        let slop_v_nonmin: Vec<Instruction> = nonminimal.iter(false).collect();
        let slop_v_nonmin_alt: Vec<Instruction> = nonminimal_alt.iter(false).collect();

        assert_eq!(
            v_zero,
            vec![
                Instruction::PushBytes(&[]),
            ]
        );
        assert_eq!(
            v_zeropush,
            vec![
                Instruction::PushBytes(&[0]),
            ]
        );

        assert_eq!(
            v_min,
            vec![
                Instruction::PushBytes(&[105]),
                Instruction::Op(opcodes::all::OP_NOP3),
            ]
        );

        assert_eq!(
            v_nonmin,
            vec![
                Instruction::Error(Error::NonMinimalPush),
            ]
        );

        assert_eq!(
            v_nonmin_alt,
            vec![
                Instruction::PushBytes(&[105, 0]),
                Instruction::Op(opcodes::all::OP_NOP3),
            ]
        );

        assert_eq!(v_min, slop_v_min);
        assert_eq!(v_min, slop_v_nonmin);
        assert_eq!(v_nonmin_alt, slop_v_nonmin_alt);
     }

    #[test]
    fn script_ord() {
        let script_1 = Builder::new().push_slice(&[1,2,3,4]).into_script();
        let script_2 = Builder::new().push_int(10).into_script();
        let script_3 = Builder::new().push_int(15).into_script();
        let script_4 = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script();

        assert!(script_1 < script_2);
        assert!(script_2 < script_3);
        assert!(script_3 < script_4);

        assert!(script_1 <= script_1);
        assert!(script_1 >= script_1);

        assert!(script_4 > script_3);
        assert!(script_3 > script_2);
        assert!(script_2 > script_1);
    }

    #[test]
    #[cfg(feature="bitcoinconsensus")]
    fn test_bitcoinconsensus () {
           // a random segwit transaction from the blockchain using native segwit
               let spent = Builder::from(hex_decode("0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d").unwrap()).into_script();
           let spending = hex_decode("010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000").unwrap();
           spent.verify(0, 18393430, spending.as_slice()).unwrap();
    }
}

