// Rust Dash Library
// Written for Dash in 2022 by
//     The Dash Core Developers
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

//! Dash Provider Update Registrar Special Transaction.
//!
//! The provider update registrar special transaction is used to update the owner controlled options
//! for a masternode.
//!
//! It is defined in DIP3 [dip-0003](https://github.com/dashpay/dips/blob/master/dip-0003.md) as follows:
//!
//! To registrar update a masternode, the masternode owner must submit another special transaction
//! (DIP2) to the network. This special transaction is called a Provider Update Registrar
//! Transaction and is abbreviated as ProUpRegTx. It can only be done by the owner.
//!
//! A ProUpRegTx is only valid for masternodes in the registered masternodes subset. When
//! processed, it updates the metadata of the masternode entry. It does not revive masternodes
//! previously marked as PoSe-banned.
//!
//! The special transaction type used for ProUpRegTx Transactions is 3.

use crate::prelude::*;
use crate::{io, VarInt};
use hashes::Hash;
use crate::{ScriptBuf};
use crate::consensus::{Decodable, Encodable, encode};
use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::bls_sig_utils::{BLSPublicKey};
use crate::hash_types::{PubkeyHash, SpecialTransactionPayloadHash, Txid, InputsHash};

/// A Provider Update Registrar Payload used in a Provider Update Registrar Special Transaction.
/// This is used to update the base aspects a Masternode on the network.
/// It must be signed by the owner's key that was set at registration.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct ProviderUpdateRegistrarPayload {
    version: u16,
    pro_tx_hash: Txid,
    provider_mode: u16,
    operator_public_key: BLSPublicKey,
    voting_key_hash: PubkeyHash,
    script_payout: ScriptBuf,
    inputs_hash: InputsHash,
    payload_sig: Vec<u8>, // TODO: Need to figure out, is this signature BLS Signature (length 96)
}

impl ProviderUpdateRegistrarPayload {
    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        let mut size = 2 + 32 + 2 + 48 + 20 + 32; // 136
        size += VarInt(self.script_payout.len() as u64).len() + self.script_payout.len();
        size += VarInt(self.payload_sig.len() as u64).len() + self.payload_sig.len();
        size
    }
}

impl SpecialTransactionBasePayloadEncodable for ProviderUpdateRegistrarPayload {
    fn base_payload_data_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.pro_tx_hash.consensus_encode(&mut s)?;
        len += self.provider_mode.consensus_encode(&mut s)?;
        len += self.operator_public_key.consensus_encode(&mut s)?;
        len += self.voting_key_hash.consensus_encode(&mut s)?;
        len += self.script_payout.consensus_encode(&mut s)?;
        len += self.inputs_hash.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderUpdateRegistrarPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, mut w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut w)?;
        len += self.payload_sig.consensus_encode(&mut w)?;
        Ok(len)
    }
}

impl Decodable for ProviderUpdateRegistrarPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;
        let pro_tx_hash = Txid::consensus_decode(r)?;
        let provider_mode = u16::consensus_decode(r)?;
        let operator_public_key = BLSPublicKey::consensus_decode(r)?;
        let voting_key_hash = PubkeyHash::consensus_decode(r)?;
        let script_payout = ScriptBuf::consensus_decode(r)?;
        let inputs_hash = InputsHash::consensus_decode(r)?;
        let payload_sig = Vec::<u8>::consensus_decode(r)?;

        Ok(ProviderUpdateRegistrarPayload {
            version,
            pro_tx_hash,
            provider_mode,
            operator_public_key,
            voting_key_hash,
            script_payout,
            inputs_hash,
            payload_sig
        })
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use hashes::Hash;
    use crate::consensus::{deserialize, Encodable};
    use crate::{Network, ScriptBuf, Transaction, Txid};
    use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
    use crate::bls_sig_utils::BLSPublicKey;
    use crate::hash_types::InputsHash;
    use crate::internal_macros::hex;
    use crate::PubkeyHash;
    use crate::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
    use crate::transaction::special_transaction::TransactionPayload::ProviderUpdateRegistrarPayloadType;

    #[test]
    fn test_provider_update_registrar_transaction() {
        // This is a test for testnet
        let _network = Network::Testnet;

        let expected_transaction_bytes = hex!("0300030001c7de76dac8dd96f9b49b12a06fe39c8caf0cad12d23ad6026094d9b11b2b260d000000006b483045022100b31895e8cea95a965c82d842eadd6eef3c7b29e677c62a5c8e2b5dce05b4ddfc02206c7b5a9ea8b71983c3b21f4ff75ac1aa44090d28af8b2d9b93e794e6eb5835e20121032ea8be689184f329dce575776bc956cd52230f4c04755d5753d9491ea5bf8f2affffffff01c94670d0060000001976a914345f07bc7ebaf9f82f273be249b6066d2d5c236688ac00000000e4010049aa692330179f95c1342715102e37777df91cc0f3a4ae7e8f9e214ee97dbb3d0000139b654f0b1c031e1cf2b934c2d895178875cfe7c6a4f6758f02bc66eea7fc292d0040701acbe31f5e14a911cb061a2f6cc4a7bb877a80c11ae06b988d98305773f93b981976a91456bcf3cac49235537d6ce0fb3214d8850a6db77788ac2d7f857a2f15eb9340a0cfbce3ff8cf09b40e582d05b1f98c7468caa0f942bcf411ff69c9cb072660cc10048332c14c08621e7461f1f4f54b448baedc0e3434d9a7c3a1780885aaef4dd44c597b49b97595e02ad54728f572967d3ce0c2c0ceac174");

        let expected_transaction: Transaction = deserialize(expected_transaction_bytes.as_slice()).expect("expected a transaction");

        let expected_provider_update_registrar_payload = expected_transaction.special_transaction_payload.clone().unwrap().to_update_registrar_payload().expect("expected to get an update registrar payload");

        let tx_id = Txid::from_str("bd98378ca37d3ae6f4850b82e77be675feb3c9bc6e33cb0c23de1b38a08034c7").expect("expected to decode tx id");

        let provider_update_registrar_payload_version = 1;
        assert_eq!(expected_provider_update_registrar_payload.version, provider_update_registrar_payload_version);
        let pro_tx_hash = Txid::from_str("3dbb7de94e219e8f7eaea4f3c01cf97d77372e10152734c1959f17302369aa49").expect("expected to decode tx id");
        assert_eq!(expected_provider_update_registrar_payload.pro_tx_hash, pro_tx_hash);

        let provider_mode = 0;
        assert_eq!(provider_mode, expected_provider_update_registrar_payload.provider_mode);

        let operator_key_hex = "139b654f0b1c031e1cf2b934c2d895178875cfe7c6a4f6758f02bc66eea7fc292d0040701acbe31f5e14a911cb061a2f";
        assert_eq!(operator_key_hex, expected_provider_update_registrar_payload.operator_public_key.to_hex());

        let voting_key_hash_hex = "6cc4a7bb877a80c11ae06b988d98305773f93b98";
        assert_eq!(voting_key_hash_hex, expected_provider_update_registrar_payload.voting_key_hash.to_hex());

        let inputs_hash_hex = "cf2b940faa8c46c7981f5bd082e5409bf08cffe3bccfa04093eb152f7a857f2d";
        assert_eq!(expected_provider_update_registrar_payload.inputs_hash.to_hex(), inputs_hash_hex, "inputs hash calculation has issues");

        assert_eq!(expected_provider_update_registrar_payload.base_payload_hash().to_hex(), "85deffc85d2304f0305356e1dc8d02eecdb3220576abb370bc67be446c854296", "Payload hash calculation has issues");

        // We should verify the script payouts match
        let pubkey_hash = PubkeyHash::from_hex("56bcf3cac49235537d6ce0fb3214d8850a6db777").expect("expected to get pubkey hash");
        let script_payout = ScriptBuf::new_p2pkh(&pubkey_hash);
        assert_eq!(expected_provider_update_registrar_payload.script_payout, script_payout);

        assert_eq!(expected_transaction.txid(), tx_id);

        //todo: once we have a BLS signatures library in rust we should implement signing
        let payload_sig = expected_transaction.special_transaction_payload.clone().unwrap().to_update_registrar_payload().unwrap().payload_sig;

        let transaction = Transaction {
            version: 3,
            lock_time: 0,
            input: expected_transaction.input.clone(), // todo:implement this
            output: expected_transaction.output.clone(), // todo:implement this
            special_transaction_payload: Some(ProviderUpdateRegistrarPayloadType(ProviderUpdateRegistrarPayload {
                version: provider_update_registrar_payload_version,
                pro_tx_hash,
                provider_mode,
                operator_public_key: BLSPublicKey::from_hex(operator_key_hex).unwrap(),
                voting_key_hash: PubkeyHash::from_hex(voting_key_hash_hex).unwrap(),
                script_payout,
                inputs_hash: InputsHash::from_hex(inputs_hash_hex).unwrap(),
                payload_sig
            }))
        };

        assert_eq!(transaction.hash_inputs().to_hex(), inputs_hash_hex);

        assert_eq!(transaction, expected_transaction);

        assert_eq!(transaction.txid(), tx_id);
    }

    #[test]
    fn size() {
        let want = 244;
        let payload = ProviderUpdateRegistrarPayload{
            version: 0,
            pro_tx_hash: Txid::all_zeros(),
            provider_mode:0,
            operator_public_key: BLSPublicKey::from([0; 48]),
            voting_key_hash: PubkeyHash::all_zeros(),
            script_payout: ScriptBuf::from_hex("00000000000000000000").unwrap(), // 10 bytes
            inputs_hash: InputsHash::all_zeros(),
            payload_sig: vec![0; 96],
        };
        assert_eq!(payload.size(), want);
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(actual, want);
    }
}
