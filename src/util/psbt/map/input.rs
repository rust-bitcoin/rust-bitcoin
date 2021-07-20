// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
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

use prelude::*;

use io;

use blockdata::script::Script;
use blockdata::transaction::{SigHashType, Transaction, TxOut};
use consensus::encode;
use util::bip32::KeySource;
use hashes::{self, hash160, ripemd160, sha256, sha256d};
use util::ecdsa::PublicKey;
use util::psbt;
use util::psbt::map::Map;
use util::psbt::raw;
use util::psbt::serialize::Deserialize;
use util::psbt::{Error, error};

/// Type: Non-Witness UTXO PSBT_IN_NON_WITNESS_UTXO = 0x00
const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
/// Type: Witness UTXO PSBT_IN_WITNESS_UTXO = 0x01
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
/// Type: Partial Signature PSBT_IN_PARTIAL_SIG = 0x02
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
/// Type: Sighash Type PSBT_IN_SIGHASH_TYPE = 0x03
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
/// Type: Redeem Script PSBT_IN_REDEEM_SCRIPT = 0x04
const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
/// Type: Witness Script PSBT_IN_WITNESS_SCRIPT = 0x05
const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
/// Type: BIP 32 Derivation Path PSBT_IN_BIP32_DERIVATION = 0x06
const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
/// Type: Finalized scriptSig PSBT_IN_FINAL_SCRIPTSIG = 0x07
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
/// Type: Finalized scriptWitness PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
/// Type: RIPEMD160 preimage PSBT_IN_RIPEMD160 = 0x0a
const PSBT_IN_RIPEMD160: u8 = 0x0a;
/// Type: SHA256 preimage PSBT_IN_SHA256 = 0x0b
const PSBT_IN_SHA256: u8 = 0x0b;
/// Type: HASH160 preimage PSBT_IN_HASH160 = 0x0c
const PSBT_IN_HASH160: u8 = 0x0c;
/// Type: HASH256 preimage PSBT_IN_HASH256 = 0x0d
const PSBT_IN_HASH256: u8 = 0x0d;
/// Type: Proprietary Use Type PSBT_IN_PROPRIETARY = 0xFC
const PSBT_IN_PROPRIETARY: u8 = 0xFC;

/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Input {
    /// The non-witness transaction this input spends from. Should only be
    /// [std::option::Option::Some] for inputs which spend non-segwit outputs or
    /// if it is unknown whether an input spends a segwit output.
    pub non_witness_utxo: Option<Transaction>,
    /// The transaction output this input spends from. Should only be
    /// [std::option::Option::Some] for inputs which spend segwit outputs,
    /// including P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,
    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_byte_values"))]
    pub partial_sigs: BTreeMap<PublicKey, Vec<u8>>,
    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<SigHashType>,
    /// The redeem script for this input.
    pub redeem_script: Option<Script>,
    /// The witness script for this input.
    pub witness_script: Option<Script>,
    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<PublicKey, KeySource>,
    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<Script>,
    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    /// TODO: Proof of reserves commitment
    /// RIPEMD160 hash to preimage map
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_byte_values"))]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,
    /// SHA256 hash to preimage map
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_byte_values"))]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,
    /// HSAH160 hash to preimage map
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_byte_values"))]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,
    /// HAS256 hash to preimage map
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_byte_values"))]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,
    /// Proprietary key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Map for Input {
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSBT_IN_NON_WITNESS_UTXO => {
                impl_psbt_insert_pair! {
                    self.non_witness_utxo <= <raw_key: _>|<raw_value: Transaction>
                }
            }
            PSBT_IN_WITNESS_UTXO => {
                impl_psbt_insert_pair! {
                    self.witness_utxo <= <raw_key: _>|<raw_value: TxOut>
                }
            }
            PSBT_IN_PARTIAL_SIG => {
                impl_psbt_insert_pair! {
                    self.partial_sigs <= <raw_key: PublicKey>|<raw_value: Vec<u8>>
                }
            }
            PSBT_IN_SIGHASH_TYPE => {
                impl_psbt_insert_pair! {
                    self.sighash_type <= <raw_key: _>|<raw_value: SigHashType>
                }
            }
            PSBT_IN_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSBT_IN_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSBT_IN_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_IN_FINAL_SCRIPTSIG => {
                impl_psbt_insert_pair! {
                    self.final_script_sig <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSBT_IN_FINAL_SCRIPTWITNESS => {
                impl_psbt_insert_pair! {
                    self.final_script_witness <= <raw_key: _>|<raw_value: Vec<Vec<u8>>>
                }
            }
            PSBT_IN_RIPEMD160 => {
                psbt_insert_hash_pair(&mut self.ripemd160_preimages, raw_key, raw_value, error::PsbtHash::Ripemd)?;
            }
            PSBT_IN_SHA256 => {
                psbt_insert_hash_pair(&mut self.sha256_preimages, raw_key, raw_value, error::PsbtHash::Sha256)?;
            }
            PSBT_IN_HASH160 => {
                psbt_insert_hash_pair(&mut self.hash160_preimages, raw_key, raw_value, error::PsbtHash::Hash160)?;
            }
            PSBT_IN_HASH256 => {
                psbt_insert_hash_pair(&mut self.hash256_preimages, raw_key, raw_value, error::PsbtHash::Hash256)?;
            }
            PSBT_IN_PROPRIETARY => match self.proprietary.entry(raw::ProprietaryKey::from_key(raw_key.clone())?) {
                btree_map::Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key).into()),
            }
            _ => match self.unknown.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                btree_map::Entry::Occupied(k) => {
                    return Err(Error::DuplicateKey(k.key().clone()).into())
                }
            },
        }

        Ok(())
    }

    fn get_pairs(&self) -> Result<Vec<raw::Pair>, io::Error> {
        let mut rv: Vec<raw::Pair> = Default::default();

        impl_psbt_get_pair! {
            rv.push(self.non_witness_utxo as <PSBT_IN_NON_WITNESS_UTXO, _>|<Transaction>)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_utxo as <PSBT_IN_WITNESS_UTXO, _>|<TxOut>)
        }

        impl_psbt_get_pair! {
            rv.push(self.partial_sigs as <PSBT_IN_PARTIAL_SIG, PublicKey>|<Vec<u8>>)
        }

        impl_psbt_get_pair! {
            rv.push(self.sighash_type as <PSBT_IN_SIGHASH_TYPE, _>|<SigHashType>)
        }

        impl_psbt_get_pair! {
            rv.push(self.redeem_script as <PSBT_IN_REDEEM_SCRIPT, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script as <PSBT_IN_WITNESS_SCRIPT, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.bip32_derivation as <PSBT_IN_BIP32_DERIVATION, PublicKey>|<KeySource>)
        }

        impl_psbt_get_pair! {
            rv.push(self.final_script_sig as <PSBT_IN_FINAL_SCRIPTSIG, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.final_script_witness as <PSBT_IN_FINAL_SCRIPTWITNESS, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.ripemd160_preimages as <PSBT_IN_RIPEMD160, ripemd160::Hash>|<Vec<u8>>)
        }

        impl_psbt_get_pair! {
            rv.push(self.sha256_preimages as <PSBT_IN_SHA256, sha256::Hash>|<Vec<u8>>)
        }

        impl_psbt_get_pair! {
            rv.push(self.hash160_preimages as <PSBT_IN_HASH160, hash160::Hash>|<Vec<u8>>)
        }

        impl_psbt_get_pair! {
            rv.push(self.hash256_preimages as <PSBT_IN_HASH256, sha256d::Hash>|<Vec<u8>>)
        }

        for (key, value) in self.proprietary.iter() {
            rv.push(raw::Pair {
                key: key.to_key(),
                value: value.clone(),
            });
        }

        for (key, value) in self.unknown.iter() {
            rv.push(raw::Pair {
                key: key.clone(),
                value: value.clone(),
            });
        }

        Ok(rv)
    }

    fn merge(&mut self, other: Self) -> Result<(), psbt::Error> {
        merge!(non_witness_utxo, self, other);

        if let (&None, Some(witness_utxo)) = (&self.witness_utxo, other.witness_utxo) {
            self.witness_utxo = Some(witness_utxo);
            self.non_witness_utxo = None; // Clear out any non-witness UTXO when we set a witness one
        }

        self.partial_sigs.extend(other.partial_sigs);
        self.bip32_derivation.extend(other.bip32_derivation);
        self.ripemd160_preimages.extend(other.ripemd160_preimages);
        self.sha256_preimages.extend(other.sha256_preimages);
        self.hash160_preimages.extend(other.hash160_preimages);
        self.hash256_preimages.extend(other.hash256_preimages);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);
        merge!(final_script_sig, self, other);
        merge!(final_script_witness, self, other);

        Ok(())
    }
}

impl_psbtmap_consensus_enc_dec_oding!(Input);

fn psbt_insert_hash_pair<H>(
    map: &mut BTreeMap<H, Vec<u8>>,
    raw_key: raw::Key,
    raw_value: Vec<u8>,
    hash_type: error::PsbtHash,
) -> Result<(), encode::Error>
where
    H: hashes::Hash + Deserialize,
{
    if raw_key.key.is_empty() {
        return Err(psbt::Error::InvalidKey(raw_key).into());
    }
    let key_val: H = Deserialize::deserialize(&raw_key.key)?;
    match map.entry(key_val) {
        btree_map::Entry::Vacant(empty_key) => {
            let val: Vec<u8> = Deserialize::deserialize(&raw_value)?;
            if <H as hashes::Hash>::hash(&val) != key_val {
                return Err(psbt::Error::InvalidPreimageHashPair {
                    preimage: val.into_boxed_slice(),
                    hash: Box::from(key_val.borrow()),
                    hash_type: hash_type,
                }
                .into());
            }
            empty_key.insert(val);
            Ok(())
        }
        btree_map::Entry::Occupied(_) => return Err(psbt::Error::DuplicateKey(raw_key).into()),
    }
}
