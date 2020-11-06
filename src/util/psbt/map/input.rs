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

use std::collections::btree_map::{Entry, BTreeMap};

use blockdata::script::Script;
use blockdata::transaction::{SigHashType, Transaction, TxOut};
use consensus::encode;
use util::bip32::KeySource;
use hashes::{self, hash160, ripemd160, sha256, sha256d};
use util::key::PublicKey;
use util::psbt;
use util::psbt::map::Map;
use util::psbt::raw;
use util::psbt::serialize::Deserialize;
use util::psbt::{Error, error};
/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq)]
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
    pub bip32_derivation: BTreeMap<PublicKey, KeySource>,
    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<Script>,
    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    /// TODO: Proof of reserves commitment
    /// RIPEMD hash to preimage map
    pub ripemd_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,
    /// SHA256 hash to preimage map
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,
    /// HSAH160 hash to preimage map
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,
    /// HAS256 hash to preimage map
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,
    /// Unknown key-value pairs for this input.
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}
serde_struct_impl!(
    Input, non_witness_utxo, witness_utxo, partial_sigs,
    sighash_type, redeem_script, witness_script, bip32_derivation,
    final_script_sig, final_script_witness,
    ripemd_preimages, sha256_preimages, hash160_preimages, hash256_preimages,
    unknown
);

impl Map for Input {
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            0u8 => {
                impl_psbt_insert_pair! {
                    self.non_witness_utxo <= <raw_key: _>|<raw_value: Transaction>
                }
            }
            1u8 => {
                impl_psbt_insert_pair! {
                    self.witness_utxo <= <raw_key: _>|<raw_value: TxOut>
                }
            }
            3u8 => {
                impl_psbt_insert_pair! {
                    self.sighash_type <= <raw_key: _>|<raw_value: SigHashType>
                }
            }
            4u8 => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            5u8 => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            7u8 => {
                impl_psbt_insert_pair! {
                    self.final_script_sig <= <raw_key: _>|<raw_value: Script>
                }
            }
            8u8 => {
                impl_psbt_insert_pair! {
                    self.final_script_witness <= <raw_key: _>|<raw_value: Vec<Vec<u8>>>
                }
            }
            2u8 => {
                impl_psbt_insert_pair! {
                    self.partial_sigs <= <raw_key: PublicKey>|<raw_value: Vec<u8>>
                }
            }
            6u8 => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: PublicKey>|<raw_value: KeySource>
                }
            }
            10u8 => {
                psbt_insert_hash_pair(&mut self.ripemd_preimages, raw_key, raw_value, error::PsbtHash::Ripemd)?;
            }
            11u8 => {
                psbt_insert_hash_pair(&mut self.sha256_preimages, raw_key, raw_value, error::PsbtHash::Sha256)?;
            }
            12u8 => {
                psbt_insert_hash_pair(&mut self.hash160_preimages, raw_key, raw_value, error::PsbtHash::Hash160)?;
            }
            13u8 => {
                psbt_insert_hash_pair(&mut self.hash256_preimages, raw_key, raw_value, error::PsbtHash::Hash256)?;
            }
            _ => match self.unknown.entry(raw_key) {
                ::std::collections::btree_map::Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                ::std::collections::btree_map::Entry::Occupied(k) => {
                    return Err(Error::DuplicateKey(k.key().clone()).into())
                }
            },
        }

        Ok(())
    }

    fn get_pairs(&self) -> Result<Vec<raw::Pair>, encode::Error> {
        let mut rv: Vec<raw::Pair> = Default::default();

        impl_psbt_get_pair! {
            rv.push(self.non_witness_utxo as <0u8, _>|<Transaction>)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_utxo as <1u8, _>|<TxOut>)
        }

        impl_psbt_get_pair! {
            rv.push(self.partial_sigs as <2u8, PublicKey>|<Vec<u8>>)
        }

        impl_psbt_get_pair! {
            rv.push(self.sighash_type as <3u8, _>|<SigHashType>)
        }

        impl_psbt_get_pair! {
            rv.push(self.redeem_script as <4u8, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script as <5u8, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.bip32_derivation as <6u8, PublicKey>|<KeySource>)
        }

        impl_psbt_get_pair! {
            rv.push(self.final_script_sig as <7u8, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.final_script_witness as <8u8, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.ripemd_preimages as <10u8, ripemd160::Hash>|<Vec<u8>>)
        }

        impl_psbt_get_pair! {
            rv.push(self.sha256_preimages as <11u8, sha256::Hash>|<Vec<u8>>)
        }

        impl_psbt_get_pair! {
            rv.push(self.hash160_preimages as <12u8, hash160::Hash>|<Vec<u8>>)
        }

        impl_psbt_get_pair! {
            rv.push(self.hash256_preimages as <13u8, sha256d::Hash>|<Vec<u8>>)
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
        self.ripemd_preimages.extend(other.ripemd_preimages);
        self.sha256_preimages.extend(other.sha256_preimages);
        self.hash160_preimages.extend(other.hash160_preimages);
        self.hash256_preimages.extend(other.hash256_preimages);
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
        Entry::Vacant(empty_key) => {
            let val: Vec<u8> = Deserialize::deserialize(&raw_value)?;
            if <H as hashes::Hash>::hash(&val) != key_val {
                return Err(psbt::Error::InvalidPreimageHashPair {
                    preimage: val,
                    hash: Vec::from(key_val.borrow()),
                    hash_type: hash_type,
                }
                .into());
            }
            empty_key.insert(val);
            Ok(())
        }
        Entry::Occupied(_) => return Err(psbt::Error::DuplicateKey(raw_key).into()),
    }
}
