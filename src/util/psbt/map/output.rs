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
use consensus::encode;
use util::bip32::KeySource;
use util::ecdsa::PublicKey;
use util::psbt;
use util::psbt::map::Map;
use util::psbt::raw;
use util::psbt::Error;

/// Type: Redeem Script PSBT_OUT_REDEEM_SCRIPT = 0x00
const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
/// Type: Witness Script PSBT_OUT_WITNESS_SCRIPT = 0x01
const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
/// Type: BIP 32 Derivation Path PSBT_OUT_BIP32_DERIVATION = 0x02
const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
/// Type: Proprietary Use Type PSBT_IN_PROPRIETARY = 0xFC
const PSBT_OUT_PROPRIETARY: u8 = 0xFC;

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    /// The redeem script for this output.
    pub redeem_script: Option<Script>,
    /// The witness script for this output.
    pub witness_script: Option<Script>,
    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<PublicKey, KeySource>,
    /// Proprietary key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Map for Output {
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSBT_OUT_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSBT_OUT_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSBT_OUT_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_OUT_PROPRIETARY => match self.proprietary.entry(raw::ProprietaryKey::from_key(raw_key.clone())?) {
                btree_map::Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key.clone()).into()),
            }
            _ => match self.unknown.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
            }
        }

        Ok(())
    }

    fn get_pairs(&self) -> Result<Vec<raw::Pair>, io::Error> {
        let mut rv: Vec<raw::Pair> = Default::default();

        impl_psbt_get_pair! {
            rv.push(self.redeem_script as <PSBT_OUT_REDEEM_SCRIPT, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script as <PSBT_OUT_WITNESS_SCRIPT, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.bip32_derivation as <PSBT_OUT_BIP32_DERIVATION, PublicKey>|<KeySource>)
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
        self.bip32_derivation.extend(other.bip32_derivation);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);

        Ok(())
    }
}

impl_psbtmap_consensus_enc_dec_oding!(Output);
