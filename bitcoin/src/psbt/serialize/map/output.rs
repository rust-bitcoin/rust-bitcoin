// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use secp256k1::XOnlyPublicKey;

use crate::bip32::KeySource;
use crate::prelude::{btree_map, BTreeMap, Vec};
use crate::psbt::consts::{
    PSBT_OUT_AMOUNT, PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_PROPRIETARY, PSBT_OUT_REDEEM_SCRIPT,
    PSBT_OUT_SCRIPT, PSBT_OUT_TAP_BIP32_DERIVATION, PSBT_OUT_TAP_INTERNAL_KEY, PSBT_OUT_TAP_TREE,
    PSBT_OUT_WITNESS_SCRIPT,
};
use crate::psbt::serialize::map::Map;
use crate::psbt::serialize::{raw, Error};
use crate::script::ScriptBuf;
use crate::taproot::{TapLeafHash, TapTree};
use crate::Amount;

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    /// The redeem script for this output.
    ///
    /// PSBT_OUT_REDEEM_SCRIPT: Optional for v0, optional for v2.
    pub redeem_script: Option<ScriptBuf>,

    /// The witness script for this output.
    ///
    /// PSBT_OUT_WITNESS_SCRIPT: Optional for v0, optional for v2.
    pub witness_script: Option<ScriptBuf>,

    /// A map from public keys needed to spend this output to their corresponding master key
    /// fingerprints and derivation paths.
    ///
    /// PSBT_OUT_BIP32_DERIVATION: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The output's amount (serialized as satoshis).
    ///
    /// PSBT_OUT_AMOUNT: Excluded for v0, required for v2.
    pub amount: Option<Amount>,

    /// The script for this output, also known as the scriptPubKey.
    ///
    /// PSBT_OUT_SCRIPT: Excluded for v0, required for v2.
    pub script_pubkey: Option<ScriptBuf>,

    /// The X-only pubkey used as the internal key in this output.
    ///
    /// PSBT_OUT_TAP_INTERNAL_KEY: Optional for v0, optional for v2.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot output tree.
    ///
    /// PSBT_OUT_TAP_TREE: Optional for v0, optional for v2.
    pub tap_tree: Option<TapTree>,

    /// Map of Taproot x only keys to origin info and leaf hashes contained in it.
    ///
    /// PSBT_OUT_TAP_BIP32_DERIVATION: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// Proprietary key-value pairs for this output.
    ///
    /// PSBT_OUT_PROPRIETARY: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output {
    /// Checks if `Output` has fields set as required by the respective BIP.
    pub(crate) fn is_valid(&self) -> bool {
        self.assert_valid_v0().is_ok() | self.assert_valid_v2().is_ok()
    }

    /// Checks if `Output` has minimum fields required by `BIP-174`.
    pub(crate) fn assert_valid_v0(&self) -> Result<(), V0InvalidError> {
        if self.amount.is_some() {
            return Err(V0InvalidError::Amount);
        }
        if self.script_pubkey.is_some() {
            return Err(V0InvalidError::ScriptPubkey);
        }
        Ok(())
    }

    /// Checks if `Output` has minimum fields required by `BIP-370`.
    pub(crate) fn assert_valid_v2(&self) -> Result<(), V2InvalidError> {
        if self.amount.is_none() {
            return Err(V2InvalidError::Amount);
        }
        if self.script_pubkey.is_none() {
            return Err(V2InvalidError::ScriptPubkey);
        }
        Ok(())
    }

    pub(super) fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), Error> {
        let raw::Pair { key: raw_key, value: raw_value } = pair;

        match raw_key.type_value {
            PSBT_OUT_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_OUT_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_OUT_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_OUT_AMOUNT => {
                impl_psbt_insert_pair! {
                    self.amount <= <raw_key: _>|<raw_value: Amount>
                }
            }
            PSBT_OUT_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.script_pubkey <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_OUT_TAP_INTERNAL_KEY => {
                impl_psbt_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|<raw_value: XOnlyPublicKey>
                }
            }
            PSBT_OUT_TAP_TREE => {
                impl_psbt_insert_pair! {
                    self.tap_tree <= <raw_key: _>|<raw_value: TapTree>
                }
            }
            PSBT_OUT_TAP_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.tap_key_origins <= <raw_key: XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
                }
            }
            PSBT_OUT_PROPRIETARY => {
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
                match self.proprietary.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    }
                    btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key)),
                }
            }
            _ => match self.unknown.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone())),
            },
        }

        Ok(())
    }

    /// Combines this [`Output`] with `other` `Output` (as described by BIP 174).
    pub fn combine(&mut self, other: Self) {
        self.bip32_derivation.extend(other.bip32_derivation);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);
        self.tap_key_origins.extend(other.tap_key_origins);

        combine!(redeem_script, self, other);
        combine!(witness_script, self, other);
        combine!(tap_internal_key, self, other);
        combine!(tap_tree, self, other);
    }
}

impl Map for Output {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_OUT_REDEEM_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_OUT_WITNESS_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivation, PSBT_OUT_BIP32_DERIVATION)
        }

        impl_psbt_get_pair! {
            rv.push(self.amount, PSBT_OUT_AMOUNT)
        }

        impl_psbt_get_pair! {
            rv.push(self.script_pubkey, PSBT_OUT_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_OUT_TAP_INTERNAL_KEY)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_tree, PSBT_OUT_TAP_TREE)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_OUT_TAP_BIP32_DERIVATION)
        }

        for (key, value) in self.proprietary.iter() {
            rv.push(raw::Pair { key: key.to_key(), value: value.clone() });
        }

        for (key, value) in self.unknown.iter() {
            rv.push(raw::Pair { key: key.clone(), value: value.clone() });
        }

        rv
    }
}

impl_psbtmap_ser_de_serialize!(Output);

/// Output is not valid for v0 (BIP-370).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V0InvalidError {
    /// PSBT_OUT_AMOUNT: Excluded for v0, required for v2.
    Amount,
    /// PSBT_OUT_SCRIPT: Excluded for v0, required for v2.
    ScriptPubkey,
}

internals::impl_from_infallible!(V0InvalidError);

impl fmt::Display for V0InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use V0InvalidError as E;

        match *self {
            E::Amount => write!(f, "PSBT_OUT_AMOUNT must be excluded for v0"),
            E::ScriptPubkey => write!(f, "PSBT_OUT_SCRIPT must be excluded for v0"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V0InvalidError {}

/// Output is not valid for v2 (BIP-370).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V2InvalidError {
    /// PSBT_OUT_AMOUNT: Excluded for v0, required for v2.
    Amount,
    /// PSBT_OUT_SCRIPT: Excluded for v0, required for v2.
    ScriptPubkey,
}

internals::impl_from_infallible!(V2InvalidError);

impl fmt::Display for V2InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use V2InvalidError::*;

        match *self {
            Amount => write!(f, "PSBT_OUT_AMOUNT is required for v2"),
            ScriptPubkey => write!(f, "PSBT_OUT_SCRIPT is required for v2"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V2InvalidError {}

#[cfg(test)]
mod tests {
    use hex::test_hex_unwrap as hex;
    use secp256k1::Secp256k1;

    use super::*;
    use crate::bip32::{ChildNumber, KeySource, Xpriv, Xpub};
    use crate::blockdata::script::ScriptBufExt;
    use crate::network::NetworkKind;
    use crate::psbt::serialize::{Deserialize, Serialize};

    #[test]
    fn serialize_then_deserialize_output() {
        let secp = &Secp256k1::new();
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

        let mut hd_keypaths: BTreeMap<secp256k1::PublicKey, KeySource> = Default::default();

        let mut sk: Xpriv = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();

        let fprint = sk.fingerprint(secp);

        let dpath: Vec<ChildNumber> = vec![
            ChildNumber::ZERO_NORMAL,
            ChildNumber::ONE_NORMAL,
            ChildNumber::from_normal_idx(2).unwrap(),
            ChildNumber::from_normal_idx(4).unwrap(),
            ChildNumber::from_normal_idx(42).unwrap(),
            ChildNumber::from_hardened_idx(69).unwrap(),
            ChildNumber::from_normal_idx(420).unwrap(),
            ChildNumber::from_normal_idx(31337).unwrap(),
        ];

        sk = sk.derive_xpriv(secp, &dpath);

        let pk = Xpub::from_xpriv(secp, &sk);

        hd_keypaths.insert(pk.public_key, (fprint, dpath.into()));

        let expected: Output = Output {
            redeem_script: Some(
                ScriptBuf::from_hex("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
            ),
            witness_script: Some(
                ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
            ),
            bip32_derivation: hd_keypaths,
            ..Default::default()
        };

        let actual = Output::deserialize(&expected.serialize()).unwrap();

        assert_eq!(expected, actual);
    }
}
