// SPDX-License-Identifier: CC0-1.0

//! PSBT serialization.
//!
//! Defines traits used for (de)serializing PSBT values into/from raw
//! bytes from/as PSBT key-value pairs.
//!

use crate::prelude::*;

use crate::io;

use crate::blockdata::script::Script;
use crate::blockdata::witness::Witness;
use crate::blockdata::transaction::{Transaction, TxOut};
use crate::consensus::encode::{self, serialize, Decodable, Encodable, deserialize_partial};
use secp256k1::{self, XOnlyPublicKey};
use crate::util::bip32::{ChildNumber, Fingerprint, KeySource};
use crate::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use crate::util::ecdsa::{EcdsaSig, EcdsaSigError};
use crate::util::psbt;
use crate::util::taproot::{TapBranchHash, TapLeafHash, ControlBlock, LeafVersion};
use crate::schnorr;
use crate::util::key::PublicKey;

use super::map::{TapTree, PsbtSighashType};

use crate::util::taproot::TaprootBuilder;
/// A trait for serializing a value as raw data for insertion into PSBT
/// key-value pairs.
pub trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSBT key-value pairs.
pub trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error>;
}

impl_psbt_de_serialize!(Transaction);
impl_psbt_de_serialize!(TxOut);
impl_psbt_de_serialize!(Witness);
impl_psbt_hash_de_serialize!(ripemd160::Hash);
impl_psbt_hash_de_serialize!(sha256::Hash);
impl_psbt_hash_de_serialize!(TapLeafHash);
impl_psbt_hash_de_serialize!(TapBranchHash);
impl_psbt_hash_de_serialize!(hash160::Hash);
impl_psbt_hash_de_serialize!(sha256d::Hash);

// taproot
impl_psbt_de_serialize!(Vec<TapLeafHash>);

impl Serialize for Script {
    fn serialize(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl Deserialize for Script {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(Self::from(bytes.to_vec()))
    }
}

impl Serialize for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }
}

impl Deserialize for PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        PublicKey::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("invalid public key"))
    }
}

impl Serialize for secp256k1::PublicKey {
    fn serialize(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}

impl Deserialize for secp256k1::PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        secp256k1::PublicKey::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("invalid public key"))
    }
}

impl Serialize for EcdsaSig {
    fn serialize(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Deserialize for EcdsaSig {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        // NB: Since BIP-174 says "the signature as would be pushed to the stack from
        // a scriptSig or witness" we should ideally use a consensus deserialization and do
        // not error on a non-standard values. However,
        //
        // 1) the current implementation of from_u32_consensus(`flag`) does not preserve
        // the sighash byte `flag` mapping all unknown values to EcdsaSighashType::All or
        // EcdsaSighashType::AllPlusAnyOneCanPay. Therefore, break the invariant
        // EcdsaSig::from_slice(&sl[..]).to_vec = sl.
        //
        // 2) This would cause to have invalid signatures because the sighash message
        // also has a field sighash_u32 (See BIP141). For example, when signing with non-standard
        // 0x05, the sighash message would have the last field as 0x05u32 while, the verification
        // would use check the signature assuming sighash_u32 as `0x01`.
        EcdsaSig::from_slice(bytes)
            .map_err(|e| match e {
                EcdsaSigError::EmptySignature => {
                    encode::Error::ParseFailed("Empty partial signature data")
                }
                EcdsaSigError::NonStandardSighashType(flag) => {
                    encode::Error::from(psbt::Error::NonStandardSighashType(flag))
                }
                EcdsaSigError::Secp256k1(..) => {
                    encode::Error::ParseFailed("Invalid Ecdsa signature")
                }
                EcdsaSigError::HexEncoding(..) =>  {
                    unreachable!("Decoding from slice, not hex")
                }
            })
    }
}

impl Serialize for KeySource {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(key_source_len(self));

        rv.append(&mut self.0.to_bytes().to_vec());

        for cnum in self.1.into_iter() {
            rv.append(&mut serialize(&u32::from(*cnum)))
        }

        rv
    }
}

impl Deserialize for KeySource {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        if bytes.len() < 4 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
        }

        let fprint: Fingerprint = Fingerprint::from(&bytes[0..4]);
        let mut dpath: Vec<ChildNumber> = Default::default();

        let mut d = &bytes[4..];
        while !d.is_empty() {
            match u32::consensus_decode(&mut d) {
                Ok(index) => dpath.push(index.into()),
                Err(e) => return Err(e),
            }
        }

        Ok((fprint, dpath.into()))
    }
}

// partial sigs
impl Serialize for Vec<u8> {
    fn serialize(&self) -> Vec<u8> {
        self.clone()
    }
}

impl Deserialize for Vec<u8> {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(bytes.to_vec())
    }
}

impl Serialize for PsbtSighashType {
    fn serialize(&self) -> Vec<u8> {
        serialize(&self.to_u32())
    }
}

impl Deserialize for PsbtSighashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        Ok(PsbtSighashType { inner: raw })
    }
}

// Taproot related ser/deser
impl Serialize for XOnlyPublicKey {
    fn serialize(&self) -> Vec<u8> {
        XOnlyPublicKey::serialize(self).to_vec()
    }
}

impl Deserialize for XOnlyPublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        XOnlyPublicKey::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid xonly public key"))
    }
}

impl Serialize for schnorr::SchnorrSig  {
    fn serialize(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Deserialize for schnorr::SchnorrSig {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        schnorr::SchnorrSig::from_slice(bytes)
            .map_err(|e| match e {
                schnorr::SchnorrSigError::InvalidSighashType(flag) => {
                    encode::Error::from(psbt::Error::NonStandardSighashType(flag as u32))
                }
                schnorr::SchnorrSigError::InvalidSchnorrSigSize(_) => {
                    encode::Error::ParseFailed("Invalid Schnorr signature length")
                }
                schnorr::SchnorrSigError::Secp256k1(..) => {
                    encode::Error::ParseFailed("Invalid Schnorr signature")
                }
            })
    }
}

impl Serialize for (XOnlyPublicKey, TapLeafHash) {
    fn serialize(&self) -> Vec<u8> {
        let ser_pk = self.0.serialize();
        let mut buf = Vec::with_capacity(ser_pk.len() + self.1.as_ref().len());
        buf.extend(&ser_pk);
        buf.extend(self.1.as_ref());
        buf
    }
}

impl Deserialize for (XOnlyPublicKey, TapLeafHash) {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        if bytes.len() < 32 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
        }
        let a: XOnlyPublicKey = Deserialize::deserialize(&bytes[..32])?;
        let b: TapLeafHash = Deserialize::deserialize(&bytes[32..])?;
        Ok((a, b))
    }
}

impl Serialize for ControlBlock {
    fn serialize(&self) -> Vec<u8> {
        ControlBlock::serialize(self)
    }
}

impl Deserialize for ControlBlock {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        Self::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid control block"))
    }
}

// Versioned Script
impl Serialize for (Script, LeafVersion) {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.0.len() + 1);
        buf.extend(self.0.as_bytes());
        buf.push(self.1.to_consensus());
        buf
    }
}

impl Deserialize for (Script, LeafVersion) {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        if bytes.is_empty() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
        }
        // The last byte is LeafVersion.
        let script = Script::deserialize(&bytes[..bytes.len() - 1])?;
        let leaf_ver = LeafVersion::from_consensus(bytes[bytes.len() - 1])
            .map_err(|_| encode::Error::ParseFailed("invalid leaf version"))?;
        Ok((script, leaf_ver))
    }
}


impl Serialize for (Vec<TapLeafHash>, KeySource) {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity( 32 * self.0.len() + key_source_len(&self.1));
        self.0.consensus_encode(&mut buf).expect("Vecs don't error allocation");
        // TODO: Add support for writing into a writer for key-source
        buf.extend(self.1.serialize());
        buf
    }
}

impl Deserialize for (Vec<TapLeafHash>, KeySource) {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let (leafhash_vec, consumed) = deserialize_partial::<Vec<TapLeafHash>>(bytes)?;
        let key_source = KeySource::deserialize(&bytes[consumed..])?;
        Ok((leafhash_vec, key_source))
    }
}

impl Serialize for TapTree {
    fn serialize(&self) -> Vec<u8> {
        match (self.0.branch().len(), self.0.branch().last()) {
            (1, Some(Some(root))) => {
                let mut buf = Vec::new();
                for leaf_info in root.leaves.iter() {
                    // # Cast Safety:
                    //
                    // TaprootMerkleBranch can only have len atmost 128(TAPROOT_CONTROL_MAX_NODE_COUNT).
                    // safe to cast from usize to u8
                    buf.push(leaf_info.merkle_branch().as_inner().len() as u8);
                    buf.push(leaf_info.leaf_version().to_consensus());
                    leaf_info.script().consensus_encode(&mut buf).expect("Vecs dont err");
                }
                buf
            }
        // This should be unreachable as we Taptree is already finalized
            _ => unreachable!(),
        }
    }
}

impl Deserialize for TapTree {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let mut builder = TaprootBuilder::new();
        let mut bytes_iter = bytes.iter();
        while let Some(depth) = bytes_iter.next() {
            let version = bytes_iter.next().ok_or(encode::Error::ParseFailed("Invalid Taproot Builder"))?;
            let (script, consumed) = deserialize_partial::<Script>(bytes_iter.as_slice())?;
            if consumed > 0 {
                bytes_iter.nth(consumed - 1);
            }

            let leaf_version = LeafVersion::from_consensus(*version)
                .map_err(|_| encode::Error::ParseFailed("Leaf Version Error"))?;
            builder = builder.add_leaf_with_ver(*depth, script, leaf_version)
                .map_err(|_| encode::Error::ParseFailed("Tree not in DFS order"))?;
        }
        if builder.is_finalizable() && !builder.has_hidden_nodes() {
            Ok(TapTree(builder))
        } else {
            Err(encode::Error::ParseFailed("Incomplete taproot Tree"))
        }
    }
}

// Helper function to compute key source len
fn key_source_len(key_source: &KeySource) -> usize {
    4 + 4 * (key_source.1).as_ref().len()
}

#[cfg(test)]
mod tests {
    use core::convert::TryFrom;

    use crate::hashes::hex::FromHex;
    use super::*;

    // Composes tree matching a given depth map, filled with dumb script leafs,
    // each of which consists of a single push-int op code, with int value
    // increased for each consecutive leaf.
    pub fn compose_taproot_builder<'map>(opcode: u8, depth_map: impl IntoIterator<Item = &'map u8>) -> TaprootBuilder {
        let mut val = opcode;
        let mut builder = TaprootBuilder::new();
        for depth in depth_map {
            let script = Script::from_hex(&format!("{:02x}", val)).unwrap();
            builder = builder.add_leaf(*depth, script).unwrap();
            let (new_val, _) = val.overflowing_add(1);
            val = new_val;
        }
        builder
    }

    #[test]
    fn taptree_hidden() {
        let mut builder = compose_taproot_builder(0x51, &[2, 2, 2]);
        builder = builder.add_leaf_with_ver(3, Script::from_hex("b9").unwrap(), LeafVersion::from_consensus(0xC2).unwrap()).unwrap();
        builder = builder.add_hidden_node(3, sha256::Hash::all_zeros()).unwrap();
        assert!(TapTree::try_from(builder).is_err());
    }

    #[test]
    fn taptree_roundtrip() {
        let mut builder = compose_taproot_builder(0x51, &[2, 2, 2, 3]);
        builder = builder.add_leaf_with_ver(3, Script::from_hex("b9").unwrap(), LeafVersion::from_consensus(0xC2).unwrap()).unwrap();
        let tree = TapTree::try_from(builder).unwrap();
        let tree_prime = TapTree::deserialize(&tree.serialize()).unwrap();
        assert_eq!(tree, tree_prime);
    }

    #[test]
    fn can_deserialize_non_standard_psbt_sighash_type() {
        let non_standard_sighash = [222u8, 0u8, 0u8, 0u8]; // 32 byte value.
        let sighash = PsbtSighashType::deserialize(&non_standard_sighash);
        assert!(sighash.is_ok())
    }
}
