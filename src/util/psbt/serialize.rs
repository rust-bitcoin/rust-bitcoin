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

//! PSBT serialization.
//!
//! Defines traits used for (de)serializing PSBT values into/from raw
//! bytes from/as PSBT key-value pairs.
//!

use prelude::*;

use ::{EcdsaSig, io};

use blockdata::script::Script;
use blockdata::transaction::{EcdsaSigHashType, Transaction, TxOut};
use consensus::encode::{self, serialize, Decodable, Encodable, deserialize_partial};
use secp256k1::{self, XOnlyPublicKey};
use util::bip32::{ChildNumber, Fingerprint, KeySource};
use hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use util::ecdsa::PublicKey;
use util::psbt;
use util::taproot::{TapBranchHash, TapLeafHash, ControlBlock, LeafVersion};
use schnorr;
use super::map::TapTree;

use util::taproot::TaprootBuilder;
use util::sighash::SchnorrSigHashType;
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
impl_psbt_de_serialize!(Vec<Vec<u8>>); // scriptWitness
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

impl Serialize for EcdsaSig {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(72);
        buf.extend(self.sig.serialize_der().iter());
        buf.push(self.hash_ty as u8);
        buf
    }
}

impl Deserialize for EcdsaSig {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let (sighash_byte, signature) = bytes.split_last()
            .ok_or(encode::Error::ParseFailed("empty partial signature data"))?;
        Ok(EcdsaSig {
            sig: secp256k1::ecdsa::Signature::from_der(signature)
                .map_err(|_| encode::Error::ParseFailed("non-DER encoded signature"))?,
            // NB: Since BIP-174 says "the signature as would be pushed to the stack from
            // a scriptSig or witness" we should use a consensus deserialization and do
            // not error on a non-standard values.
            hash_ty: EcdsaSigHashType::from_u32_consensus(*sighash_byte as u32)
        })
    }
}

impl Serialize for KeySource {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(key_source_len(&self));

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

impl Serialize for EcdsaSigHashType {
    fn serialize(&self) -> Vec<u8> {
        serialize(&self.as_u32())
    }
}

impl Deserialize for EcdsaSigHashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        let rv: EcdsaSigHashType = EcdsaSigHashType::from_u32_consensus(raw);

        if rv.as_u32() == raw {
            Ok(rv)
        } else {
            Err(psbt::Error::NonStandardSigHashType(raw).into())
        }
    }
}

// Taproot related ser/deser
impl Serialize for XOnlyPublicKey {
    fn serialize(&self) -> Vec<u8> {
        XOnlyPublicKey::serialize(&self).to_vec()
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
        match bytes.len() {
            65 => {
                let hash_ty = SchnorrSigHashType::from_u8(bytes[64])
                    .map_err(|_| encode::Error::ParseFailed("Invalid Sighash type"))?;
                let sig = secp256k1::schnorr::Signature::from_slice(&bytes[..64])
                    .map_err(|_| encode::Error::ParseFailed("Invalid Schnorr signature"))?;
                Ok(schnorr::SchnorrSig{ sig, hash_ty })
            }
            64 => {
                let sig = secp256k1::schnorr::Signature::from_slice(&bytes[..64])
                    .map_err(|_| encode::Error::ParseFailed("Invalid Schnorr signature"))?;
                    Ok(schnorr::SchnorrSig{ sig, hash_ty: SchnorrSigHashType::Default })
            }
            _ => Err(encode::Error::ParseFailed("Invalid Schnorr signature len"))
        }
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
        ControlBlock::serialize(&self)
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
        buf.push(self.1.as_u8());
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
        let leaf_ver = LeafVersion::from_u8(bytes[bytes.len() - 1])
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
        let (leafhash_vec, consumed) = deserialize_partial::<Vec<TapLeafHash>>(&bytes)?;
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
                    buf.push(leaf_info.merkle_branch.as_inner().len() as u8);
                    buf.push(leaf_info.ver.as_u8());
                    leaf_info.script.consensus_encode(&mut buf).expect("Vecs dont err");
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

            let leaf_version = LeafVersion::from_u8(*version)
                .map_err(|_| encode::Error::ParseFailed("Leaf Version Error"))?;
            builder = builder.add_leaf_with_ver(usize::from(*depth), script, leaf_version)
                .map_err(|_| encode::Error::ParseFailed("Tree not in DFS order"))?;
        }
        if builder.is_complete() {
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
