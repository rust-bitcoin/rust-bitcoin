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

//! # PSBT Serialization
//!
//! Defines traits used for (de)serializing PSBT values into/from raw
//! bytes in PSBT key-value pairs.

use prelude::*;

use io;

use blockdata::script::Script;
use blockdata::transaction::{SigHashType, Transaction, TxOut};
use consensus::encode::{self, serialize, Decodable};
use util::bip32::{ChildNumber, Fingerprint, KeySource};
use hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use util::ecdsa::PublicKey;
use util::psbt;
use schnorr::{self, SpendingSignature};

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
impl_psbt_hash_de_serialize!(hash160::Hash);
impl_psbt_hash_de_serialize!(sha256d::Hash);

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

impl Serialize for SpendingSignature {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(65);
        buf.extend(&self.signature()[..]);
        if self.requires_sighash() {
            buf.push(self.sighash_byte());
        }
        buf
    }
}

impl Deserialize for SpendingSignature {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let (sig_slice, sighash_type) = match bytes.len() {
            64 => (bytes, SigHashType::All),
            65 => (&bytes[..=64], SigHashType::from_u32_consensus(bytes[64] as u32)),
            _ => return Err(encode::Error::ParseFailed("non-standard partial BIP-341 signature data length"))
        };
        let signature = schnorr::Signature::from_slice(sig_slice)
            .expect("BIP-340 signature reconstruction from 64-byte slice");
        Ok(SpendingSignature::with(signature, sighash_type))
    }
}


impl Serialize for KeySource {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(4 + 4 * (self.1).as_ref().len());

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

impl Serialize for SigHashType {
    fn serialize(&self) -> Vec<u8> {
        serialize(&self.as_u32())
    }
}

impl Deserialize for SigHashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        let rv: SigHashType = SigHashType::from_u32_consensus(raw);

        if rv.as_u32() == raw {
            Ok(rv)
        } else {
            Err(psbt::Error::NonStandardSigHashType(raw).into())
        }
    }
}
