// SPDX-License-Identifier: CC0-1.0

//! PSBT serialization.
//!
//! Traits to serialize PSBT values to and from raw bytes
//! according to the BIP-174 specification.

use hashes::{hash160, ripemd160, sha256, sha256d};
use secp256k1::XOnlyPublicKey;

use super::map::{Input, Map, Output, PsbtSighashType};
use crate::bip32::{ChildNumber, Fingerprint, KeySource};
use crate::consensus::encode::{self, deserialize_partial, serialize, Decodable, Encodable};
use crate::crypto::key::PublicKey;
use crate::crypto::{ecdsa, taproot};
use crate::io::Write;
use crate::prelude::{DisplayHex, String, Vec};
use crate::psbt::{Error, Psbt};
use crate::script::ScriptBuf;
use crate::taproot::{
    ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TapTree, TaprootBuilder,
};
use crate::transaction::{Transaction, TxOut};
use crate::witness::Witness;
use crate::VarInt;
/// A trait for serializing a value as raw data for insertion into PSBT
/// key-value maps.
pub(crate) trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSBT key-value maps.
pub(crate) trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

impl Psbt {
    /// Serialize a value as bytes in hex.
    pub fn serialize_hex(&self) -> String { self.serialize().to_lower_hex_string() }

    /// Serialize as raw binary data
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.serialize_to_writer(&mut buf).expect("Writing to Vec can't fail");
        buf
    }

    /// Serialize the PSBT into a writer.
    pub fn serialize_to_writer(&self, w: &mut impl Write) -> io::Result<usize> {
        let mut written_len = 0;

        fn write_all(w: &mut impl Write, data: &[u8]) -> io::Result<usize> {
            w.write_all(data).map(|_| data.len())
        }

        // magic
        written_len += write_all(w, b"psbt")?;
        // separator
        written_len += write_all(w, &[0xff])?;

        written_len += write_all(w, &self.serialize_map())?;

        for i in &self.inputs {
            written_len += write_all(w, &i.serialize_map())?;
        }

        for i in &self.outputs {
            written_len += write_all(w, &i.serialize_map())?;
        }

        Ok(written_len)
    }

    /// Deserialize a value from raw binary data.
    pub fn deserialize(mut bytes: &[u8]) -> Result<Self, Error> {
        Self::deserialize_from_reader(&mut bytes)
    }

    /// Deserialize a value from raw binary data read from a `BufRead` object.
    pub fn deserialize_from_reader<R: io::BufRead>(r: &mut R) -> Result<Self, Error> {
        const MAGIC_BYTES: &[u8] = b"psbt";

        let magic: [u8; 4] = Decodable::consensus_decode(r)?;
        if magic != MAGIC_BYTES {
            return Err(Error::InvalidMagic);
        }

        const PSBT_SERPARATOR: u8 = 0xff_u8;
        let separator: u8 = Decodable::consensus_decode(r)?;
        if separator != PSBT_SERPARATOR {
            return Err(Error::InvalidSeparator);
        }

        let mut global = Psbt::decode_global(r)?;
        global.unsigned_tx_checks()?;

        let inputs: Vec<Input> = {
            let inputs_len: usize = (global.unsigned_tx.input).len();

            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for _ in 0..inputs_len {
                inputs.push(Input::decode(r)?);
            }

            inputs
        };

        let outputs: Vec<Output> = {
            let outputs_len: usize = (global.unsigned_tx.output).len();

            let mut outputs: Vec<Output> = Vec::with_capacity(outputs_len);

            for _ in 0..outputs_len {
                outputs.push(Output::decode(r)?);
            }

            outputs
        };

        global.inputs = inputs;
        global.outputs = outputs;
        Ok(global)
    }
}
impl_psbt_de_serialize!(Transaction);
impl_psbt_de_serialize!(TxOut);
impl_psbt_de_serialize!(Witness);
impl_psbt_hash_de_serialize!(ripemd160::Hash);
impl_psbt_hash_de_serialize!(sha256::Hash);
impl_psbt_hash_de_serialize!(TapLeafHash);
impl_psbt_hash_de_serialize!(TapNodeHash);
impl_psbt_hash_de_serialize!(hash160::Hash);
impl_psbt_hash_de_serialize!(sha256d::Hash);

// Taproot
impl_psbt_de_serialize!(Vec<TapLeafHash>);

impl Serialize for ScriptBuf {
    fn serialize(&self) -> Vec<u8> { self.to_bytes() }
}

impl Deserialize for ScriptBuf {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> { Ok(Self::from(bytes.to_vec())) }
}

impl Serialize for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }
}

impl Deserialize for PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        PublicKey::from_slice(bytes).map_err(Error::InvalidPublicKey)
    }
}

impl Serialize for secp256k1::PublicKey {
    fn serialize(&self) -> Vec<u8> { self.serialize().to_vec() }
}

impl Deserialize for secp256k1::PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        secp256k1::PublicKey::from_slice(bytes).map_err(Error::InvalidSecp256k1PublicKey)
    }
}

impl Serialize for ecdsa::Signature {
    fn serialize(&self) -> Vec<u8> { self.to_vec() }
}

impl Deserialize for ecdsa::Signature {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
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
        ecdsa::Signature::from_slice(bytes).map_err(|e| match e {
            ecdsa::DecodeError::EmptySignature => Error::InvalidEcdsaSignature(e),
            ecdsa::DecodeError::SighashType(err) => Error::NonStandardSighashType(err.0),
            ecdsa::DecodeError::Secp256k1(..) => Error::InvalidEcdsaSignature(e),
        })
    }
}

impl Serialize for KeySource {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(key_source_len(self));

        rv.append(&mut self.0.to_byte_array().to_vec());

        for cnum in self.1.into_iter() {
            rv.append(&mut serialize(&u32::from(*cnum)))
        }

        rv
    }
}

impl Deserialize for KeySource {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let fprint: Fingerprint = bytes[0..4].try_into().expect("4 is the fingerprint length");
        let mut dpath: Vec<ChildNumber> = Default::default();

        let mut d = &bytes[4..];
        while !d.is_empty() {
            match u32::consensus_decode(&mut d) {
                Ok(index) => dpath.push(index.into()),
                Err(e) => return Err(e.into()),
            }
        }

        Ok((fprint, dpath.into()))
    }
}

// partial sigs
impl Serialize for Vec<u8> {
    fn serialize(&self) -> Vec<u8> { self.clone() }
}

impl Deserialize for Vec<u8> {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> { Ok(bytes.to_vec()) }
}

impl Serialize for PsbtSighashType {
    fn serialize(&self) -> Vec<u8> { serialize(&self.to_u32()) }
}

impl Deserialize for PsbtSighashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        Ok(PsbtSighashType { inner: raw })
    }
}

// Taproot related ser/deser
impl Serialize for XOnlyPublicKey {
    fn serialize(&self) -> Vec<u8> { XOnlyPublicKey::serialize(self).to_vec() }
}

impl Deserialize for XOnlyPublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        XOnlyPublicKey::from_slice(bytes).map_err(|_| Error::InvalidXOnlyPublicKey)
    }
}

impl Serialize for taproot::Signature {
    fn serialize(&self) -> Vec<u8> { self.to_vec() }
}

impl Deserialize for taproot::Signature {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        use taproot::DecodeError::*;

        taproot::Signature::from_slice(bytes).map_err(|e| match e {
            SighashType(err) => Error::NonStandardSighashType(err.0),
            InvalidSignatureSize(_) => Error::InvalidTaprootSignature(e),
            Secp256k1(..) => Error::InvalidTaprootSignature(e),
        })
    }
}

impl Serialize for (XOnlyPublicKey, TapLeafHash) {
    fn serialize(&self) -> Vec<u8> {
        let ser_pk = self.0.serialize();
        let mut buf = Vec::with_capacity(ser_pk.len() + self.1.as_byte_array().len());
        buf.extend(&ser_pk);
        buf.extend(self.1.as_byte_array());
        buf
    }
}

impl Deserialize for (XOnlyPublicKey, TapLeafHash) {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 32 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        let a: XOnlyPublicKey = Deserialize::deserialize(&bytes[..32])?;
        let b: TapLeafHash = Deserialize::deserialize(&bytes[32..])?;
        Ok((a, b))
    }
}

impl Serialize for ControlBlock {
    fn serialize(&self) -> Vec<u8> { ControlBlock::serialize(self) }
}

impl Deserialize for ControlBlock {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes).map_err(|_| Error::InvalidControlBlock)
    }
}

// Versioned ScriptBuf
impl Serialize for (ScriptBuf, LeafVersion) {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.0.len() + 1);
        buf.extend(self.0.as_bytes());
        buf.push(self.1.to_consensus());
        buf
    }
}

impl Deserialize for (ScriptBuf, LeafVersion) {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        // The last byte is LeafVersion.
        let script = ScriptBuf::deserialize(&bytes[..bytes.len() - 1])?;
        let leaf_ver = LeafVersion::from_consensus(bytes[bytes.len() - 1])
            .map_err(|_| Error::InvalidLeafVersion)?;
        Ok((script, leaf_ver))
    }
}

impl Serialize for (Vec<TapLeafHash>, KeySource) {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 * self.0.len() + key_source_len(&self.1));
        self.0.consensus_encode(&mut buf).expect("Vecs don't error allocation");
        buf.extend(self.1.serialize());
        buf
    }
}

impl Deserialize for (Vec<TapLeafHash>, KeySource) {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let (leafhash_vec, consumed) = deserialize_partial::<Vec<TapLeafHash>>(bytes)?;
        let key_source = KeySource::deserialize(&bytes[consumed..])?;
        Ok((leafhash_vec, key_source))
    }
}

impl Serialize for TapTree {
    fn serialize(&self) -> Vec<u8> {
        let capacity = self
            .script_leaves()
            .map(|l| {
                l.script().len() + VarInt::from(l.script().len()).size() // script version
            + 1 // Merkle branch
            + 1 // leaf version
            })
            .sum::<usize>();
        let mut buf = Vec::with_capacity(capacity);
        for leaf_info in self.script_leaves() {
            // # Cast Safety:
            //
            // TaprootMerkleBranch can only have len atmost 128(TAPROOT_CONTROL_MAX_NODE_COUNT).
            // safe to cast from usize to u8
            buf.push(leaf_info.merkle_branch().len() as u8);
            buf.push(leaf_info.version().to_consensus());
            leaf_info.script().consensus_encode(&mut buf).expect("Vecs dont err");
        }
        buf
    }
}

impl Deserialize for TapTree {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut builder = TaprootBuilder::new();
        let mut bytes_iter = bytes.iter();
        while let Some(depth) = bytes_iter.next() {
            let version = bytes_iter.next().ok_or(Error::Taproot("invalid Taproot Builder"))?;
            let (script, consumed) = deserialize_partial::<ScriptBuf>(bytes_iter.as_slice())?;
            if consumed > 0 {
                bytes_iter.nth(consumed - 1);
            }
            let leaf_version =
                LeafVersion::from_consensus(*version).map_err(|_| Error::InvalidLeafVersion)?;
            builder = builder
                .add_leaf_with_ver(*depth, script, leaf_version)
                .map_err(|_| Error::Taproot("Tree not in DFS order"))?;
        }
        TapTree::try_from(builder).map_err(Error::TapTree)
    }
}

// Helper function to compute key source len
fn key_source_len(key_source: &KeySource) -> usize { 4 + 4 * (key_source.1).as_ref().len() }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::ScriptBufExt as _;

    // Composes tree matching a given depth map, filled with dumb script leafs,
    // each of which consists of a single push-int op code, with int value
    // increased for each consecutive leaf.
    pub fn compose_taproot_builder<'map>(
        opcode: u8,
        depth_map: impl IntoIterator<Item = &'map u8>,
    ) -> TaprootBuilder {
        let mut val = opcode;
        let mut builder = TaprootBuilder::new();
        for depth in depth_map {
            let script = ScriptBuf::from_hex(&format!("{:02x}", val)).unwrap();
            builder = builder.add_leaf(*depth, script).unwrap();
            let (new_val, _) = val.overflowing_add(1);
            val = new_val;
        }
        builder
    }

    #[test]
    fn taptree_hidden() {
        let dummy_hash = TapNodeHash::from_byte_array([0x12; 32]);
        let mut builder = compose_taproot_builder(0x51, &[2, 2, 2]);
        builder = builder
            .add_leaf_with_ver(
                3,
                ScriptBuf::from_hex("b9").unwrap(),
                LeafVersion::from_consensus(0xC2).unwrap(),
            )
            .unwrap();
        builder = builder.add_hidden_node(3, dummy_hash).unwrap();
        assert!(TapTree::try_from(builder).is_err());
    }

    #[test]
    fn taptree_roundtrip() {
        let mut builder = compose_taproot_builder(0x51, &[2, 2, 2, 3]);
        builder = builder
            .add_leaf_with_ver(
                3,
                ScriptBuf::from_hex("b9").unwrap(),
                LeafVersion::from_consensus(0xC2).unwrap(),
            )
            .unwrap();
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

    #[test]
    #[should_panic(expected = "InvalidMagic")]
    fn invalid_vector_1() {
        let hex_psbt = b"0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300";
        Psbt::deserialize(hex_psbt).unwrap();
    }
}
