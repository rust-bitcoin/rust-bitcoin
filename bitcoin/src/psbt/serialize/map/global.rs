// SPDX-License-Identifier: CC0-1.0

use core::{cmp, fmt};

use internals::{write_err, ToU64 as _};
use io::{self, BufRead, Cursor, Read, Write};

use crate::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
use crate::consensus::encode::{ReadExt as _, MAX_VEC_SIZE};
use crate::consensus::{encode, Decodable};
use crate::locktime::absolute;
use crate::prelude::{btree_map, BTreeMap, DisplayHex, Vec};
use crate::psbt::consts::{
    PSBT_GLOBAL_FALLBACK_LOCKTIME, PSBT_GLOBAL_INPUT_COUNT, PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_PROPRIETARY, PSBT_GLOBAL_TX_MODIFIABLE, PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION, PSBT_GLOBAL_XPUB,
};
use crate::psbt::serialize::map::{self, input, output, Map};
use crate::psbt::serialize::{raw, Error};
use crate::psbt::{self, Version};
use crate::transaction::{self, Transaction};

/// A serializable PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Psbt {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be empty.
    ///
    /// PSBT_GLOBAL_UNSIGNED_TX: Required for v0, excluded for v2.
    pub unsigned_tx: Option<Transaction>,

    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32.
    ///
    /// PSBT_GLOBAL_XPUB: Optional for v0, optional for v2.
    pub xpub: BTreeMap<Xpub, KeySource>,

    /// The version number of the transaction being built.
    ///
    /// PSBT_GLOBAL_TX_VERSION: Excluded for v0, required for v2.
    pub tx_version: Option<transaction::Version>,

    /// The transaction locktime to use if no inputs specify a required locktime.
    ///
    /// PSBT_GLOBAL_FALLBACK_LOCKTIME: Excluded for v0, optional for v2.
    pub fallback_lock_time: Option<absolute::LockTime>,

    /// The number of inputs in this PSBT.
    ///
    /// PSBT_GLOBAL_INPUT_COUNT: Excluded for v0, required for v2.
    pub input_count: Option<usize>, // Serialized as compact int.

    /// The number of outputs in this PSBT.
    ///
    /// PSBT_GLOBAL_OUTPUT_COUNT: Excluded for v0, required for v2.
    pub output_count: Option<usize>, // Serialized as compact int.

    /// A bitfield for various transaction modification flags.
    ///
    /// PSBT_GLOBAL_TX_MODIFIABLE: Excluded for v0, optional for v2.
    pub tx_modifiable_flags: Option<u8>,

    /// The version number of this PSBT (if omitted defaults to version 0).
    ///
    /// PSBT_GLOBAL_VERSION: Optional for v0, optional for v2.
    pub version: Version,

    /// Global proprietary key-value pairs.
    ///
    /// PSBT_GLOBAL_PROPRIETARY: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,

    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<map::Input>,

    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<map::Output>,
}

impl Psbt {
    /// Checks if `Psbt` has fields set as required by the respective BIP based on `self.version`.
    pub fn assert_valid(&self) -> Result<(), InvalidError> {
        match self.version {
            Version::Zero => Ok(self.assert_valid_v0()?),
            Version::Two => Ok(self.assert_valid_v2()?),
        }
    }

    /// Checks if `Psbt` has fields set as required by `BIP-174`.
    pub fn assert_valid_v0(&self) -> Result<(), V0InvalidError> {
        use V0InvalidError as E;

        if self.version != Version::Zero {
            return Err(E::InvalidVersion(self.version));
        }

        if self.unsigned_tx.is_none() {
            return Err(E::UnsignedTx);
        }
        if self.tx_version.is_some() {
            return Err(E::TxVersion);
        }
        if self.fallback_lock_time.is_some() {
            return Err(E::FallbackLockTime);
        }
        if self.input_count.is_some() {
            return Err(E::InputCount);
        }
        if self.output_count.is_some() {
            return Err(E::OutputCount);
        }
        if self.tx_modifiable_flags.is_some() {
            return Err(E::TxModifiableFlags);
        }

        self.inputs.iter().try_for_each(|input| input.assert_valid_v0())?;
        self.outputs.iter().try_for_each(|output| output.assert_valid_v0())?;

        Ok(())
    }

    /// Checks if `Psbt` has fields set as required by `BIP-370`.
    pub fn assert_valid_v2(&self) -> Result<(), V2InvalidError> {
        use V2InvalidError as E;

        if self.version != Version::Two {
            return Err(E::InvalidVersion(self.version));
        }

        if self.unsigned_tx.is_some() {
            return Err(E::UnsignedTx);
        }
        if self.tx_version.is_none() {
            return Err(E::TxVersion);
        }
        if self.input_count.is_none() {
            return Err(E::InputCount);
        }
        if self.output_count.is_none() {
            return Err(E::OutputCount);
        }

        self.inputs.iter().try_for_each(|input| input.assert_valid_v2())?;
        self.outputs.iter().try_for_each(|output| output.assert_valid_v2())?;

        Ok(())
    }

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
        if global.version == Version::Zero {
            psbt::unsigned_tx_checks(
                global.unsigned_tx.as_ref().expect("guaranteed by decode_global"),
            )?;
        }

        let inputs: Vec<map::Input> = {
            let inputs_len = global.num_inputs().expect("guaranteed by decode_global");
            let mut inputs: Vec<map::Input> = Vec::with_capacity(inputs_len);
            for _ in 0..inputs_len {
                inputs.push(map::Input::decode(r)?);
            }
            inputs
        };

        let outputs: Vec<map::Output> = {
            let outputs_len = global.num_outputs().expect("guaranteed by decode_global");
            let mut outputs: Vec<map::Output> = Vec::with_capacity(outputs_len);
            for _ in 0..outputs_len {
                outputs.push(map::Output::decode(r)?);
            }
            outputs
        };

        global.inputs = inputs;
        global.outputs = outputs;
        Ok(global)
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP 174.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), Error> {
        // FIXME: What if one is valid v0 and one is valid v2?
        if let (Some(ref this), Some(ref that)) = (&self.unsigned_tx, &other.unsigned_tx) {
            if this != that {
                return Err(Error::UnexpectedUnsignedTx {
                    expected: Box::new(this.clone()),
                    actual: Box::new(that.clone()),
                });
            }
        }

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpub {
            match self.xpub.entry(xpub) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if (derivation1 == derivation2 && fingerprint1 == fingerprint2)
                        || (derivation1.len() < derivation2.len()
                            && derivation1[..]
                                == derivation2[derivation2.len() - derivation1.len()..])
                    {
                        continue;
                    } else if derivation2[..]
                        == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue;
                    }
                    return Err(Error::CombineInconsistentKeySources(Box::new(xpub)));
                }
            }
        }

        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.combine(other_input);
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.combine(other_output);
        }

        Ok(())
    }

    fn num_inputs(&self) -> Result<usize, InvalidError> {
        self.assert_valid()?;
        match self.version {
            Version::Zero => Ok(self.unsigned_tx.as_ref().unwrap().input.len()),
            Version::Two => Ok(self.input_count.unwrap()),
        }
    }

    fn num_outputs(&self) -> Result<usize, InvalidError> {
        self.assert_valid()?;
        match self.version {
            Version::Zero => Ok(self.unsigned_tx.as_ref().unwrap().output.len()),
            Version::Two => Ok(self.output_count.unwrap()),
        }
    }
}

impl Map for Psbt {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        if let Some(ref unsigned_tx) = self.unsigned_tx {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_UNSIGNED_TX, key_data: vec![] },
                value: {
                    // Manually serialized to ensure 0-input txs are serialized without witnesses.
                    let mut ret = Vec::new();
                    ret.extend(encode::serialize(&unsigned_tx.version));
                    ret.extend(encode::serialize(&unsigned_tx.input));
                    ret.extend(encode::serialize(&unsigned_tx.output));
                    ret.extend(encode::serialize(&unsigned_tx.lock_time));
                    ret
                },
            });
        }

        for (xpub, (fingerprint, derivation)) in &self.xpub {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_XPUB, key_data: xpub.encode().to_vec() },
                value: {
                    let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                    ret.extend(fingerprint.as_bytes());
                    derivation.into_iter().for_each(|n| ret.extend(&u32::from(*n).to_le_bytes()));
                    ret
                },
            });
        }

        // FIXME: Is the following comment (and code) stale now we have v2?
        // Serializing version only for non-default value; otherwise test vectors fail
        if self.version.to_u32() > 0 {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_VERSION, key_data: vec![] },
                value: self.version.to_u32().to_le_bytes().to_vec(),
            });
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

impl Psbt {
    pub(crate) fn decode_global<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let mut r = r.take(MAX_VEC_SIZE.to_u64());
        let mut unsigned_tx: Option<Transaction> = None;
        let mut xpub_map: BTreeMap<Xpub, (Fingerprint, DerivationPath)> = Default::default();
        let mut tx_version: Option<transaction::Version> = None;
        let mut fallback_lock_time: Option<absolute::LockTime> = None;
        let mut input_count: Option<usize> = None;
        let mut output_count: Option<usize> = None;
        let mut tx_modifiable_flags: Option<u8> = None;
        let mut version: Option<Version> = None;
        let mut proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();
        let mut unknown: BTreeMap<raw::Key, Vec<u8>> = Default::default();

        loop {
            match raw::Pair::decode(&mut r) {
                Ok(pair) => {
                    match pair.key.type_value {
                        PSBT_GLOBAL_UNSIGNED_TX => {
                            // key has to be empty
                            if pair.key.key_data.is_empty() {
                                // there can only be one unsigned transaction
                                if unsigned_tx.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);

                                    // Manually deserialized to ensure 0-input
                                    // txs without witnesses are deserialized
                                    // properly.
                                    unsigned_tx = Some(Transaction {
                                        version: Decodable::consensus_decode(&mut decoder)?,
                                        input: Decodable::consensus_decode(&mut decoder)?,
                                        output: Decodable::consensus_decode(&mut decoder)?,
                                        lock_time: Decodable::consensus_decode(&mut decoder)?,
                                    });

                                    if decoder.position() != vlen.to_u64() {
                                        return Err(Error::PartialDataConsumption);
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_XPUB => {
                            if !pair.key.key_data.is_empty() {
                                let xpub = Xpub::decode(&pair.key.key_data)
                                    .map_err(|_| Error::XPubKey(
                                        "can't deserialize ExtendedPublicKey from global XPUB key data"
                                    ))?;

                                if pair.value.is_empty() || pair.value.len() % 4 != 0 {
                                    return Err(Error::XPubKey(
                                        "incorrect length of global xpub derivation data",
                                    ));
                                }

                                let child_count = pair.value.len() / 4 - 1;
                                let mut decoder = Cursor::new(pair.value);
                                let mut fingerprint = [0u8; 4];
                                decoder.read_exact(&mut fingerprint[..]).map_err(|_| {
                                    Error::XPubKey("can't read global xpub fingerprint")
                                })?;
                                let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                                while let Ok(index) = u32::consensus_decode(&mut decoder) {
                                    path.push(ChildNumber::from(index))
                                }
                                let derivation = DerivationPath::from(path);
                                // Keys, according to BIP-174, must be unique
                                if xpub_map
                                    .insert(xpub, (Fingerprint::from(fingerprint), derivation))
                                    .is_some()
                                {
                                    return Err(Error::XPubKey("repeated global xpub key"));
                                }
                            } else {
                                return Err(Error::XPubKey(
                                    "Xpub global key must contain serialized Xpub data",
                                ));
                            }
                        }
                        PSBT_GLOBAL_TX_VERSION => {
                            if pair.key.key_data.is_empty() {
                                if tx_version.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 4 {
                                        return Err(Error::ValueWrongLength(vlen, 4));
                                    }
                                    // TODO: Consider doing checks for standard transaction version?
                                    tx_version = Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKeyDataNotEmpty(pair.key));
                            }
                        }
                        PSBT_GLOBAL_FALLBACK_LOCKTIME =>
                            if pair.key.key_data.is_empty() {
                                if fallback_lock_time.is_none() {
                                    let vlen: usize = pair.value.len();
                                    if vlen != 4 {
                                        return Err(Error::ValueWrongLength(vlen, 4));
                                    }
                                    let mut decoder = Cursor::new(pair.value);
                                    fallback_lock_time =
                                        Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKeyDataNotEmpty(pair.key));
                            },
                        PSBT_GLOBAL_INPUT_COUNT => {
                            if pair.key.key_data.is_empty() {
                                if output_count.is_none() {
                                    // TODO: Do we need to check the length for a VarInt?
                                    // let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    let count = decoder.read_compact_size()?;
                                    input_count = Some(count as usize); // compact_size fits in 32 bits.
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKeyDataNotEmpty(pair.key));
                            }
                        }
                        PSBT_GLOBAL_OUTPUT_COUNT => {
                            if pair.key.key_data.is_empty() {
                                if output_count.is_none() {
                                    // TODO: Do we need to check the length for a VarInt?
                                    // let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    let count = decoder.read_compact_size()?;
                                    output_count = Some(count as usize); // compact_size fits in 32 bits.
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKeyDataNotEmpty(pair.key));
                            }
                        }
                        PSBT_GLOBAL_TX_MODIFIABLE =>
                            if pair.key.key_data.is_empty() {
                                if tx_modifiable_flags.is_none() {
                                    let vlen: usize = pair.value.len();
                                    if vlen != 1 {
                                        return Err(Error::ValueWrongLength(vlen, 1));
                                    }
                                    let mut decoder = Cursor::new(pair.value);
                                    tx_modifiable_flags =
                                        Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKeyDataNotEmpty(pair.key));
                            },
                        PSBT_GLOBAL_VERSION => {
                            // key has to be empty
                            if pair.key.key_data.is_empty() {
                                // there can only be one version
                                if version.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 4 {
                                        return Err(Error::Version(
                                            "invalid global version value length (must be 4 bytes)",
                                        ));
                                    }
                                    let v: u32 = Decodable::consensus_decode(&mut decoder)?;
                                    version = Some(Version::try_from(v)?);
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_PROPRIETARY => match proprietary
                            .entry(raw::ProprietaryKey::try_from(pair.key.clone())?)
                        {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(_) =>
                                return Err(Error::DuplicateKey(pair.key)),
                        },
                        _ => match unknown.entry(pair.key) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(k) =>
                                return Err(Error::DuplicateKey(k.key().clone())),
                        },
                    }
                }
                Err(crate::psbt::Error::NoMorePairs) => break,
                Err(e) => return Err(e),
            }
        }

        let psbt = Psbt {
            unsigned_tx,
            xpub: xpub_map,
            tx_version,
            fallback_lock_time,
            input_count,
            output_count,
            tx_modifiable_flags,
            version: version.unwrap_or(Version::Zero),
            proprietary,
            unknown,
            inputs: vec![],
            outputs: vec![],
        };
        psbt.assert_valid()?;
        Ok(psbt)
    }
}

#[cfg(feature = "base64")]
mod display_from_str {
    use core::fmt;
    use core::str::FromStr;

    use base64::display::Base64Display;
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    use internals::write_err;

    use super::{Error, Psbt};

    /// Error encountered during PSBT decoding from Base64 string.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum PsbtParseError {
        /// Error in internal PSBT data structure.
        PsbtEncoding(Error),
        /// Error in PSBT Base64 encoding.
        Base64Encoding(::base64::DecodeError),
    }

    internals::impl_from_infallible!(PsbtParseError);

    impl fmt::Display for PsbtParseError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use self::PsbtParseError::*;

            match *self {
                PsbtEncoding(ref e) => write_err!(f, "error in internal PSBT data structure"; e),
                Base64Encoding(ref e) => write_err!(f, "error in PSBT base64 encoding"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for PsbtParseError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use self::PsbtParseError::*;

            match self {
                PsbtEncoding(e) => Some(e),
                Base64Encoding(e) => Some(e),
            }
        }
    }

    impl fmt::Display for Psbt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", Base64Display::new(&self.serialize(), &BASE64_STANDARD))
        }
    }

    impl FromStr for Psbt {
        type Err = PsbtParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let data = BASE64_STANDARD.decode(s).map_err(PsbtParseError::Base64Encoding)?;
            Psbt::deserialize(&data).map_err(PsbtParseError::PsbtEncoding)
        }
    }
}
#[cfg(feature = "base64")]
pub use self::display_from_str::PsbtParseError;

/// PSBT is not valid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidError {
    /// Invalid for v0.
    V0Invalid(V0InvalidError),
    /// Invalid for v2.
    V2Invalid(V2InvalidError),
    /// Unsupported version number.
    UnsupportedVersion(u32),
}

internals::impl_from_infallible!(InvalidError);

impl fmt::Display for InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InvalidError::*;

        match *self {
            V0Invalid(ref e) => write_err!(f, "v0"; e),
            V2Invalid(ref e) => write_err!(f, "v2"; e),
            UnsupportedVersion(v) => write!(f, "unsupported PSBT version number {}", v),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InvalidError::*;

        match *self {
            V0Invalid(ref e) => Some(e),
            V2Invalid(ref e) => Some(e),
            UnsupportedVersion(_) => None,
        }
    }
}

impl From<V0InvalidError> for InvalidError {
    fn from(e: V0InvalidError) -> Self { Self::V0Invalid(e) }
}

impl From<V2InvalidError> for InvalidError {
    fn from(e: V2InvalidError) -> Self { Self::V2Invalid(e) }
}

/// Output is not valid for v0 (BIP-370).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V0InvalidError {
    /// Invalid version (not version 0).
    InvalidVersion(Version),
    /// PSBT_GLOBAL_UNSIGNED_TX: Required for v0, excluded for v2.
    UnsignedTx,
    /// PSBT_GLOBAL_TX_VERSION: Excluded for v0, required for v2.
    TxVersion,
    /// PSBT_GLOBAL_FALLBACK_LOCKTIME: Excluded for v0, optional for v2.
    FallbackLockTime,
    /// PSBT_GLOBAL_INPUT_COUNT: Excluded for v0, required for v2.
    InputCount,
    /// PSBT_GLOBAL_OUTPUT_COUNT: Excluded for v0, required for v2.
    OutputCount,
    /// PSBT_GLOBAL_TX_MODIFIABLE: Excluded for v0, optional for v2.
    TxModifiableFlags,
    /// Psbt contains an invalid input.
    Input(input::V0InvalidError),
    /// Psbt contains an invalid output.
    Output(output::V0InvalidError),
}

internals::impl_from_infallible!(V0InvalidError);

impl fmt::Display for V0InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use V0InvalidError as E;

        match *self {
            E::InvalidVersion(v) =>
                write!(f, "invalid version {} (expected version 0)", v.to_u32()),
            E::UnsignedTx => write!(f, "PSBT_GLOBAL_UNSIGNED_TX is required for v0"),
            E::TxVersion => write!(f, "PSBT_GLOBAL_TX_VERSION must be excluded for v0"),
            E::FallbackLockTime =>
                write!(f, "PSBT_GLOBAL_FALLBACK_LOCKTIME must be excluded for v0"),
            E::InputCount => write!(f, "PSBT_GLOBAL_INPUT_COUNT must be excluded for v0"),
            E::OutputCount => write!(f, "PSBT_GLOBAL_OUTPUT_COUNT must be excluded for v0"),
            E::TxModifiableFlags => write!(f, "PSBT_GLOBAL_TX_MODIFIABLE must be excluded for v0"),
            E::Input(ref e) => write_err!(f, "PSBT contains an invalid input"; e),
            E::Output(ref e) => write_err!(f, "PSBT contains an invalid output"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V0InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use V0InvalidError as E;

        match *self {
            E::InvalidVersion(_)
            | E::UnsignedTx
            | E::TxVersion
            | E::FallbackLockTime
            | E::InputCount
            | E::OutputCount
            | E::TxModifiableFlags => None,
            E::Input(ref e) => Some(e),
            E::Output(ref e) => Some(e),
        }
    }
}

impl From<input::V0InvalidError> for V0InvalidError {
    fn from(e: input::V0InvalidError) -> Self { Self::Input(e) }
}

impl From<output::V0InvalidError> for V0InvalidError {
    fn from(e: output::V0InvalidError) -> Self { Self::Output(e) }
}

/// Output is not valid for v2 (BIP-370).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V2InvalidError {
    /// Invalid version (not version 2).
    InvalidVersion(Version),
    /// PSBT_GLOBAL_UNSIGNED_TX: Required for v0, excluded for v2.
    UnsignedTx,
    /// PSBT_GLOBAL_TX_VERSION: Excluded for v0, required for v2.
    TxVersion,
    /// PSBT_GLOBAL_INPUT_COUNT: Excluded for v0, required for v2.
    InputCount,
    /// PSBT_GLOBAL_OUTPUT_COUNT: Excluded for v0, required for v2.
    OutputCount,
    /// Psbt contains an invalid input.
    Input(input::V2InvalidError),
    /// Psbt contains an invalid output.
    Output(output::V2InvalidError),
}

internals::impl_from_infallible!(V2InvalidError);

impl fmt::Display for V2InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use V2InvalidError as E;

        match *self {
            E::InvalidVersion(v) =>
                write!(f, "invalid version {} (expected version 2)", v.to_u32()),
            E::UnsignedTx => write!(f, "PSBT_GLOBAL_UNSIGNED_TX must be excluded for v2"),
            E::TxVersion => write!(f, "PSBT_GLOBAL_TX_VERSION is required for v2"),
            E::InputCount => write!(f, "PSBT_GLOBAL_INPUT_COUNT is required for v2"),
            E::OutputCount => write!(f, "PSBT_GLOBAL_OUTPUT_COUNT is required for v2"),
            E::Input(ref e) => write_err!(f, "PSBT contains an invalid input"; e),
            E::Output(ref e) => write_err!(f, "PSBT contains an invalid output"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V2InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use V2InvalidError as E;

        match *self {
            E::InvalidVersion(_)
            | E::UnsignedTx
            | E::TxVersion
            | E::InputCount
            | E::OutputCount => None,
            E::Input(ref e) => Some(e),
            E::Output(ref e) => Some(e),
        }
    }
}

impl From<input::V2InvalidError> for V2InvalidError {
    fn from(e: input::V2InvalidError) -> Self { Self::Input(e) }
}

impl From<output::V2InvalidError> for V2InvalidError {
    fn from(e: output::V2InvalidError) -> Self { Self::Output(e) }
}

#[cfg(test)]
mod tests {
    use hashes::{hash160, ripemd160, sha256};
    use hex::{test_hex_unwrap as hex, FromHex};

    use super::*;
    use crate::locktime::absolute;
    use crate::psbt::serialize::map::{Input, Output};
    use crate::psbt::serialize::{Deserialize, Serialize};
    use crate::script::{ScriptBuf, ScriptBufExt as _};
    use crate::transaction::{self, OutPoint, TxIn, TxOut};
    use crate::witness::Witness;
    use crate::{Amount, Sequence};

    #[track_caller]
    pub fn hex_psbt(s: &str) -> Result<Psbt, crate::psbt::serialize::error::Error> {
        let r = Vec::from_hex(s);
        match r {
            Err(_e) => panic!("unable to parse hex string {}", s),
            Ok(v) => Psbt::deserialize(&v),
        }
    }

    #[test]
    #[should_panic(expected = "InvalidMagic")]
    fn invalid_vector_1() {
        let hex_psbt = b"0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300";
        Psbt::deserialize(hex_psbt).unwrap();
    }

    #[test]
    fn serialize_then_deserialize_global() {
        let tx_version = transaction::Version::TWO;
        let expected = Psbt {
            unsigned_tx: Some(Transaction {
                version: tx_version,
                lock_time: absolute::LockTime::from_consensus(1257139),
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"
                            .parse()
                            .unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    witness: Witness::default(),
                }],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(99_999_699),
                        script_pubkey: ScriptBuf::from_hex(
                            "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac",
                        )
                        .unwrap(),
                    },
                    TxOut {
                        value: Amount::from_sat(100_000_000),
                        script_pubkey: ScriptBuf::from_hex(
                            "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
                        )
                        .unwrap(),
                    },
                ],
            }),
            version: Version::Zero,
            xpub: Default::default(),
            tx_version: None,
            fallback_lock_time: None,
            input_count: None,
            output_count: None,
            tx_modifiable_flags: None,
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![Input::default()],
            outputs: vec![Output::default(), Output::default()],
        };

        let actual: Psbt = Psbt::deserialize(&expected.serialize()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_psbtkvpair() {
        let expected = raw::Pair {
            key: raw::Key { type_value: 0u64, key_data: vec![42u8, 69u8] },
            value: vec![69u8, 42u8, 4u8],
        };

        let actual = raw::Pair::deserialize(&expected.serialize()).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn deserialize_and_serialize_psbt_with_two_partial_sigs() {
        let hex = "70736274ff0100890200000001207ae985d787dfe6143d5c58fad79cc7105e0e799fcf033b7f2ba17e62d7b3200000000000ffffffff02563d03000000000022002019899534b9a011043c0dd57c3ff9a381c3522c5f27c6a42319085b56ca543a1d6adc020000000000220020618b47a07ebecca4e156edb1b9ea7c24bdee0139fc049237965ffdaf56d5ee73000000000001012b801a0600000000002200201148e93e9315e37dbed2121be5239257af35adc03ffdfc5d914b083afa44dab82202025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee076473044022007e06b362e89912abd4661f47945430739b006a85d1b2a16c01dc1a4bd07acab022061576d7aa834988b7ab94ef21d8eebd996ea59ea20529a19b15f0c9cebe3d8ac01220202b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a473044022002787f926d6817504431ee281183b8119b6845bfaa6befae45e13b6d430c9d2f02202859f149a6cd26ae2f03a107e7f33c7d91730dade305fe077bae677b5d44952a01010547522102b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a21025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee07652ae0001014752210283ef76537f2d58ae3aa3a4bd8ae41c3f230ccadffb1a0bd3ca504d871cff05e7210353d79cc0cb1396f4ce278d005f16d948e02a6aec9ed1109f13747ecb1507b37b52ae00010147522102b3937241777b6665e0d694e52f9c1b188433641df852da6fc42187b5d8a368a321034cdd474f01cc5aa7ff834ad8bcc882a87e854affc775486bc2a9f62e8f49bd7852ae00";
        let psbt: Psbt = hex_psbt(hex).unwrap();
        assert_eq!(hex, psbt.serialize_hex());
    }

    #[test]
    fn serialize_and_deserialize_preimage_psbt() {
        // create a sha preimage map
        let mut sha256_preimages = BTreeMap::new();
        sha256_preimages.insert(sha256::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        sha256_preimages.insert(sha256::Hash::hash(&[1u8]), vec![1u8]);

        // same for hash160
        let mut hash160_preimages = BTreeMap::new();
        hash160_preimages.insert(hash160::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        hash160_preimages.insert(hash160::Hash::hash(&[1u8]), vec![1u8]);

        // same vector as valid_vector_1 from BIPs with added
        let tx_version = transaction::Version::TWO;
        let mut unserialized = Psbt {
            unsigned_tx: Some(Transaction {
                version: tx_version,
                lock_time: absolute::LockTime::from_consensus(1257139),
                input: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                            vout: 0,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                        witness: Witness::default(),
                    }
                ],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(99_999_699),
                        script_pubkey: ScriptBuf::from_hex("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
                    },
                    TxOut {
                        value: Amount::from_sat(100_000_000),
                        script_pubkey: ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
                    },
                ],
            }),
            version: Version::Zero,
            xpub: Default::default(),
            tx_version: None,
            fallback_lock_time: None,
            input_count: None,
            output_count: None,
            tx_modifiable_flags: None,
            proprietary: Default::default(),
            unknown: Default::default(),

            inputs: vec![
                Input {
                    non_witness_utxo: Some(Transaction {
                        version: transaction::Version::ONE,
                        lock_time: absolute::LockTime::ZERO,
                        input: vec![
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptBuf::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985").unwrap(),
                                sequence: Sequence::MAX,
                                witness: Witness::from_slice(&[
                                    hex!("304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01"),
                                    hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"),
                                ]),
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptBuf::from_hex("160014fe3e9ef1a745e974d902c4355943abcb34bd5353").unwrap(),
                                sequence: Sequence::MAX,
                                witness: Witness::from_slice(&[
                                    hex!("3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01"),
                                    hex!("0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3"),
                                ]),
                            }
                        ],
                        output: vec![
                            TxOut {
                                value: Amount::from_sat(200_000_000),
                                script_pubkey: ScriptBuf::from_hex("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac").unwrap(),
                            },
                            TxOut {
                                value: Amount::from_sat(190_303_501_938),
                                script_pubkey: ScriptBuf::from_hex("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                            },
                        ],
                    }),
                    ..Default::default()
                },
            ],
            outputs: vec![
                Output {
                    ..Default::default()
                },
                Output {
                    ..Default::default()
                },
            ],
        };
        unserialized.inputs[0].hash160_preimages = hash160_preimages;
        unserialized.inputs[0].sha256_preimages = sha256_preimages;

        let rtt: Psbt = hex_psbt(&unserialized.serialize_hex()).unwrap();
        assert_eq!(rtt, unserialized);

        // Now add an ripemd160 with incorrect preimage
        let mut ripemd160_preimages = BTreeMap::new();
        ripemd160_preimages.insert(ripemd160::Hash::hash(&[17u8]), vec![18u8]);
        unserialized.inputs[0].ripemd160_preimages = ripemd160_preimages;

        // Now the roundtrip should fail as the preimage is incorrect.
        let rtt: Result<Psbt, _> = hex_psbt(&unserialized.serialize_hex());
        assert!(rtt.is_err());
    }

    #[test]
    fn serialize_and_deserialize_proprietary() {
        let mut psbt: Psbt = hex_psbt("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
        psbt.proprietary.insert(
            raw::ProprietaryKey { prefix: b"test".to_vec(), subtype: 0u64, key: b"test".to_vec() },
            b"test".to_vec(),
        );
        assert!(!psbt.proprietary.is_empty());
        let rtt: Psbt = hex_psbt(&psbt.serialize_hex()).unwrap();
        assert!(!rtt.proprietary.is_empty());
    }
}
