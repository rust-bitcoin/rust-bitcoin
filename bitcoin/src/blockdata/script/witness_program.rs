//! The segregated witness program as defined by [BIP-0141].
//!
//! > A scriptPubKey (or redeemScript as defined in BIP-0016/P2SH) that consists of a 1-byte push
//! > opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new special
//! > meaning. The value of the first push is called the "version byte". The following byte
//! > vector pushed is called the "witness program".
//!
//! [BIP-0141]: <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>

use internals::array_vec::ArrayVec;

use super::witness_version::WitnessVersion;
use super::{PushBytes, WScriptHash, WitnessScript, WitnessScriptSizeError};
use crate::crypto::key::{FullPublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey};
use crate::script::WitnessScriptExt as _;
use crate::taproot::TapNodeHash;

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::Error;

/// The minimum byte size of a segregated witness program.
pub const MIN_SIZE: usize = 2;

/// The maximum byte size of a segregated witness program.
pub const MAX_SIZE: usize = 40;

/// The P2A program which is given by 0x4e73.
pub(crate) const P2A_PROGRAM: [u8; 2] = [78, 115];

/// The segregated witness program.
///
/// The segregated witness program is technically only the program bytes _excluding_ the witness
/// version, however we maintain length invariants on the `program` that are governed by the version
/// number, therefore we carry the version number around along with the program bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessProgram {
    /// The SegWit version associated with this witness program.
    version: WitnessVersion,
    /// The witness program (between 2 and 40 bytes).
    program: ArrayVec<u8, MAX_SIZE>,
}

impl WitnessProgram {
    /// Constructs a new witness program, copying the content from the given byte slice.
    pub fn new(version: WitnessVersion, bytes: &[u8]) -> Result<Self, Error> {
        let program_len = bytes.len();
        if program_len < MIN_SIZE || program_len > MAX_SIZE {
            return Err(Error::InvalidLength(program_len));
        }

        // Specific SegWit v0 check. These addresses can never spend funds sent to them.
        if version == WitnessVersion::V0 && (program_len != 20 && program_len != 32) {
            return Err(Error::InvalidSegwitV0Length(program_len));
        }

        let program = ArrayVec::from_slice(bytes);
        Ok(Self { version, program })
    }

    /// Constructs a new [`WitnessProgram`] from a 20 byte pubkey hash.
    fn new_p2wpkh(program: [u8; 20]) -> Self {
        Self { version: WitnessVersion::V0, program: ArrayVec::from_slice(&program) }
    }

    /// Constructs a new [`WitnessProgram`] from a 32 byte script hash.
    fn new_p2wsh(program: [u8; 32]) -> Self {
        Self { version: WitnessVersion::V0, program: ArrayVec::from_slice(&program) }
    }

    /// Constructs a new [`WitnessProgram`] from a 32 byte serialized Taproot x-only pubkey.
    fn new_p2tr(program: [u8; 32]) -> Self {
        Self { version: WitnessVersion::V1, program: ArrayVec::from_slice(&program) }
    }

    /// Constructs a new [`WitnessProgram`] from `pk` for a P2WPKH output.
    pub fn p2wpkh(pk: FullPublicKey) -> Self {
        let hash = pk.wpubkey_hash();
        Self::new_p2wpkh(hash.to_byte_array())
    }

    /// Constructs a new [`WitnessProgram`] from `script` for a P2WSH output.
    pub fn p2wsh(script: &WitnessScript) -> Result<Self, WitnessScriptSizeError> {
        script.wscript_hash().map(Self::p2wsh_from_hash)
    }

    /// Constructs a new [`WitnessProgram`] from `script` for a P2WSH output.
    pub fn p2wsh_from_hash(hash: WScriptHash) -> Self { Self::new_p2wsh(hash.to_byte_array()) }

    /// Constructs a new [`WitnessProgram`] from an untweaked key for a P2TR output.
    ///
    /// This function applies BIP-0341 key-tweaking to the untweaked
    /// key using the merkle root, if it's present.
    pub fn p2tr<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let internal_key = internal_key.into();
        let output_key = internal_key.tap_tweak(merkle_root);
        let (pubkey, _) = output_key.as_x_only_public_key().serialize();
        Self::new_p2tr(pubkey)
    }

    /// Constructs a new [`WitnessProgram`] from a tweaked key for a P2TR output.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        let (pubkey, _) = output_key.as_x_only_public_key().serialize();
        Self::new_p2tr(pubkey)
    }

    /// Constructs a new [`WitnessProgram`] for a P2A output.
    pub const fn p2a() -> Self {
        Self { version: WitnessVersion::V1, program: ArrayVec::from_slice(&P2A_PROGRAM) }
    }

    /// Returns the witness program version.
    pub fn version(&self) -> WitnessVersion { self.version }

    /// Returns the witness program.
    pub fn program(&self) -> &PushBytes {
        self.program
            .as_slice()
            .try_into()
            .expect("witness programs are always smaller than max size of PushBytes")
    }

    /// Returns true if this witness program is for a P2WPKH output.
    pub fn is_p2wpkh(&self) -> bool {
        self.version == WitnessVersion::V0 && self.program.len() == 20
    }

    /// Returns true if this witness program is for a P2WSH output.
    pub fn is_p2wsh(&self) -> bool {
        self.version == WitnessVersion::V0 && self.program.len() == 32
    }

    /// Returns true if this witness program is for a P2TR output.
    pub fn is_p2tr(&self) -> bool { self.version == WitnessVersion::V1 && self.program.len() == 32 }

    /// Returns true if this witness program is for a P2A output.
    pub fn is_p2a(&self) -> bool {
        self.version == WitnessVersion::V1 && self.program == P2A_PROGRAM
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for WitnessProgram {
    /// Serializes a [`WitnessProgram`].
    ///
    /// Depending on the data format, the underlying `program` bytes are serialized differently:
    /// - **Human-readable formats** (e.g., JSON): The `program` bytes are serialized as a hex string.
    /// - **Binary formats** (e.g., Bincode): The `program` bytes are serialized directly as raw bytes.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use internals::serde::SerializeBytesAsHex;
        use serde::ser::SerializeStruct;

        let human_readable = serializer.is_human_readable();
        let mut state = serializer.serialize_struct("WitnessProgram", 2)?;
        state.serialize_field("version", &self.version)?;
        if human_readable {
            state.serialize_field("program", &SerializeBytesAsHex(self.program.as_slice()))?;
        } else {
            state.serialize_field("program", &self.program)?;
        }
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for WitnessProgram {
    /// Deserializes a [`WitnessProgram`].
    ///
    /// ### Errors
    /// Returns a deserialization error if:
    /// - Mandatory fields (`version` or `program`) are missing or duplicated.
    /// - The hex string in a human-readable format is malformed or invalidly sized.
    /// - The combination of `version` and `program` fails validation in `WitnessProgram::new`.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;

        use serde::de;

        struct Program(ArrayVec<u8, MAX_SIZE>);

        impl<'de> serde::Deserialize<'de> for Program {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    struct HexVisitor;

                    impl de::Visitor<'_> for HexVisitor {
                        type Value = Program;

                        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                            write!(f, "a hex string encoding {} to {} bytes", MIN_SIZE, MAX_SIZE)
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: de::Error,
                        {
                            let bytes = hex::decode_to_vec(v).map_err(E::custom)?;
                            if bytes.len() > MAX_SIZE {
                                return Err(E::invalid_length(bytes.len(), &self));
                            }
                            Ok(Program(ArrayVec::from_slice(&bytes)))
                        }
                    }

                    deserializer.deserialize_str(HexVisitor)
                } else {
                    let av = ArrayVec::<u8, MAX_SIZE>::deserialize(deserializer)?;
                    Ok(Self(av))
                }
            }
        }

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Version,
            Program,
        }

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = WitnessProgram;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a WitnessProgram struct with 'version' and 'program' fields")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let version: WitnessVersion =
                    seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let program: Program =
                    seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;
                WitnessProgram::new(version, &program.0).map_err(de::Error::custom)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut version: Option<WitnessVersion> = None;
                let mut program: Option<Program> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Version => {
                            if version.is_some() {
                                return Err(de::Error::duplicate_field("version"));
                            }
                            version = Some(map.next_value()?);
                        }
                        Field::Program => {
                            if program.is_some() {
                                return Err(de::Error::duplicate_field("program"));
                            }
                            program = Some(map.next_value::<Program>()?);
                        }
                    }
                }

                let version = version.ok_or_else(|| de::Error::missing_field("version"))?;
                let program = program.ok_or_else(|| de::Error::missing_field("program"))?;

                WitnessProgram::new(version, &program.0).map_err(de::Error::custom)
            }
        }

        const FIELDS: &[&str] = &["version", "program"];
        deserializer.deserialize_struct("WitnessProgram", FIELDS, Visitor)
    }
}

/// Error types for witness programs.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    /// Witness program error.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum Error {
        /// The witness program must be between 2 and 40 bytes in length.
        InvalidLength(usize),
        /// A v0 witness program must be either of length 20 or 32.
        InvalidSegwitV0Length(usize),
    }

    impl From<Infallible> for Error {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::InvalidLength(len) =>
                    write!(f, "witness program must be between 2 and 40 bytes: length={}", len),
                Self::InvalidSegwitV0Length(len) =>
                    write!(f, "a v0 witness program must be either 20 or 32 bytes: length={}", len),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for Error {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::InvalidLength(_) | Self::InvalidSegwitV0Length(_) => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_program_is_too_short() {
        let arbitrary_bytes = [0x00; MIN_SIZE - 1];
        assert!(WitnessProgram::new(WitnessVersion::V15, &arbitrary_bytes).is_err()); // Arbitrary version
    }

    #[test]
    fn witness_program_is_too_long() {
        let arbitrary_bytes = [0x00; MAX_SIZE + 1];
        assert!(WitnessProgram::new(WitnessVersion::V15, &arbitrary_bytes).is_err()); // Arbitrary version
    }

    #[test]
    fn valid_v0_witness_programs() {
        let arbitrary_bytes = [0x00; MAX_SIZE];

        for size in MIN_SIZE..=MAX_SIZE {
            let program = WitnessProgram::new(WitnessVersion::V0, &arbitrary_bytes[..size]);

            if size == 20 {
                assert!(program.expect("valid witness program").is_p2wpkh());
                continue;
            }
            if size == 32 {
                assert!(program.expect("valid witness program").is_p2wsh());
                continue;
            }
            assert!(program.is_err());
        }
    }

    #[test]
    fn valid_v1_witness_programs() {
        let arbitrary_bytes = [0x00; 32];
        assert!(WitnessProgram::new(WitnessVersion::V1, &arbitrary_bytes)
            .expect("valid witness program")
            .is_p2tr());

        let p2a_bytes = [78, 115];
        assert!(WitnessProgram::new(WitnessVersion::V1, &p2a_bytes)
            .expect("valid witness program")
            .is_p2a());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn roundtrip_v0_p2wpkh() {
        let want = WitnessProgram::new(WitnessVersion::V0, &[0xAB; 20]).unwrap();
        let json = serde_json::to_string(&want).expect("serialize");
        let got: WitnessProgram = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(got, want);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn roundtrip_v1_p2tr() {
        let want = WitnessProgram::new(WitnessVersion::V1, &[0xCD; 32]).unwrap();
        let json = serde_json::to_string(&want).expect("serialize");
        let got: WitnessProgram = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(want, got);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_seq_format() {
        let want = WitnessProgram::new(WitnessVersion::V0, &[0xAB; 20]).unwrap();
        let encoded = bincode::serialize(&want).expect("serialize");
        let got: WitnessProgram = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(got, want);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_duplicate_version_field_is_err() {
        let prog = "00".repeat(20);
        let json = format!(r#"{{"version":0,"version":0,"program":"{prog}"}}"#);
        assert!(serde_json::from_str::<WitnessProgram>(&json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_duplicate_program_field_is_err() {
        let prog = "00".repeat(20);
        let json = format!(r#"{{"version":0,"program":"{prog}","program":"{prog}"}}"#);
        assert!(serde_json::from_str::<WitnessProgram>(&json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_missing_version_field_is_err() {
        let prog = "00".repeat(20);
        let json = format!(r#"{{"program":"{prog}"}}"#);
        assert!(serde_json::from_str::<WitnessProgram>(&json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_missing_program_field_is_err() {
        let json = r#"{"version":0}"#;
        assert!(serde_json::from_str::<WitnessProgram>(json).is_err());
    }

    // WitnessProgram::new validation is still enforced after deserialization.
    // A V0 program of length 21 is structurally valid JSON but semantically invalid.
    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_invalid_v0_program_length_is_err() {
        let prog = "aa".repeat(21);
        let json = format!(r#"{{"version":0,"program":"{prog}"}}"#);
        assert!(serde_json::from_str::<WitnessProgram>(&json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_human_readable_uses_hex_for_program() {
        let original = WitnessProgram::new(WitnessVersion::V0, &[0xAB; 20]).unwrap();
        let got = serde_json::to_string(&original).expect("serialize");
        let want = format!(r#"{{"version":0,"program":"{}"}}"#, "ab".repeat(20));
        assert_eq!(got, want);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_human_readable_hex_program() {
        let json = format!(r#"{{"version":1,"program":"{}"}}"#, "cd".repeat(32));
        let got: WitnessProgram = serde_json::from_str(&json).expect("deserialize");
        let want = WitnessProgram::new(WitnessVersion::V1, &[0xCD; 32]).unwrap();
        assert_eq!(got, want);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_invalid_hex_program_is_err() {
        // Odd-length hex string.
        let json = r#"{"version":0,"program":"abc"}"#;
        assert!(serde_json::from_str::<WitnessProgram>(json).is_err());

        // Non-hex character.
        let json = r#"{"version":0,"program":"zz"}"#;
        assert!(serde_json::from_str::<WitnessProgram>(json).is_err());
    }
}
