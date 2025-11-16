//! The segregated witness program as defined by [BIP-0141].
//!
//! > A scriptPubKey (or redeemScript as defined in BIP-0016/P2SH) that consists of a 1-byte push
//! > opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new special
//! > meaning. The value of the first push is called the "version byte". The following byte
//! > vector pushed is called the "witness program".
//!
//! [BIP-0141]: <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>

use core::convert::Infallible;
use core::fmt;

use internals::array_vec::ArrayVec;
use secp256k1::{Secp256k1, Verification};

use super::witness_version::WitnessVersion;
use super::{PushBytes, WScriptHash, WitnessScript, WitnessScriptSizeError};
use crate::crypto::key::{CompressedPublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey};
use crate::script::WitnessScriptExt as _;
use crate::taproot::TapNodeHash;

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
        use Error::*;

        let program_len = bytes.len();
        if program_len < MIN_SIZE || program_len > MAX_SIZE {
            return Err(InvalidLength(program_len));
        }

        // Specific SegWit v0 check. These addresses can never spend funds sent to them.
        if version == WitnessVersion::V0 && (program_len != 20 && program_len != 32) {
            return Err(InvalidSegwitV0Length(program_len));
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
    pub fn p2wpkh(pk: CompressedPublicKey) -> Self {
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
    pub fn p2tr<C: Verification, K: Into<UntweakedPublicKey>>(
        secp: &Secp256k1<C>,
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let internal_key = internal_key.into();
        let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
        let pubkey = output_key.as_x_only_public_key().serialize();
        Self::new_p2tr(pubkey)
    }

    /// Constructs a new [`WitnessProgram`] from a tweaked key for a P2TR output.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        let pubkey = output_key.as_x_only_public_key().serialize();
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
        use Error::*;

        match *self {
            InvalidLength(len) =>
                write!(f, "witness program must be between 2 and 40 bytes: length={}", len),
            InvalidSegwitV0Length(len) =>
                write!(f, "a v0 witness program must be either 20 or 32 bytes: length={}", len),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            InvalidLength(_) | InvalidSegwitV0Length(_) => None,
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
}
