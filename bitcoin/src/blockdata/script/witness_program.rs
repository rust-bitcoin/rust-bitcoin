//! The segregated witness program as defined by [BIP141].
//!
//! > A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that consists of a 1-byte push
//! > opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new special
//! > meaning. The value of the first push is called the "version byte". The following byte
//! > vector pushed is called the "witness program".
//!
//! [BIP141]: <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>

use core::fmt;

use hashes::Hash as _;
use internals::array_vec::ArrayVec;
use secp256k1::{Secp256k1, Verification};

use crate::blockdata::script::witness_version::WitnessVersion;
use crate::blockdata::script::{PushBytes, Script};
use crate::crypto::key::{CompressedPublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey};
use crate::taproot::TapNodeHash;

/// The minimum byte size of a segregated witness program.
pub const MIN_SIZE: usize = 2;

/// The maximum byte size of a segregated witness program.
pub const MAX_SIZE: usize = 40;

/// The segregated witness program.
///
/// The segregated witness program is technically only the program bytes _excluding_ the witness
/// version, however we maintain length invariants on the `program` that are governed by the version
/// number, therefore we carry the version number around along with the program bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessProgram {
    /// The segwit version associated with this witness program.
    version: WitnessVersion,
    /// The witness program (between 2 and 40 bytes).
    program: ArrayVec<u8, MAX_SIZE>,
}

impl WitnessProgram {
    /// Creates a new witness program, copying the content from the given byte slice.
    pub fn new(version: WitnessVersion, bytes: &[u8]) -> Result<Self, Error> {
        use Error::*;

        let program_len = bytes.len();
        if program_len < MIN_SIZE || program_len > MAX_SIZE {
            return Err(InvalidLength(program_len));
        }

        // Specific segwit v0 check. These addresses can never spend funds sent to them.
        if version == WitnessVersion::V0 && (program_len != 20 && program_len != 32) {
            return Err(InvalidSegwitV0Length(program_len));
        }

        let program = ArrayVec::from_slice(bytes);
        Ok(WitnessProgram { version, program })
    }

    /// Creates a [`WitnessProgram`] from a 20 byte pubkey hash.
    fn new_p2wpkh(program: [u8; 20]) -> Self {
        WitnessProgram { version: WitnessVersion::V0, program: ArrayVec::from_slice(&program) }
    }

    /// Creates a [`WitnessProgram`] from a 32 byte script hash.
    fn new_p2wsh(program: [u8; 32]) -> Self {
        WitnessProgram { version: WitnessVersion::V0, program: ArrayVec::from_slice(&program) }
    }

    /// Creates a [`WitnessProgram`] from a 32 byte serialize taproot xonly pubkey.
    fn new_p2tr(program: [u8; 32]) -> Self {
        WitnessProgram { version: WitnessVersion::V1, program: ArrayVec::from_slice(&program) }
    }

    /// Creates a [`WitnessProgram`] from `pk` for a P2WPKH output.
    pub fn p2wpkh(pk: &CompressedPublicKey) -> Self {
        let hash = pk.wpubkey_hash();
        WitnessProgram::new_p2wpkh(hash.to_byte_array())
    }

    /// Creates a [`WitnessProgram`] from `script` for a P2WSH output.
    pub fn p2wsh(script: &Script) -> Self {
        let hash = script.wscript_hash();
        WitnessProgram::new_p2wsh(hash.to_byte_array())
    }

    /// Creates a pay to taproot address from an untweaked key.
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
        let pubkey = output_key.to_inner().serialize();
        WitnessProgram::new_p2tr(pubkey)
    }

    /// Creates a pay to taproot address from a pre-tweaked output key.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        let pubkey = output_key.to_inner().serialize();
        WitnessProgram::new_p2tr(pubkey)
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

    /// Returns true if this witness program is for a P2WPSH output.
    pub fn is_p2wsh(&self) -> bool {
        self.version == WitnessVersion::V0 && self.program.len() == 32
    }

    /// Returns true if this witness program is for a P2TR output.
    pub fn is_p2tr(&self) -> bool { self.version == WitnessVersion::V1 && self.program.len() == 32 }
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

internals::impl_from_infallible!(Error);

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
