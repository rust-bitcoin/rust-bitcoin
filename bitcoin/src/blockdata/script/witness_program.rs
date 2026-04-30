//! The segregated witness program as defined by [BIP-0141].
//!
//! > A scriptPubKey (or redeemScript as defined in BIP-0016/P2SH) that consists of a 1-byte push
//! > opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new special
//! > meaning. The value of the first push is called the "version byte". The following byte
//! > vector pushed is called the "witness program".
//!
//! [BIP-0141]: <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>

use super::witness_version::WitnessVersion;
use super::PushBytes;
use crate::crypto::key::{TapTweak, UntweakedPublicKey};
use crate::taproot::TapNodeHash;

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::Error;
#[doc(inline)]
pub use addresses::witness_program::{WitnessProgram, MAX_SIZE, MIN_SIZE};

/// The P2A program which is given by 0x4e73.
pub(crate) const P2A_PROGRAM: [u8; 2] = [78, 115];

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`WitnessProgram`] type.
    pub trait WitnessProgramExt impl for WitnessProgram {
        /// Constructs a new [`WitnessProgram`] from an untweaked key for a P2TR output.
        ///
        /// This function applies BIP-0341 key-tweaking to the untweaked
        /// key using the merkle root, if it's present.
        fn p2tr<K: Into<UntweakedPublicKey>>(
            internal_key: K,
            merkle_root: Option<TapNodeHash>,
        ) -> Self {
            let internal_key = internal_key.into();
            let output_key = internal_key.tap_tweak(merkle_root);
            let (pubkey, _) = output_key.as_x_only_public_key().serialize();
            Self::new(WitnessVersion::V1, &pubkey)
                .expect("pubkey is valid size range for witness program")
        }

        /// Returns the witness program.
        fn program(&self) -> &PushBytes {
            self.as_program_slice()
                .try_into()
                .expect("witness programs are always smaller than max size of PushBytes")
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::WitnessProgram {}
}

/// Error types for witness programs.
pub mod error {
    #[doc(no_inline)]
    pub use addresses::witness_program::Error;
}
