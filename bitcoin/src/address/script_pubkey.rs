// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scriptPubkey script extensions.

use secp256k1::{Secp256k1, Verification};

use crate::internal_macros::define_extension_trait;
use crate::key::{
    PubkeyHash, PublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey, WPubkeyHash,
};
use crate::opcodes::all::*;
use crate::script::witness_program::{WitnessProgram, P2A_PROGRAM};
use crate::script::witness_version::WitnessVersion;
use crate::script::{Builder, PushBytes, Script, ScriptBuf, ScriptHash, WScriptHash};
use crate::taproot::TapNodeHash;

define_extension_trait! {
    /// Extension functionality to add scriptPubkey support to the [`ScriptBuf`] type.
    pub trait ScriptBufExt impl for ScriptBuf {
        /// Generates P2PK-type of scriptPubkey.
        fn new_p2pk(pubkey: PublicKey) -> Self {
            Builder::new().push_key(pubkey).push_opcode(OP_CHECKSIG).into_script()
        }

        /// Generates P2PKH-type of scriptPubkey.
        fn new_p2pkh(pubkey_hash: PubkeyHash) -> Self {
            Builder::new()
                .push_opcode(OP_DUP)
                .push_opcode(OP_HASH160)
                .push_slice(pubkey_hash)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_CHECKSIG)
                .into_script()
        }

        /// Generates P2SH-type of scriptPubkey with a given hash of the redeem script.
        fn new_p2sh(script_hash: ScriptHash) -> Self {
            Builder::new()
                .push_opcode(OP_HASH160)
                .push_slice(script_hash)
                .push_opcode(OP_EQUAL)
                .into_script()
        }

        /// Generates P2WPKH-type of scriptPubkey.
        fn new_p2wpkh(pubkey_hash: WPubkeyHash) -> Self {
            // pubkey hash is 20 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv0)
            new_witness_program_unchecked(WitnessVersion::V0, pubkey_hash)
        }

        /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
        fn new_p2wsh(script_hash: WScriptHash) -> Self {
            // script hash is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv0)
            new_witness_program_unchecked(WitnessVersion::V0, script_hash)
        }

        /// Generates P2TR for script spending path using an internal public key and some optional
        /// script tree Merkle root.
        fn new_p2tr<C: Verification, K: Into<UntweakedPublicKey>>(
            secp: &Secp256k1<C>,
            internal_key: K,
            merkle_root: Option<TapNodeHash>,
        ) -> Self {
            let internal_key = internal_key.into();
            let (output_key, _) = internal_key.tap_tweak(secp, merkle_root);
            // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
            new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
        }

        /// Generates P2TR for key spending path for a known [`TweakedPublicKey`].
        fn new_p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
            // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
            new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
        }

        /// Generates pay to anchor output.
        fn new_p2a() -> Self {
            new_witness_program_unchecked(WitnessVersion::V1, P2A_PROGRAM)
        }

        /// Generates P2WSH-type of scriptPubkey with a given [`WitnessProgram`].
        fn new_witness_program(witness_program: &WitnessProgram) -> Self {
            Builder::new()
                .push_opcode(witness_program.version().into())
                .push_slice(witness_program.program())
                .into_script()
        }
    }
}

/// Generates P2WSH-type of scriptPubkey with a given [`WitnessVersion`] and the program bytes.
/// Does not do any checks on version or program length.
///
/// Convenience method used by `new_p2a`, `new_p2wpkh`, `new_p2wsh`, `new_p2tr`, and `new_p2tr_tweaked`.
pub(super) fn new_witness_program_unchecked<T: AsRef<PushBytes>>(
    version: WitnessVersion,
    program: T,
) -> ScriptBuf {
    let program = program.as_ref();
    debug_assert!(program.len() >= 2 && program.len() <= 40);
    // In SegWit v0, the program must be either 20 bytes (P2WPKH) or 32 bytes (P2WSH) long.
    debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
    Builder::new().push_opcode(version.into()).push_slice(program).into_script()
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Script {}
    impl Sealed for super::ScriptBuf {}
    impl Sealed for super::Builder {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::ScriptExt as _;

    #[test]
    fn shortest_witness_program() {
        let bytes = [0x00; 2]; // Arbitrary bytes, witprog must be between 2 and 40.
        let version = WitnessVersion::V15; // Arbitrary version number, intentionally not 0 or 1.

        let p = WitnessProgram::new(version, &bytes).expect("failed to create witness program");
        let script = ScriptBuf::new_witness_program(&p);

        assert_eq!(script.witness_version(), Some(version));
    }

    #[test]
    fn longest_witness_program() {
        let bytes = [0x00; 40]; // Arbitrary bytes, witprog must be between 2 and 40.
        let version = WitnessVersion::V16; // Arbitrary version number, intentionally not 0 or 1.

        let p = WitnessProgram::new(version, &bytes).expect("failed to create witness program");
        let script = ScriptBuf::new_witness_program(&p);

        assert_eq!(script.witness_version(), Some(version));
    }
}
