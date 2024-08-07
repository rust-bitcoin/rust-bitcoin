// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scriptPubkey script extensions.

use secp256k1::{Secp256k1, Verification};

use crate::internal_macros::define_extension_trait;
use crate::key::{
    PubkeyHash, PublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey, WPubkeyHash,
    XOnlyPublicKey,
};
use crate::opcodes::all::*;
use crate::script::witness_program::WitnessProgram;
use crate::script::witness_version::WitnessVersion;
use crate::script::{
    self, Builder, PushBytes, RedeemScriptSizeError, Script, ScriptBuf, ScriptHash, WScriptHash,
    WitnessScriptSizeError,
};
use crate::taproot::TapNodeHash;

define_extension_trait! {
    /// Extension functionality to add scriptPubkey support to the [`Builder`] type.
    pub trait BuilderExt impl for Builder {
        /// Adds instructions to push a public key onto the stack.
        fn push_key(self: Self, key: PublicKey) -> Builder {
            if key.compressed {
                self.push_slice(key.inner.serialize())
            } else {
                self.push_slice(key.inner.serialize_uncompressed())
            }
        }

        /// Adds instructions to push an XOnly public key onto the stack.
        fn push_x_only_key(self: Self, x_only_key: XOnlyPublicKey) -> Builder {
            self.push_slice(x_only_key.serialize())
        }
    }
}

define_extension_trait! {
    /// Extension functionality to add scriptPubkey support to the [`Script`] type.
    pub trait ScriptExt impl for Script {
        /// Computes the P2WSH output corresponding to this witnessScript (aka the "witness redeem
        /// script").
        fn to_p2wsh(self: &Self) -> Result<ScriptBuf, WitnessScriptSizeError> {
            self.wscript_hash().map(ScriptBuf::new_p2wsh)
        }

        /// Computes P2TR output with a given internal key and a single script spending path equal to
        /// the current script, assuming that the script is a Tapscript.
        fn to_p2tr<C: Verification>(
            self: &Self,
            secp: &Secp256k1<C>,
            internal_key: UntweakedPublicKey,
        ) -> ScriptBuf {
            let leaf_hash = self.tapscript_leaf_hash();
            let merkle_root = TapNodeHash::from(leaf_hash);
            ScriptBuf::new_p2tr(secp, internal_key, Some(merkle_root))
        }

        /// Computes the P2SH output corresponding to this redeem script.
        fn to_p2sh(self: &Self) -> Result<ScriptBuf, RedeemScriptSizeError> {
            self.script_hash().map(ScriptBuf::new_p2sh)
        }

        /// Returns the script code used for spending a P2WPKH output if this script is a script pubkey
        /// for a P2WPKH output. The `scriptCode` is described in [BIP143].
        ///
        /// [BIP143]: <https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki>
        fn p2wpkh_script_code(self: &Self) -> Option<ScriptBuf> {
            if self.is_p2wpkh() {
                // The `self` script is 0x00, 0x14, <pubkey_hash>
                let bytes = &self.as_bytes()[2..];
                let wpkh = WPubkeyHash::from_slice(bytes).expect("length checked in is_p2wpkh()");
                Some(script::p2wpkh_script_code(wpkh))
            } else {
                None
            }
        }

        /// Checks whether a script pubkey is a P2PK output.
        ///
        /// You can obtain the public key, if its valid,
        /// by calling [`p2pk_public_key()`](Self::p2pk_public_key)
        fn is_p2pk(self: &Self) -> bool { self.p2pk_pubkey_bytes().is_some() }

        /// Returns the public key if this script is P2PK with a **valid** public key.
        ///
        /// This may return `None` even when [`is_p2pk()`](Self::is_p2pk) returns true.
        /// This happens when the public key is invalid (e.g. the point not being on the curve).
        /// In this situation the script is unspendable.
        fn p2pk_public_key(self: &Self) -> Option<PublicKey> {
            PublicKey::from_slice(self.p2pk_pubkey_bytes()?).ok()
        }
    }
}

define_extension_trait! {
    pub(crate) trait ScriptExtPrivate impl for Script {
        /// Returns the bytes of the (possibly invalid) public key if this script is P2PK.
        fn p2pk_pubkey_bytes(self: &Self) -> Option<&[u8]> {
            match self.len() {
                67 if self.as_bytes()[0] == OP_PUSHBYTES_65.to_u8()
                    && self.as_bytes()[66] == OP_CHECKSIG.to_u8() =>
                    Some(&self.as_bytes()[1..66]),
                35 if self.as_bytes()[0] == OP_PUSHBYTES_33.to_u8()
                    && self.as_bytes()[34] == OP_CHECKSIG.to_u8() =>
                    Some(&self.as_bytes()[1..34]),
                _ => None,
            }
        }
    }
}

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
        fn new_p2tr<C: Verification>(
            secp: &Secp256k1<C>,
            internal_key: UntweakedPublicKey,
            merkle_root: Option<TapNodeHash>,
        ) -> Self {
            let (output_key, _) = internal_key.tap_tweak(secp, merkle_root);
            // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
            new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
        }

        /// Generates P2TR for key spending path for a known [`TweakedPublicKey`].
        fn new_p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
            // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
            new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
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
/// Convenience method used by `new_p2wpkh`, `new_p2wsh`, `new_p2tr`, and `new_p2tr_tweaked`.
pub(super) fn new_witness_program_unchecked<T: AsRef<PushBytes>>(
    version: WitnessVersion,
    program: T,
) -> ScriptBuf {
    let program = program.as_ref();
    debug_assert!(program.len() >= 2 && program.len() <= 40);
    // In segwit v0, the program must be 20 or 32 bytes long.
    debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
    Builder::new().push_opcode(version.into()).push_slice(program).into_script()
}

#[cfg(test)]
mod tests {
    use super::*;

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
