// SPDX-License-Identifier: CC0-1.0
// Written by the rust-bitcoin developers.

//! [BIP143] Transaction Signature Verification for Version 0 Witness Program
//!
//! [BIP143]: <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
//!

use core::fmt;

use crate::blockdata::opcodes::all::*;
use crate::consensus::{encode, Decodable, Encodable};
use crate::consensus::encode::WriteExt;
use crate::io;
use crate::prelude::*;
use crate::script::{Builder, Script, ScriptBuf};

/// The scriptCode as defined in [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki).
#[derive(Default, Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct ScriptCode(ScriptBuf);

impl ScriptCode {
    /// Returns the script code used for spending a P2WPKH output if this script is a script pubkey
    /// for a P2WPKH output.
    pub fn new_p2wpkh(wpkh: &Script) -> Option<Self> {
        if !wpkh.is_v0_p2wpkh() {
            return None
        }
        // From BIP143: For P2WPKH witness program, the scriptCode is 0x1976a914{20-byte-pubkey-hash}88ac
        let script = Builder::new()
            .push_opcode(OP_PUSHBYTES_25)
            .push_opcode(OP_DUP)               // 0x76
            .push_opcode(OP_HASH160)           // 0xa9
            // push_slice pushes OP_PUSHBYTES_20 (0x14)
            .push_slice(&wpkh.as_bytes()[2..]) // The `wpkh` script is 0x00, 0x14, <pubkey_hash>
            .push_opcode(OP_EQUALVERIFY)       // 0x88
            .push_opcode(OP_CHECKSIG)          // 0xac
            .into_script();

        Some(ScriptCode(script))
    }

    /// Returns the script code used for spending a P2WSH output using `witness` (redeem script).
    ///
    /// We do not currently support `OP_CODESEPARATOR`.
    pub fn new_p2wsh(witness: &Script) -> Self {
        // From BIP143:
        // - if the witnessScript does not contain any OP_CODESEPARATOR, the scriptCode is the
        // witnessScript serialized as scripts inside CTxOut.
        // - if the witnessScript contains any OP_CODESEPARATOR, the scriptCode is the witnessScript
        // but removing everything up to and including the last executed OP_CODESEPARATOR before the
        // signature checking opcode being executed, serialized as scripts inside CTxOut. (The exact
        // semantics is demonstrated in the examples below)

        // This function is implemented according to the BIP iff OP_CODESEPARATOR is not present.

        // We can't use Builder::push_slice() because it pushes extra bytes for witnesses over 76
        // bytes long.

        let mut v = vec![0];
        v[0] = witness.len() as u8;
        v.extend_from_slice(witness.as_bytes());

        let buf = ScriptBuf::from_bytes(v);
        ScriptCode(buf)
    }

    /// Returns the script code used for spending a P2WSH output using `witness` (redeem script)
    /// after first removing everything upto and including the first `OP_CODESEPARATOR`.
    ///
    /// This is a hack, we should implement a full script evaluation engine.
    pub fn __new_p2wsh_remove_op_codeseparator(witness: &Script) -> Self {
        let bytes = witness.to_bytes();
        let mut iter = bytes.iter();
        iter.position(|&x| x == OP_CODESEPARATOR.to_u8());
        let stripped: Vec<u8> = iter.copied().collect();

        // We can't use Builder::push_slice() because it pushes extra bytes for witnesses over 76
        // bytes long.

        let mut v = vec![0];
        v[0] = stripped.len() as u8;
        v.extend_from_slice(&stripped);

        let buf = ScriptBuf::from_bytes(v);
        ScriptCode(buf)
    }

    /// Returns a [`ScriptCode`] directly from `raw_script`
    ///
    /// Assumes the given script is the correctly constructed script code. Useful for custom cases
    /// with code separator, or in cases where the user wants to explicitly trust the given script as
    /// a correctly computed script code.
    pub fn dangerous_assume_script_code(raw_script: ScriptBuf) -> Self {
        ScriptCode(raw_script)
    }
}

impl fmt::LowerHex for ScriptCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0.as_script(), f)
    }
}

impl fmt::UpperHex for ScriptCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0.as_script(), f)
    }
}

impl Encodable for ScriptCode {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.emit_slice(self.0.as_script().as_bytes())?;
        Ok(self.0.len())
    }
}

impl Decodable for ScriptCode {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let v: Vec<u8> = Decodable::consensus_decode_from_finite_reader(r)?;
        Ok(ScriptCode(ScriptBuf::from(v)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus;
    use crate::hashes::hex::FromHex;

    // TODO: Once we support `OP_CODESEPARATOR` these tests should be made to pass without the
    // `ScriptCode::__new_p2wsh_remove_op_codeseparator` method.

    #[test]
    fn bip143_p2wsh_part_1() {
        //     witnessScript: 21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
        //                    <026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae> CHECKSIGVERIFY CODESEPARATOR <0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465> CHECKSIG
        let redeem_script = ScriptBuf::from_hex("21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac").expect("failed to parse redeem_script script");

        //   scriptCode:  4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
        //                                                                                        ^^
        //                (please note that the not-yet-executed OP_CODESEPARATOR is not removed from the scriptCode)
        let script_code = ScriptCode::new_p2wsh(&redeem_script);
        assert_eq!(consensus::serialize_hex(&script_code), "4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");

        //   scriptCode:  23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
        //                (everything up to the last executed OP_CODESEPARATOR, including that OP_CODESEPARATOR, are removed)
        let script_code = ScriptCode::__new_p2wsh_remove_op_codeseparator(&redeem_script);
        assert_eq!(consensus::serialize_hex(&script_code), "23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
    }

    #[test]
    fn bip143_p2wsh_part_2() {
        //     witnessScript:0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
        //                   0 IF CODESEPARATOR ENDIF <0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98> CHECKSIG
        let redeem_script = ScriptBuf::from_hex("0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac").expect("failed to parse redeem_script script");

        //   scriptCode:  270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
        //                (since the OP_CODESEPARATOR is not executed, nothing is removed from the scriptCode)
        let script_code = ScriptCode::new_p2wsh(&redeem_script);
        assert_eq!(consensus::serialize_hex(&script_code), "270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac");


        //     witnessScript:5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
        //                   1 IF CODESEPARATOR ENDIF <0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98> CHECKSIG
        let redeem_script = ScriptBuf::from_hex("5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac").expect("failed to parse redeem_script script");

        //   scriptCode:  2468210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
        //                (everything up to the last executed OP_CODESEPARATOR, including that OP_CODESEPARATOR, are removed)
        let script_code = ScriptCode::__new_p2wsh_remove_op_codeseparator(&redeem_script);
        assert_eq!(consensus::serialize_hex(&script_code), "2468210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac");
    }
}
