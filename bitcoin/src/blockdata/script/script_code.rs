// SPDX-License-Identifier: CC0-1.0

use core::ops::Deref;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use crate::key::WPubkeyHash;
use crate::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_PUSHBYTES_20};
use crate::script::ScriptCode;
const P2WPKH_SCRIPT_CODE_LEN: usize = 25;

/// Owned script code used for P2WPKH sighash computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2wpkhScriptCode([u8; P2WPKH_SCRIPT_CODE_LEN]);

impl P2wpkhScriptCode {
    /// Constructs a new [`P2wpkhScriptCode`] containing the script code used for spending a P2WPKH output.
    pub fn new_p2wpkh(wpkh: WPubkeyHash) -> Self {
        let mut bytes = [0u8; P2WPKH_SCRIPT_CODE_LEN];

        bytes[0] = OP_DUP.to_u8();
        bytes[1] = OP_HASH160.to_u8();
        bytes[2] = OP_PUSHBYTES_20.to_u8();
        bytes[3..23].copy_from_slice(wpkh.as_byte_array());
        bytes[23] = OP_EQUALVERIFY.to_u8();
        bytes[24] = OP_CHECKSIG.to_u8();

        Self(bytes)
    }

    /// Borrows the script code without modifying or copying its bytes.
    pub fn as_script(&self) -> &ScriptCode { ScriptCode::from_bytes(&self.0) }
}

impl AsRef<ScriptCode> for P2wpkhScriptCode {
    fn as_ref(&self) -> &ScriptCode { self.as_script() }
}

impl Deref for P2wpkhScriptCode {
    type Target = ScriptCode;

    fn deref(&self) -> &Self::Target { self.as_script() }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for P2wpkhScriptCode {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let hash: [u8; 20] = u.arbitrary()?;
        let wpkh = WPubkeyHash::from_byte_array(hash);

        Ok(Self::new_p2wpkh(wpkh))
    }
}
