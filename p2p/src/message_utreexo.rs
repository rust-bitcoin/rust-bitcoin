// SPDX-License-Identifier: CC0-1.0

//! BIP-0183: Utreexo Peer Services network messages.

use alloc::boxed::Box;
use alloc::vec::Vec;

use bitcoin::consensus::{encode, Decodable, Encodable, ReadExt, WriteExt};
#[allow(unused_imports)]
use bitcoin::key::{PubkeyHash, WPubkeyHash};
#[allow(unused_imports)]
use bitcoin::script::{ScriptBuf, ScriptHash, ScriptPubKey, TapScript, WScriptHash};
#[allow(unused_imports)]
use bitcoin::{BlockHash, Transaction, TxOut};
use io::{BufRead, Write};
use units::{Amount, BlockHeight};

/// Utreexo root hashes as packed positions.
///
/// [`PackedPositions`] represents the hash payload of the `UtreexoProofHash`
/// inventory vector. This hash represents Merkle positions of up to 4 leaves,
/// with each leaf taking up 8 bytes.
///
/// Unused spaces are padded with [`u64::MAX`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackedPositions {
    /// The 0th leaf position. Always present.
    pub leaf_0: u64,
    /// The 1st leaf position. It's presence is optional.
    pub leaf_1: Option<u64>,
    /// The 2nd leaf position. It's presence is optional.
    pub leaf_2: Option<u64>,
    /// The 3rd leaf position. It's presence is optional.
    pub leaf_3: Option<u64>,
}

impl PackedPositions {
    /// Serialize a [`PackedPositions`] struct into a byte array.
    pub fn to_byte_array(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];

        bytes[0..8].copy_from_slice(&self.leaf_0.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.leaf_1.unwrap_or(u64::MAX).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.leaf_2.unwrap_or(u64::MAX).to_le_bytes());
        bytes[24..32].copy_from_slice(&self.leaf_3.unwrap_or(u64::MAX).to_le_bytes());

        bytes
    }
}

impl Encodable for PackedPositions {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        // The 0th leaf position is always present.
        len += self.leaf_0.consensus_encode(w)?;

        // The 1st leaf position is optional.
        if let Some(leaf_1) = self.leaf_1 {
            len += leaf_1.consensus_encode(w)?;
        } else {
            len += u64::MAX.consensus_encode(w)?;
        }

        // The 2nd leaf position is optional
        if let Some(leaf_2) = self.leaf_2 {
            len += leaf_2.consensus_encode(w)?;
        } else {
            len += u64::MAX.consensus_encode(w)?;
        }

        // The 3rd leaf position is optional.
        if let Some(leaf_3) = self.leaf_3 {
            len += leaf_3.consensus_encode(w)?;
        } else {
            len += u64::MAX.consensus_encode(w)?;
        }

        Ok(len)
    }
}

impl Decodable for PackedPositions {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        // `u64::MAX` encodes the absence of a leaf on that slot.
        let parse_leaf = |v: u64| if v == u64::MAX { None } else { Some(v) };

        Ok(Self {
            leaf_0: u64::consensus_decode(r)?,
            leaf_1: parse_leaf(u64::consensus_decode(r)?),
            leaf_2: parse_leaf(u64::consensus_decode(r)?),
            leaf_3: parse_leaf(u64::consensus_decode(r)?),
        })
    }
}
