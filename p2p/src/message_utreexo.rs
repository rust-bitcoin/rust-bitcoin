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

use crate::consensus::parse_failed_error;

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

/// The [`ReconstructableScript`] type allows nodes to rebuild
/// the locking script without relaying redundant information.
///
/// Since the [`ScriptHash`], [`PubkeyHash`], [`WScriptHash`]
/// and [`WPubkeyHash`] script types hide their scripts behind
/// a hash, it's useless to relay that hash, as the actual script
/// can be recovered from the `scriptSig` or `witness` fields in
/// the moment the [`TxOut`] is spent.
///
/// For [`TapScript`] and non-standard scripts where the script
/// cannot be reconstructed from transaction data, the actual
/// script has to be sent.
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
pub enum ReconstructableScript {
    /// Other: P2TR and non-standard outputs (0x00).
    Other(Box<[u8]>),
    /// P2PKH (0x01).
    PubkeyHash,
    /// P2WPKH (0x02).
    WitnessV0PubkeyHash,
    /// P2SH (0x03).
    ScriptHash,
    /// P2WSH (0x04).
    WitnessV0ScriptHash,
}

impl Encodable for ReconstructableScript {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        match self {
            Self::Other(script) => {
                len += 0x00.consensus_encode(w)?;
                len += script.consensus_encode(w)?;
            }
            Self::PubkeyHash => {
                len += 0x01.consensus_encode(w)?;
            }
            Self::WitnessV0PubkeyHash => {
                len += 0x02.consensus_encode(w)?;
            }
            Self::ScriptHash => {
                len += 0x03.consensus_encode(w)?;
            }
            Self::WitnessV0ScriptHash => {
                len += 0x04.consensus_encode(w)?;
            }
        }

        Ok(len)
    }
}

impl Decodable for ReconstructableScript {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let tag = u8::consensus_decode(r)?;
        match tag {
            0x00 => {
                let script_bytes = Vec::<u8>::consensus_decode(r)?;
                Ok(Self::Other(script_bytes.into_boxed_slice()))
            }
            0x01 => Ok(Self::PubkeyHash),
            0x02 => Ok(Self::WitnessV0PubkeyHash),
            0x03 => Ok(Self::ScriptHash),
            0x04 => Ok(Self::WitnessV0ScriptHash),
            _ => Err(parse_failed_error("Invalid ReconstructableScript tag: {tag}")),
        }
    }
}

#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
/// The [`CompactLeafData`] type contains all the information needed
/// for a node to rebuild the full leaf data for a given [`TxOut`].
pub struct CompactLeafData {
    /// The header code is obtained by doing a left shift of
    /// the block height the [`TxOut`] was confirmed in. If the [`TxOut`]
    /// is an output of a coinbase transaction, it gets OR-ed with 1.
    pub header_code: u32,
    /// The amount of satoshis locked on the [`TxOut`].
    pub amount: Amount,
    /// The [`TxOut`]'s scriptPubKey in the [`ReconstructableScript`] format.
    pub script_pubkey: ReconstructableScript,
}

impl Encodable for CompactLeafData {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.header_code.consensus_encode(w)?;
        len += self.amount.consensus_encode(w)?;
        len += self.script_pubkey.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for CompactLeafData {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            header_code: u32::consensus_decode(r)?,
            amount: Amount::consensus_decode(r)?,
            script_pubkey: ReconstructableScript::consensus_decode(r)?,
        })
    }
}
