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

/// The [`TTLInfo`] type informs a node about how long to hold a proof in it's cache.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct TTLInfo {
    /// The TTL value of a leaf in the Utreexo Merkle forest,
    /// determined by the amount of leaves that were added to the
    /// accumulator since it's inception.
    pub ttl: usize,
    /// The position of the leaf in the Utreexo Merkle forest at
    /// the moment it was removed.
    pub death_position: usize,
}

impl Encodable for TTLInfo {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += w.emit_compact_size(self.ttl)?;
        len += w.emit_compact_size(self.death_position)?;

        Ok(len)
    }
}

impl Decodable for TTLInfo {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            ttl: r.read_compact_size()? as usize,
            death_position: r.read_compact_size()? as usize,
        })
    }
}

/// The [`UtreexoTTL`] type holds TTL information about leaves at a given `block_height`.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoTTL {
    /// The [`BlockHeight`] denotes the block that these [`TTLInfo`]s refer to.
    pub block_height: BlockHeight,
    /// The set of [`TTLInfo`]'s at height `block_height`.
    pub ttls: Vec<TTLInfo>,
}

impl Encodable for UtreexoTTL {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.block_height.consensus_encode(w)?;
        len += self.ttls.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for UtreexoTTL {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            block_height: BlockHeight::consensus_decode(r)?,
            ttls: Vec::<TTLInfo>::consensus_decode(r)?,
        })
    }
}

/// The `uproof` message (BIP-0324 type 29).
///
/// The [`UtreexoProof`] (`uproof`) message has all the data needed for a Utreexo
/// Compact State Node (CSN) or archive node to validate a block.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoProof {
    /// The hash of the block this Utreexo proof proves.
    pub blockhash: BlockHash,
    /// The hashes requested via the `getuproof` message. These hashes must be in tree order.
    pub proof_hashes: Vec<[u8; 32]>,
    /// The locations of the leaf datas on the Utreexo Merkle tree. These locations must
    /// be in blockchain order and include either all locations or no locations at all.
    pub target_locations: Vec<usize>,
    /// The preimage of the commited [`TxOut`] ([`CompactLeafData`]) requested via the `getuproof` message.
    /// These [`CompactLeafData`]s must be in blockchain order.
    pub leaf_datas: Vec<CompactLeafData>,
}

impl Encodable for UtreexoProof {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.blockhash.consensus_encode(w)?;
        len += self.proof_hashes.consensus_encode(w)?;
        len += w.emit_compact_size(self.target_locations.len())?;
        for location in &self.target_locations {
            len += w.emit_compact_size(*location)?;
        }
        len += self.leaf_datas.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for UtreexoProof {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let blockhash = BlockHash::consensus_decode(r)?;
        let proof_hashes = Vec::<[u8; 32]>::consensus_decode(r)?;

        let target_locations_len = r.read_compact_size()? as usize;
        let mut target_locations = Vec::with_capacity(target_locations_len);
        for _ in 0..target_locations_len {
            target_locations.push(r.read_compact_size()? as usize);
        }

        let leaf_datas = Vec::<CompactLeafData>::consensus_decode(r)?;

        Ok(Self { blockhash, proof_hashes, target_locations, leaf_datas })
    }
}

/// The `getuproof` message (BIP-0324 type 30).
///
/// The [`GetUtreexoProof`] (`getuproof`) message is a request for a block's inclusion proof.
///
/// The bitmaps must be in Big-Endian and padded to the nearest byte, with 1 indicating a
/// request and 0 indicating an omission of the proof hash or leaf data. Use the
/// `proof_positions` function to generate the bitmaps from a given set of targets
/// (see the 'Utility Functions' sections from BIP-0181).
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetUtreexoProof {
    /// The hash of the block which inclusion proofs are requested.
    pub blockhash: BlockHash,
    /// Indicates if the complete proof or only a subset of it is requested.
    pub include_all: bool,
    /// A bitmap of the requested proof hashes.
    pub proof_request_bitmap: Vec<u8>,
    /// A bitmap of the requested leaf datas.
    pub leaf_data_request_bitmap: Vec<u8>,
}

impl Encodable for GetUtreexoProof {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.blockhash.consensus_encode(w)?;
        len += self.include_all.consensus_encode(w)?;
        len += self.proof_request_bitmap.consensus_encode(w)?;
        len += self.leaf_data_request_bitmap.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for GetUtreexoProof {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            blockhash: BlockHash::consensus_decode(r)?,
            include_all: bool::consensus_decode(r)?,
            proof_request_bitmap: Vec::<u8>::consensus_decode(r)?,
            leaf_data_request_bitmap: Vec::<u8>::consensus_decode(r)?,
        })
    }
}

/// The `uttls` message (BIP-0324 type 31).
///
/// The [`UtreexoTTLs`] (`uttls`) message has the requested [`UtreexoTTL`]s and proof hashes
/// needed to validate that the given TTLs were commited in the provided application binary.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoTTLs {
    /// The requested [`UtreexoTTL`]s.
    pub utreexo_ttls: Vec<UtreexoTTL>,
    /// The requested proof hashes.
    pub proof_hashes: Vec<[u8; 32]>,
}

impl Encodable for UtreexoTTLs {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.utreexo_ttls.consensus_encode(w)?;
        len += self.proof_hashes.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for UtreexoTTLs {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            utreexo_ttls: Vec::<UtreexoTTL>::consensus_decode(r)?,
            proof_hashes: Vec::<[u8; 32]>::consensus_decode(r)?,
        })
    }
}

/// The `getuttls` message (BIP-0324 type 32).
///
/// The [`GetUtreexoTTLs`] (`getuttls`) message is a request for [`UtreexoTTL`]s and proof hashes.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetUtreexoTTLs {
    /// The block height of the commited TTL accumulator,
    /// used to specify which accumulator the TTL should be proved against.
    pub version: BlockHeight,
    /// The block height which the first TTL message will be provided for.
    pub start_height: BlockHeight,
    /// Indicates the maximum number of TTLs that should be provided, as an exponent of 2 (2^max_receive_exponent).
    pub max_receive_exponent: u8,
}

impl Encodable for GetUtreexoTTLs {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += self.start_height.consensus_encode(w)?;
        len += self.max_receive_exponent.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for GetUtreexoTTLs {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            version: BlockHeight::consensus_decode(r)?,
            start_height: BlockHeight::consensus_decode(r)?,
            max_receive_exponent: u8::consensus_decode(r)?,
        })
    }
}

/// The `usummary` message (BIP-0324 type 33).
///
/// The [`UtreexoSummary`] (`usummary`) message has all the data needed to
/// calculate the missing Merkle forest positions required to validate any given block.
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
pub struct UtreexoSummary {
    /// The hash of the block this [`UtreexoSummary`] relates to.
    pub blockhash: BlockHash,
    /// The number of leaves added to the accumulator on the block this [`UtreexoSummary`] relates to.
    pub num_additions: usize,
    /// The Utreexo Merkle tree locations of the leaf datas.
    /// These locations must be in blockchain order and must include all locations.
    pub target_locations: Vec<u64>,
}

impl Encodable for UtreexoSummary {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.blockhash.consensus_encode(w)?;
        len += w.emit_compact_size(self.num_additions)?;
        len += self.blockhash.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for UtreexoSummary {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let blockhash = BlockHash::consensus_decode(r)?;
        let num_additions = r.read_compact_size()? as usize;
        let target_locations = Vec::<u64>::consensus_decode(r)?;

        Ok(Self { blockhash, num_additions, target_locations })
    }
}

/// The `utreexotx` message (BIP-0324 type 34).
///
/// The [`UtreexoTransaction`] (`utreexotx`) message is the
/// non-Utreexo transaction appended with it's inclusion proof.
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
pub struct UtreexoTransaction {
    /// The non-Utreexo transaction. Unconfirmed inputs are marked by left-shifting the index by 1 and setting the LSB to 1.
    /// TODO(@luisschwab): update the BIP to make the left-shift **explicit**.
    pub transaction: Transaction,
    /// The requested Utreexo summaries.
    pub proof_hashes: Vec<UtreexoSummary>,
    /// The preimage of the leaf datas referenced in the transaction. These preimages must be in
    /// the order of the referenced inputs. A unconfirmed input does not have a corresponding
    /// leaf data.
    pub leaf_datas: Vec<CompactLeafData>,
}

impl Encodable for UtreexoTransaction {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.transaction.consensus_encode(w)?;
        len += self.proof_hashes.consensus_encode(w)?;
        len += self.leaf_datas.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for UtreexoTransaction {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            transaction: Transaction::consensus_decode(r)?,
            proof_hashes: Vec::<UtreexoSummary>::consensus_decode(r)?,
            leaf_datas: Vec::<CompactLeafData>::consensus_decode(r)?,
        })
    }
}

/// The `uroot` message (BIP-0324 type 35).
///
/// The [`UtreexoRoot`] (`uroot`) message is the Utreexo accumulator state at a given height
/// with a proof to a Utreexo accumulator of the Utreexo roots.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoRoot {
    /// The number of leaves that were added to the accumulator at this block hash.
    pub num_leaves: usize,
    /// The position of the Utreexo root in the optional accumulator of Utreexo roots.
    pub target: usize,
    /// The blockhash for this Utreexo accumulator.
    pub blockhash: BlockHash,
    /// The roots of the Utreexo Merkle forest at this block hash.
    pub root_hashes: Vec<[u8; 32]>,
    /// The proof hashes necessary to validate with the pre-commited Utreexo accumulator of the Utreexo roots.
    pub proof_hashes: Vec<[u8; 32]>,
}

impl Encodable for UtreexoRoot {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += w.emit_compact_size(self.num_leaves)?;
        len += w.emit_compact_size(self.target)?;
        len += self.blockhash.consensus_encode(w)?;
        len += self.proof_hashes.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for UtreexoRoot {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let num_leaves = r.read_compact_size()? as usize;
        let target = r.read_compact_size()? as usize;
        let blockhash = BlockHash::consensus_decode(r)?;
        let root_hashes = Vec::<[u8; 32]>::consensus_decode(r)?;
        let proof_hashes = Vec::<[u8; 32]>::consensus_decode(r)?;

        Ok(Self { num_leaves, target, blockhash, root_hashes, proof_hashes })
    }
}

/// The `geturoot` message (BIP-0324 type 36).
///
/// The [`GetUtreexoRoot`] (`geturoot`) message is a request for the accumulator state at the given block hash.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetUtreexoRoot {
    /// The block hash that the accumulator state is being requested for.
    pub blockhash: BlockHash,
}

impl Encodable for GetUtreexoRoot {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.blockhash.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for GetUtreexoRoot {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self { blockhash: BlockHash::consensus_decode(r)? })
    }
}

#[cfg(test)]
mod tests {
    // TODO(@luisschwab): add tests (pending BIP-0183 test vectors)
}
