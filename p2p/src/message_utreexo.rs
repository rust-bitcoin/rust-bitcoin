// SPDX-License-Identifier: CC0-1.0

//! BIP-0183: Utreexo Peer Services network messages.

// TODO(@luisschwab): should a `Vec<u8>` be used in the place of the [`Script`]/[`ScriptBuf`]?

use alloc::vec::Vec;

use bitcoin::consensus::{encode, Decodable, Encodable};
use bitcoin::{BlockHash, Transaction};
use io::{BufRead, Write};
use units::{Amount, BlockHeight};

/// The [`ReconstructableScriptTag`] encodes the type of locking script
/// and instructs how it should be reconstructed. If the locking script
/// cannot be reconstructed from the transaction, the actual script must
/// be sent (in this case, the `Other` variant is used).
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
pub enum ReconstructableScriptTag {
    /// Other (0x00): used for Taproot outputs.
    Other,
    /// P2PKH (0x01).
    PubkeyHash,
    /// P2WPKH (0x02).
    WitnessV0PubkeyHash,
    /// P2SH (0x03).
    ScriptHash,
    /// P2WSH (0x04).
    WitnessV0ScriptHash,
}

impl Encodable for ReconstructableScriptTag {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let rst = match self {
            ReconstructableScriptTag::Other => 0u8,
            ReconstructableScriptTag::PubkeyHash => 1u8,
            ReconstructableScriptTag::WitnessV0PubkeyHash => 2u8,
            ReconstructableScriptTag::ScriptHash => 3u8,
            ReconstructableScriptTag::WitnessV0ScriptHash => 4u8,
        };
        rst.consensus_encode(w)
    }
}

impl Decodable for ReconstructableScriptTag {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let rst = u8::consensus_decode(r)?;
        match rst {
            0 => Ok(ReconstructableScriptTag::Other),
            1 => Ok(ReconstructableScriptTag::PubkeyHash),
            2 => Ok(ReconstructableScriptTag::WitnessV0PubkeyHash),
            3 => Ok(ReconstructableScriptTag::ScriptHash),
            4 => Ok(ReconstructableScriptTag::WitnessV0ScriptHash),
            _ => Err(crate::consensus::parse_failed_error("Invalid ReconstructableScriptTag")),
        }
    }
}

/// The [`ReconstructableScript`] type allows nodes to rebuild
/// the locking script without relaying redundant information.
///
/// Since the [`ScriptHash`], [`PubkeyHash`], [`WScriptHash`]
/// and [`WPubkeyHash`] script types hide their scripts behind
/// a hash, it's useless to relay that hash, as the actual script
/// can be recovered from the `scriptSig` or `witness` fields in
/// the moment the UTXO is spent.
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
pub struct ReconstructableScript {
    /// The kind of locking script the UTXO is locked to.
    pub tag: ReconstructableScriptTag,
    /// The actual script, if [`ReconstructableScriptTag`] is of kind `Other`.
    pub script: Option<Vec<u8>>,
}

impl Encodable for ReconstructableScript {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut rs = self.tag.consensus_encode(w)?;
        if self.tag == ReconstructableScriptTag::Other {
            if let Some(ref script) = self.script {
                rs += script.consensus_encode(w)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Script required when tag is Other"
                ));
            }
        }
        Ok(rs)
    }
}

impl Decodable for ReconstructableScript {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let tag = ReconstructableScriptTag::consensus_decode(r)?;
        let script = if tag == ReconstructableScriptTag::Other {
            Some(Vec::<u8>::consensus_decode(r)?)
        } else {
            None
        };
        Ok(ReconstructableScript { tag, script })
    }
}

/// The [`CompactLeafData`] type contains all the information needed
/// for a node to rebuild the full leaf data for a given UTXO.
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
pub struct CompactLeafData {
    /// The header code is obtained by doing a left shift of
    /// the block height the UTXO was confirmed in. If the UTXO
    /// is an output of a coinbase transaction, it gets OR-ed with 1.
    pub header_code: u32,
    /// The amount of satoshis locked on the UTXO.
    pub amount: Amount,
    /// The UTXO's scriptPubKey in the [`ReconstructableScript`] format.
    pub script_pubkey: ReconstructableScript,
}

impl Encodable for CompactLeafData {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for CompactLeafData {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
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
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for TTLInfo {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
    }
}

/// The [`UtreexoTTL`] type... TODO
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoTTL {
    /// The [`BlockHeigh`] denotes the block that these [`TTInfo`]s refer to.
    pub block_height: BlockHeight,
    /// The set of [`TTLInfo`]s at height `block_height`.
    pub ttls: Vec<TTLInfo>,
}

impl Encodable for UtreexoTTL {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for UtreexoTTL {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
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
    /// The preimage of the commited UTXOs ([`CompactLeafData`]) requested via the `getuproof` message.
    /// These [`CompactLeafData`]s must be in blockchain order.
    pub leaf_datas: Vec<CompactLeafData>,
}

impl Encodable for UtreexoProof {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for UtreexoProof {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
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
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for GetUtreexoProof {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
    }
}

/// The `uttls` message (BIP-0324 type 31).
///
/// The [`UtreexoTTLs`] (`uttls`) message has the requested [`UtreexoTTL`]s and proof hashes
/// needed to validate that the given TTLs were commited in the provided binary. <- TODO check this
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoTTLs {
    /// The requested [`UtreexoTTL`]s.
    pub utreexo_ttls: Vec<UtreexoTTL>,
    /// The requested proof hashes.
    pub proof_hashes: Vec<[u8; 32]>,
}

impl Encodable for UtreexoTTLs {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for UtreexoTTLs {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
    }
}

/// The `getuttls` message (BIP-0324 type 32).
///
/// The [`GetUtreexoTTLs] (`getuttls`) message is a request for [`UtreexoTTL`]s and proof hashes.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetUtreexoTTLs {
    /// The block height of the commited TTL accumulator,
    /// used to specify which accumulator the TTL should be proved against.
    pub version: BlockHeight,
    /// The block height which the first TTL message will be provided for.
    pub start_height: BlockHeight,
    /// Indicates the maximum number of TTLs that should be provided, as an exponent of 2 (2^max_receive_exponent).
    max_receive_exponent: u8,
}

impl Encodable for GetUtreexoTTLs {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for GetUtreexoTTLs {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
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
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for UtreexoSummary {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
    }
}

#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
pub struct TxMessage(pub Transaction);

/// The `utreexotx` message (BIP-0324 type 34).
///
/// The [`UtreexoTx`] (`utreexotx`) message is the
/// non-Utreexo transaction appended with it's inclusion proof.
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
pub struct UtreexoTx {
    /// The non-Utreexo transaction. Unconfirmed inputs
    /// are marked by (TODO: left or right?) shifting the index by 1 and setting the LSB to 1.
    pub transaction: TxMessage,
    /// The requested Utreexo summaries.
    pub proof_hashes: Vec<UtreexoSummary>,
    /// The preimage of the leaf datas referenced in the transaction. These preimages must be in
    /// the order of the referenced inputs. A unconfirmed input does not have a corresponding
    /// leaf data.
    pub leaf_datas: Vec<CompactLeafData>,
}

impl Encodable for UtreexoTx {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for UtreexoTx {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
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
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for UtreexoRoot {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
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
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Decodable for GetUtreexoRoot {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        unimplemented!()
    }
}
