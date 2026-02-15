// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.

use core::convert::Infallible;
use core::fmt;
#[cfg(feature = "alloc")]
use core::marker::PhantomData;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::Encodable;
#[cfg(feature = "hex")]
use encoding::EncodableByteIter;
#[cfg(feature = "alloc")]
use encoding::{
    CompactSizeEncoder, Decodable, Decoder, Decoder2, Decoder6, Encoder2, SliceEncoder, VecDecoder,
};
use hashes::{sha256d, HashEngine as _};
use internals::write_err;

#[cfg(feature = "alloc")]
use crate::pow::{CompactTargetDecoder, CompactTargetDecoderError};
#[cfg(feature = "alloc")]
use crate::prelude::Vec;
#[cfg(feature = "alloc")]
use crate::time::{BlockTimeDecoder, BlockTimeDecoderError};
#[cfg(feature = "alloc")]
use crate::transaction::{TxMerkleNodeDecoder, TxMerkleNodeDecoderError};
use crate::{BlockTime, CompactTarget, TxMerkleNode};
#[cfg(feature = "alloc")]
use crate::{Transaction, WitnessMerkleNode};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use units::block::{BlockHeight, BlockHeightDecoder, BlockHeightEncoder, BlockHeightInterval, BlockMtp, BlockMtpInterval};
// Re-export errors that appear directly in the API - but no doc inline.
#[doc(no_inline)]
pub use units::block::{BlockHeightDecoderError, TooBigForRelativeHeightError};

#[doc(inline)]
pub use crate::hash_types::{
    BlockHash, BlockHashDecoder, BlockHashDecoderError, BlockHashEncoder, WitnessCommitment,
};

/// Marker for whether or not a block has been validated.
///
/// We define valid as:
///
/// * The Merkle root of the header matches Merkle root of the transaction list.
/// * The witness commitment in coinbase matches the transaction list.
///
/// See `bitcoin::block::BlockUncheckedExt::validate()`.
#[cfg(feature = "alloc")]
pub trait Validation: sealed::Validation + Sync + Send + Sized + Unpin {
    /// Indicates whether this `Validation` is `Checked` or not.
    const IS_CHECKED: bool;
}

/// Bitcoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// # Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[cfg(feature = "alloc")]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Block<V = Unchecked>
where
    V: Validation,
{
    /// The block header
    header: Header,
    /// List of transactions contained in the block
    transactions: Vec<Transaction>,
    /// Cached witness root if it's been computed.
    witness_root: Option<WitnessMerkleNode>,
    /// Validation marker.
    _marker: PhantomData<V>,
}

#[cfg(feature = "alloc")]
impl Block<Unchecked> {
    /// Constructs a new `Block` without doing any validation.
    #[inline]
    pub fn new_unchecked(header: Header, transactions: Vec<Transaction>) -> Self {
        Self { header, transactions, witness_root: None, _marker: PhantomData::<Unchecked> }
    }

    /// Ignores block validation logic and just assumes you know what you are doing.
    ///
    /// You should only use this function if you trust the block i.e., it comes from a trusted node.
    #[must_use]
    #[inline]
    pub fn assume_checked(self, witness_root: Option<WitnessMerkleNode>) -> Block<Checked> {
        Block {
            header: self.header,
            transactions: self.transactions,
            witness_root,
            _marker: PhantomData::<Checked>,
        }
    }

    /// Decomposes block into its constituent parts.
    #[inline]
    pub fn into_parts(self) -> (Header, Vec<Transaction>) { (self.header, self.transactions) }

    /// Returns the constituent parts of the block by reference.
    #[inline]
    pub fn as_parts(&self) -> (&Header, &[Transaction]) { (&self.header, &self.transactions) }

    /// Validates (or checks) a block.
    ///
    /// We define valid as:
    ///
    /// * The Merkle root of the header matches Merkle root of the transaction list.
    /// * The witness commitment in coinbase matches the transaction list.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The block has no transactions.
    /// * The first transaction is not a coinbase transaction.
    /// * The Merkle root of the header does not match the Merkle root of the transaction list.
    /// * The witness commitment in the coinbase does not match the transaction list.
    pub fn validate(self) -> Result<Block<Checked>, InvalidBlockError> {
        if self.transactions.is_empty() {
            return Err(InvalidBlockError::NoTransactions);
        }

        if !self.transactions[0].is_coinbase() {
            return Err(InvalidBlockError::InvalidCoinbase);
        }

        if !self.check_merkle_root() {
            return Err(InvalidBlockError::InvalidMerkleRoot);
        }

        match self.check_witness_commitment() {
            (false, _) => Err(InvalidBlockError::InvalidWitnessCommitment),
            (true, witness_root) => {
                let block = Self::new_unchecked(self.header, self.transactions);
                Ok(block.assume_checked(witness_root))
            }
        }
    }

    /// Checks if Merkle root of header matches Merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match compute_merkle_root(&self.transactions) {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Computes the witness commitment for a list of transactions.
    pub fn compute_witness_commitment(
        &self,
        witness_reserved_value: &[u8],
    ) -> Option<(WitnessMerkleNode, WitnessCommitment)> {
        compute_witness_root(&self.transactions).map(|witness_root| {
            let mut encoder = sha256d::Hash::engine();
            encoder = hashes::encode_to_engine(&witness_root, encoder);
            encoder.input(witness_reserved_value);
            let witness_commitment = WitnessCommitment::from_byte_array(
                sha256d::Hash::from_engine(encoder).to_byte_array(),
            );
            (witness_root, witness_commitment)
        })
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    // Returns the Merkle root if it was computed (so it can be cached in `assume_checked`).
    pub fn check_witness_commitment(&self) -> (bool, Option<WitnessMerkleNode>) {
        if self.transactions.is_empty() {
            return (false, None);
        }

        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.transactions.iter().all(|t| t.inputs.iter().all(|i| i.witness.is_empty())) {
            return (true, None);
        }

        if self.transactions[0].is_coinbase() {
            let coinbase = self.transactions[0].clone();
            if let Some(commitment) = witness_commitment_from_coinbase(&coinbase) {
                // Witness reserved value is in coinbase input witness.
                let witness_vec: Vec<_> = coinbase.inputs[0].witness.iter().collect();
                if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                    if let Some((witness_root, witness_commitment)) =
                        self.compute_witness_commitment(witness_vec[0])
                    {
                        if commitment == witness_commitment {
                            return (true, Some(witness_root));
                        }
                    }
                }
            }
        }

        (false, None)
    }
}

#[cfg(feature = "alloc")]
impl Block<Checked> {
    /// Gets a reference to the block header.
    #[inline]
    pub fn header(&self) -> &Header { &self.header }

    /// Gets a reference to the block's list of transactions.
    #[inline]
    pub fn transactions(&self) -> &[Transaction] { &self.transactions }

    /// Returns the cached witness root if one is present.
    ///
    /// It is assumed that a block will have the witness root calculated and cached as part of the
    /// validation process.
    #[inline]
    pub fn cached_witness_root(&self) -> Option<WitnessMerkleNode> { self.witness_root }
}

#[cfg(feature = "alloc")]
impl<V: Validation> Block<V> {
    /// Returns the block hash.
    #[inline]
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }
}

#[cfg(feature = "alloc")]
impl From<Block> for BlockHash {
    #[inline]
    fn from(block: Block) -> Self { block.block_hash() }
}

#[cfg(feature = "alloc")]
impl From<&Block> for BlockHash {
    #[inline]
    fn from(block: &Block) -> Self { block.block_hash() }
}

/// Marker that the block's merkle root has been successfully validated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg(feature = "alloc")]
pub enum Checked {}

#[cfg(feature = "alloc")]
impl Validation for Checked {
    const IS_CHECKED: bool = true;
}

/// Marker that the block's merkle root has not been validated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg(feature = "alloc")]
pub enum Unchecked {}

#[cfg(feature = "alloc")]
impl Validation for Unchecked {
    const IS_CHECKED: bool = false;
}

#[cfg(feature = "alloc")]
mod sealed {
    /// Seals the block validation marker traits.
    pub trait Validation {}
    impl Validation for super::Checked {}
    impl Validation for super::Unchecked {}
}

#[cfg(feature = "alloc")]
encoding::encoder_newtype! {
    /// The encoder for the [`Block`] type.
    pub struct BlockEncoder<'e>(
        Encoder2<HeaderEncoder<'e>, Encoder2<CompactSizeEncoder, SliceEncoder<'e, Transaction>>>
    );
}

#[cfg(feature = "alloc")]
impl Encodable for Block {
    type Encoder<'e>
        = Encoder2<HeaderEncoder<'e>, Encoder2<CompactSizeEncoder, SliceEncoder<'e, Transaction>>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            self.header.encoder(),
            Encoder2::new(
                CompactSizeEncoder::new(self.transactions.len()),
                SliceEncoder::without_length_prefix(&self.transactions),
            ),
        )
    }
}

#[cfg(feature = "alloc")]
type BlockInnerDecoder = Decoder2<HeaderDecoder, VecDecoder<Transaction>>;

/// The decoder for the [`Block`] type.
///
/// This decoder can only produce a `Block<Unchecked>`.
#[cfg(feature = "alloc")]
pub struct BlockDecoder(BlockInnerDecoder);

#[cfg(feature = "alloc")]
impl Decoder for BlockDecoder {
    type Output = Block;
    type Error = BlockDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(BlockDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (header, transactions) = self.0.end().map_err(BlockDecoderError)?;
        Ok(Self::Output::new_unchecked(header, transactions))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decodable for Block {
    type Decoder = BlockDecoder;
    fn decoder() -> Self::Decoder {
        BlockDecoder(Decoder2::new(Header::decoder(), VecDecoder::<Transaction>::new()))
    }
}

/// An error consensus decoding a [`Block`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDecoderError(<BlockInnerDecoder as Decoder>::Error);

#[cfg(feature = "alloc")]
impl From<Infallible> for BlockDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for BlockDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            encoding::Decoder2Error::First(ref e) => write_err!(f, "block decoder error"; e),
            encoding::Decoder2Error::Second(ref e) => write_err!(f, "block decoder error"; e),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "std")]
impl std::error::Error for BlockDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            encoding::Decoder2Error::First(ref e) => Some(e),
            encoding::Decoder2Error::Second(ref e) => Some(e),
        }
    }
}

/// Invalid block error.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidBlockError {
    /// Header Merkle root does not match the calculated Merkle root.
    InvalidMerkleRoot,
    /// The witness commitment in coinbase transaction does not match the calculated `witness_root`.
    InvalidWitnessCommitment,
    /// Block has no transactions (missing coinbase).
    NoTransactions,
    /// The first transaction is not a valid coinbase transaction.
    InvalidCoinbase,
}

#[cfg(feature = "alloc")]
impl From<Infallible> for InvalidBlockError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for InvalidBlockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidMerkleRoot =>
                write!(f, "header Merkle root does not match the calculated Merkle root"),
            Self::InvalidWitnessCommitment => write!(f, "the witness commitment in coinbase transaction does not match the calculated witness_root"),
            Self::NoTransactions => write!(f, "block has no transactions (missing coinbase)"),
            Self::InvalidCoinbase =>
                write!(f, "the first transaction is not a valid coinbase transaction"),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "std")]
impl std::error::Error for InvalidBlockError {}

/// Computes the Merkle root for a list of transactions.
///
/// Returns `None` if the iterator was empty, or if the transaction list contains
/// consecutive duplicates which would trigger CVE 2012-2459. Blocks with duplicate
/// transactions will always be invalid, so there is no harm in us refusing to
/// compute their merkle roots.
///
/// Unless you are certain your transaction list is nonempty and has no duplicates,
/// you should not unwrap the `Option` returned by this method!
#[cfg(feature = "alloc")]
pub fn compute_merkle_root(transactions: &[Transaction]) -> Option<TxMerkleNode> {
    let hashes = transactions.iter().map(Transaction::compute_txid);
    TxMerkleNode::calculate_root(hashes)
}

/// Computes the Merkle root of transactions hashed for witness.
///
/// Returns `None` if the iterator was empty, or if the transaction list contains
/// consecutive duplicates which would trigger CVE 2012-2459. Blocks with duplicate
/// transactions will always be invalid, so there is no harm in us refusing to
/// compute their merkle roots.
///
/// Unless you are certain your transaction list is nonempty and has no duplicates,
/// you should not unwrap the `Option` returned by this method!
#[cfg(feature = "alloc")]
pub fn compute_witness_root(transactions: &[Transaction]) -> Option<WitnessMerkleNode> {
    let hashes = transactions.iter().enumerate().map(|(i, t)| {
        if i == 0 {
            // Replace the first hash with zeroes.
            crate::Wtxid::COINBASE
        } else {
            t.compute_wtxid()
        }
    });
    WitnessMerkleNode::calculate_root(hashes)
}

#[cfg(feature = "alloc")]
fn witness_commitment_from_coinbase(coinbase: &Transaction) -> Option<WitnessCommitment> {
    // Consists of OP_RETURN, OP_PUSHBYTES_36, and four "witness header" bytes.
    const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

    if !coinbase.is_coinbase() {
        return None;
    }

    // Commitment is in the last output that starts with magic bytes.
    if let Some(pos) = coinbase
        .outputs
        .iter()
        .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
    {
        let bytes =
            <[u8; 32]>::try_from(&coinbase.outputs[pos].script_pubkey.as_bytes()[6..38]).unwrap();
        Some(WitnessCommitment::from_byte_array(bytes))
    } else {
        None
    }
}

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [Merkle tree] committing to all transactions in the block.
///
/// [Merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// # Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the Merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: BlockTime,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

impl Header {
    /// The number of bytes that the block header contributes to the size of a block.
    // Serialized length of fields (version, prev_blockhash, merkle_root, time, bits, nonce)
    pub const SIZE: usize = 4 + 32 + 32 + 4 + 4 + 4; // 80

    /// Returns the block hash.
    // This is the same as `Encodable` but done manually because `Encodable` isn't in `primitives`.
    pub fn block_hash(&self) -> BlockHash {
        let bare_hash = hashes::encode_to_engine(self, sha256d::Hash::engine()).finalize();
        BlockHash::from_byte_array(bare_hash.to_byte_array())
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl core::str::FromStr for Header {
    type Err = ParseHeaderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::hex_codec::HexPrimitive::from_str(s).map_err(ParseHeaderError)
    }
}

#[cfg(feature = "hex")]
impl fmt::Display for Header {
    #[allow(clippy::use_self)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use hex_unstable::{fmt_hex_exact, Case};

        fmt_hex_exact!(f, Header::SIZE, EncodableByteIter::new(self), Case::Lower)
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::LowerHex for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&crate::hex_codec::HexPrimitive(self), f)
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::UpperHex for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&crate::hex_codec::HexPrimitive(self), f)
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("block_hash", &self.block_hash())
            .field("version", &self.version)
            .field("prev_blockhash", &self.prev_blockhash)
            .field("merkle_root", &self.merkle_root)
            .field("time", &self.time)
            .field("bits", &self.bits)
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// An error that occurs during parsing of a [`Header`] from a hex string.
#[cfg(all(feature = "hex", feature = "alloc"))]
pub struct ParseHeaderError(crate::ParsePrimitiveError<Header>);

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::Debug for ParseHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Debug::fmt(&self.0, f) }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl fmt::Display for ParseHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Debug::fmt(&self, f) }
}

#[cfg(all(feature = "hex", feature = "alloc", feature = "std"))]
impl std::error::Error for ParseHeaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.0)
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`Header`] type.
    pub struct HeaderEncoder<'e>(
        encoding::Encoder6<
            VersionEncoder<'e>,
            BlockHashEncoder<'e>,
            crate::merkle_tree::TxMerkleNodeEncoder<'e>,
            crate::time::BlockTimeEncoder<'e>,
            crate::pow::CompactTargetEncoder<'e>,
            encoding::ArrayEncoder<4>,
        >
    );
}

impl Encodable for Header {
    type Encoder<'e> = HeaderEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        HeaderEncoder::new(encoding::Encoder6::new(
            self.version.encoder(),
            self.prev_blockhash.encoder(),
            self.merkle_root.encoder(),
            self.time.encoder(),
            self.bits.encoder(),
            encoding::ArrayEncoder::without_length_prefix(self.nonce.to_le_bytes()),
        ))
    }
}

#[cfg(feature = "alloc")]
type HeaderInnerDecoder = Decoder6<
    VersionDecoder,
    BlockHashDecoder,
    TxMerkleNodeDecoder,
    BlockTimeDecoder,
    CompactTargetDecoder,
    encoding::ArrayDecoder<4>, // Nonce
>;

/// The decoder for the [`Header`] type.
#[cfg(feature = "alloc")]
pub struct HeaderDecoder(HeaderInnerDecoder);

#[cfg(feature = "alloc")]
impl HeaderDecoder {
    fn from_inner(e: <HeaderInnerDecoder as Decoder>::Error) -> HeaderDecoderError {
        match e {
            encoding::Decoder6Error::First(e) => HeaderDecoderError::Version(e),
            encoding::Decoder6Error::Second(e) => HeaderDecoderError::PrevBlockhash(e),
            encoding::Decoder6Error::Third(e) => HeaderDecoderError::MerkleRoot(e),
            encoding::Decoder6Error::Fourth(e) => HeaderDecoderError::Time(e),
            encoding::Decoder6Error::Fifth(e) => HeaderDecoderError::Bits(e),
            encoding::Decoder6Error::Sixth(e) => HeaderDecoderError::Nonce(e),
        }
    }
}

#[cfg(feature = "alloc")]
impl Decoder for HeaderDecoder {
    type Output = Header;
    type Error = HeaderDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(Self::from_inner)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (version, prev_blockhash, merkle_root, time, bits, nonce) =
            self.0.end().map_err(Self::from_inner)?;
        let nonce = u32::from_le_bytes(nonce);
        Ok(Header { version, prev_blockhash, merkle_root, time, bits, nonce })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decodable for Header {
    type Decoder = HeaderDecoder;
    fn decoder() -> Self::Decoder {
        HeaderDecoder(Decoder6::new(
            VersionDecoder::new(),
            BlockHashDecoder::new(),
            TxMerkleNodeDecoder::new(),
            BlockTimeDecoder::new(),
            CompactTargetDecoder::new(),
            encoding::ArrayDecoder::new(),
        ))
    }
}

/// An error consensus decoding a `Header`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderDecoderError {
    /// Error while decoding the `version`.
    Version(VersionDecoderError),
    /// Error while decoding the `prev_blockhash`.
    PrevBlockhash(BlockHashDecoderError),
    /// Error while decoding the `merkle_root`.
    MerkleRoot(TxMerkleNodeDecoderError),
    /// Error while decoding the `time`.
    Time(BlockTimeDecoderError),
    /// Error while decoding the `bits`.
    Bits(CompactTargetDecoderError),
    /// Error while decoding the `nonce`.
    Nonce(encoding::UnexpectedEofError),
}

#[cfg(feature = "alloc")]
impl From<Infallible> for HeaderDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for HeaderDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Version(ref e) => write_err!(f, "header decoder error"; e),
            Self::PrevBlockhash(ref e) => write_err!(f, "header decoder error"; e),
            Self::MerkleRoot(ref e) => write_err!(f, "header decoder error"; e),
            Self::Time(ref e) => write_err!(f, "header decoder error"; e),
            Self::Bits(ref e) => write_err!(f, "header decoder error"; e),
            Self::Nonce(ref e) => write_err!(f, "header decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "alloc")]
impl std::error::Error for HeaderDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Version(ref e) => Some(e),
            Self::PrevBlockhash(ref e) => Some(e),
            Self::MerkleRoot(ref e) => Some(e),
            Self::Time(ref e) => Some(e),
            Self::Bits(ref e) => Some(e),
            Self::Nonce(ref e) => Some(e),
        }
    }
}

impl From<Header> for BlockHash {
    #[inline]
    fn from(header: Header) -> Self { header.block_hash() }
}

impl From<&Header> for BlockHash {
    #[inline]
    fn from(header: &Header) -> Self { header.block_hash() }
}

/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if the version bits are
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// # Relevant BIPs
///
/// * [BIP-0009 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP-0034 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-0034 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-0009 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-0009 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Constructs a new [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    #[inline]
    pub const fn from_consensus(v: i32) -> Self { Self(v) }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    #[inline]
    pub const fn to_consensus(self) -> i32 { self.0 }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-0009 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(self, bit: u8) -> bool {
        // Only bits [0, 28] inclusive are used for signalling.
        if bit > 28 {
            return false;
        }

        // To signal using version bits, the first three bits must be `001`.
        if (self.0 as u32) & !Self::VERSION_BITS_MASK != Self::USE_VERSION_BITS {
            return false;
        }

        // The bit is set if signalling a soft fork.
        (self.0 as u32 & Self::VERSION_BITS_MASK) & (1 << bit) > 0
    }
}

impl fmt::Display for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl fmt::LowerHex for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

impl fmt::UpperHex for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

impl fmt::Octal for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Octal::fmt(&self.0, f) }
}

impl fmt::Binary for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Binary::fmt(&self.0, f) }
}

impl Default for Version {
    #[inline]
    fn default() -> Self { Self::NO_SOFT_FORK_SIGNALLING }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`Version`] type.
    pub struct VersionEncoder<'e>(encoding::ArrayEncoder<4>);
}

impl Encodable for Version {
    type Encoder<'e> = VersionEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        VersionEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`Version`] type.
pub struct VersionDecoder(encoding::ArrayDecoder<4>);

impl VersionDecoder {
    /// Constructs a new [`Version`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

impl Default for VersionDecoder {
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for VersionDecoder {
    type Output = Version;
    type Error = VersionDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(VersionDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let n = i32::from_le_bytes(self.0.end().map_err(VersionDecoderError)?);
        Ok(Version::from_consensus(n))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for Version {
    type Decoder = VersionDecoder;
    fn decoder() -> Self::Decoder { VersionDecoder(encoding::ArrayDecoder::<4>::new()) }
}

/// An error consensus decoding an `Version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDecoderError(encoding::UnexpectedEofError);

impl From<Infallible> for VersionDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for VersionDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "version decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VersionDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for Block {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let header = Header::arbitrary(u)?;
        let transactions = Vec::<Transaction>::arbitrary(u)?;
        Ok(Self::new_unchecked(header, transactions))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Header {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: Version::arbitrary(u)?,
            prev_blockhash: BlockHash::from_byte_array(u.arbitrary()?),
            merkle_root: TxMerkleNode::from_byte_array(u.arbitrary()?),
            time: u.arbitrary()?,
            bits: CompactTarget::from_consensus(u.arbitrary()?),
            nonce: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Version {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Equally weight known versions and arbitrary versions
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => Ok(Self::ONE),
            1 => Ok(Self::TWO),
            2 => Ok(Self::NO_SOFT_FORK_SIGNALLING),
            _ => Ok(Self::from_consensus(u.arbitrary()?)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;
    #[cfg(feature = "alloc")]
    use alloc::{format, vec};
    #[cfg(all(feature = "alloc", feature = "hex"))]
    use core::str::FromStr as _;

    use encoding::{Decoder, Encoder};

    use super::*;

    fn dummy_header() -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0x77; 32]),
            time: BlockTime::from(2),
            bits: CompactTarget::from_consensus(3),
            nonce: 4,
        }
    }

    #[test]
    fn version_is_not_signalling_with_invalid_bit() {
        let arbitrary_version = Version::from_consensus(1_234_567_890);
        // The max bit number to signal is 28.
        assert!(!Version::is_signalling_soft_fork(arbitrary_version, 29));
    }

    #[test]
    fn version_is_not_signalling_when_use_version_bit_not_set() {
        let version = Version::from_consensus(0b0100_0000_0000_0000_0000_0000_0000_0000);
        // Top three bits must be 001 to signal.
        assert!(!Version::is_signalling_soft_fork(version, 1));
    }

    #[test]
    fn version_is_signalling() {
        let version = Version::from_consensus(0b0010_0000_0000_0000_0000_0000_0000_0010);
        assert!(Version::is_signalling_soft_fork(version, 1));
        let version = Version::from_consensus(0b0011_0000_0000_0000_0000_0000_0000_0000);
        assert!(Version::is_signalling_soft_fork(version, 28));
    }

    #[test]
    fn version_is_not_signalling() {
        let version = Version::from_consensus(0b0010_0000_0000_0000_0000_0000_0000_0010);
        assert!(!Version::is_signalling_soft_fork(version, 0));
    }

    #[test]
    fn version_to_consensus() {
        let version = Version::from_consensus(1_234_567_890);
        assert_eq!(version.to_consensus(), 1_234_567_890);
    }

    #[test]
    fn version_default() {
        let version = Version::default();
        assert_eq!(version.to_consensus(), Version::NO_SOFT_FORK_SIGNALLING.to_consensus());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn version_display() {
        let version = Version(75);
        assert_eq!(format!("{}", version), "75");
        assert_eq!(format!("{:x}", version), "4b");
        assert_eq!(format!("{:#x}", version), "0x4b");
        assert_eq!(format!("{:X}", version), "4B");
        assert_eq!(format!("{:#X}", version), "0x4B");
        assert_eq!(format!("{:o}", version), "113");
        assert_eq!(format!("{:#o}", version), "0o113");
        assert_eq!(format!("{:b}", version), "1001011");
        assert_eq!(format!("{:#b}", version), "0b1001011");
    }

    // Check that the size of the header consensus serialization matches the const SIZE value
    #[test]
    fn header_size() {
        let header = dummy_header();

        // Calculate the size of the block header in bytes from the sum of the serialized lengths
        // its fields: version, prev_blockhash, merkle_root, time, bits, nonce.
        let header_size = header.version.to_consensus().to_le_bytes().len()
            + header.prev_blockhash.as_byte_array().len()
            + header.merkle_root.as_byte_array().len()
            + header.time.to_u32().to_le_bytes().len()
            + header.bits.to_consensus().to_le_bytes().len()
            + header.nonce.to_le_bytes().len();

        assert_eq!(header_size, Header::SIZE);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_new_unchecked() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions.clone());
        assert_eq!(block.header, header);
        assert_eq!(block.transactions, transactions);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_assume_checked() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions.clone());
        let witness_root = Some(WitnessMerkleNode::from_byte_array([0x88; 32]));
        let checked_block = block.assume_checked(witness_root);
        assert_eq!(checked_block.header(), &header);
        assert_eq!(checked_block.transactions(), &transactions);
        assert_eq!(checked_block.cached_witness_root(), witness_root);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_into_parts() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions.clone());
        let (block_header, block_transactions) = block.into_parts();
        assert_eq!(block_header, header);
        assert_eq!(block_transactions, transactions);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_cached_witness_root() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions);
        let witness_root = Some(WitnessMerkleNode::from_byte_array([0x88; 32]));
        let checked_block = block.assume_checked(witness_root);
        assert_eq!(checked_block.cached_witness_root(), witness_root);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_validation_no_transactions() {
        let header = dummy_header();
        let transactions = Vec::new(); // Empty transactions

        let block = Block::new_unchecked(header, transactions);
        matches!(block.validate(), Err(InvalidBlockError::NoTransactions));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_validation_invalid_coinbase() {
        let header = dummy_header();

        // Create a non-coinbase transaction (has a real previous output, not all zeros)
        let non_coinbase_tx = Transaction {
            version: crate::transaction::Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn {
                previous_output: crate::OutPoint {
                    txid: crate::Txid::from_byte_array([1; 32]), // Not all zeros
                    vout: 0,
                },
                script_sig: crate::ScriptSigBuf::new(),
                sequence: units::Sequence::ENABLE_LOCKTIME_AND_RBF,
                witness: crate::Witness::new(),
            }],
            outputs: vec![crate::TxOut {
                amount: units::Amount::ONE_BTC,
                script_pubkey: crate::ScriptPubKeyBuf::new(),
            }],
        };

        let transactions = vec![non_coinbase_tx];
        let block = Block::new_unchecked(header, transactions);

        matches!(block.validate(), Err(InvalidBlockError::InvalidCoinbase));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_decoder_read_limit() {
        let mut coinbase_in = crate::TxIn::EMPTY_COINBASE;
        coinbase_in.script_sig = crate::ScriptSigBuf::from_bytes(vec![0u8; 2]);

        let block = Block::new_unchecked(
            dummy_header(),
            vec![Transaction {
                version: crate::transaction::Version::ONE,
                lock_time: crate::absolute::LockTime::ZERO,
                inputs: vec![coinbase_in],
                outputs: vec![crate::TxOut {
                    amount: units::Amount::MIN,
                    script_pubkey: crate::ScriptPubKeyBuf::new(),
                }],
            }],
        );

        let bytes = encoding::encode_to_vec(&block);
        let mut view = bytes.as_slice();

        let mut decoder = Block::decoder();
        assert!(decoder.read_limit() > 0);
        let needs_more = decoder.push_bytes(&mut view).unwrap();
        assert!(!needs_more);
        assert_eq!(decoder.read_limit(), 0);
        assert_eq!(decoder.end().unwrap(), block);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn header_decoder_read_limit() {
        let header = dummy_header();
        let bytes = encoding::encode_to_vec(&header);
        let mut view = bytes.as_slice();

        let mut decoder = Header::decoder();
        assert!(decoder.read_limit() > 0);
        let needs_more = decoder.push_bytes(&mut view).unwrap();
        assert!(!needs_more);
        assert_eq!(decoder.read_limit(), 0);
        assert_eq!(decoder.end().unwrap(), header);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_check_witness_commitment_optional() {
        // Valid block with optional witness commitment
        let mut header = dummy_header();
        header.merkle_root = TxMerkleNode::from_byte_array([0u8; 32]);
        let coinbase = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![],
        };

        let transactions = vec![coinbase];
        let block = Block::new_unchecked(header, transactions);

        let result = block.check_witness_commitment();
        assert_eq!(result, (true, None));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_block_hash() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions);
        assert_eq!(block.block_hash(), header.block_hash());
    }

    #[test]
    fn block_hash_from_header() {
        let header = dummy_header();
        let block_hash = header.block_hash();
        assert_eq!(block_hash, BlockHash::from(header));
    }

    #[test]
    fn block_hash_from_header_ref() {
        let header = dummy_header();
        let block_hash: BlockHash = BlockHash::from(&header);
        assert_eq!(block_hash, header.block_hash());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_hash_from_block() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions);
        let block_hash: BlockHash = BlockHash::from(block);
        assert_eq!(block_hash, header.block_hash());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_hash_from_block_ref() {
        let header = dummy_header();
        let transactions = vec![];
        let block = Block::new_unchecked(header, transactions);
        let block_hash: BlockHash = BlockHash::from(&block);
        assert_eq!(block_hash, header.block_hash());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn header_debug() {
        let header = dummy_header();
        let expected = format!(
            "Header {{ block_hash: {:?}, version: {:?}, prev_blockhash: {:?}, merkle_root: {:?}, time: {:?}, bits: {:?}, nonce: {:?} }}",
            header.block_hash(),
            header.version,
            header.prev_blockhash,
            header.merkle_root,
            header.time,
            header.bits,
            header.nonce
        );
        assert_eq!(format!("{:?}", header), expected);
    }

    #[test]
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    fn header_display() {
        let seconds: u32 = 1_653_195_600; // Arbitrary timestamp: May 22nd, 5am UTC.

        let header = Header {
            version: Version::TWO,
            prev_blockhash: BlockHash::from_byte_array([0xab; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0xcd; 32]),
            time: BlockTime::from(seconds),
            bits: CompactTarget::from_consensus(0xbeef),
            nonce: 0xcafe,
        };

        let want = concat!(
            "02000000",                                                         // version
            "abababababababababababababababababababababababababababababababab", // prev_blockhash
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", // merkle_root
            "50c38962",                                                         // time
            "efbe0000",                                                         // bits
            "feca0000",                                                         // nonce
        );
        assert_eq!(want.len(), 160);
        assert_eq!(format!("{}", header), want);

        // Check how formatting options are handled.
        let want = format!("{:.20}", want);
        let got = format!("{:.20}", header);
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    fn header_hex() {
        let header = dummy_header();

        let want = concat!(
            "01000000",                                                         // version
            "9999999999999999999999999999999999999999999999999999999999999999", // prev_blockhash
            "7777777777777777777777777777777777777777777777777777777777777777", // merkle_root
            "02000000",                                                         // time
            "03000000",                                                         // bits
            "04000000",                                                         // nonce
        );

        // All of these should yield a lowercase hex
        assert_eq!(want, format!("{:x}", header));
        assert_eq!(want, format!("{}", header));

        // And these should yield uppercase hex
        let upper_encoded =
            want.chars().map(|chr| chr.to_ascii_uppercase()).collect::<alloc::string::String>();
        assert_eq!(upper_encoded, format!("{:X}", header));
    }

    #[test]
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    fn header_from_hex_str_round_trip() {
        // Create a header and convert it to a hex string
        let header = dummy_header();

        let lower_hex_header = format!("{:x}", header);
        let upper_hex_header = format!("{:X}", header);

        // Parse the hex strings back into headers
        let parsed_lower = Header::from_str(&lower_hex_header).unwrap();
        let parsed_upper = Header::from_str(&upper_hex_header).unwrap();

        // The parsed header should match the originals
        assert_eq!(header, parsed_lower);
        assert_eq!(header, parsed_upper);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_decode() {
        // Make a simple block, encode then decode. Verify equivalence.
        let header = Header {
            version: Version::ONE,
            #[rustfmt::skip]
            prev_blockhash: BlockHash::from_byte_array([
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
            ]),
            #[rustfmt::skip]
            merkle_root: TxMerkleNode::from_byte_array([
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
            ]),
            time: BlockTime::from(1_742_979_600), // 26 Mar 2025 9:00 UTC
            bits: CompactTarget::from_consensus(12_345_678),
            nonce: 1024,
        };

        let block: u32 = 741_521;
        let transactions = vec![Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: units::absolute::LockTime::from_height(block).unwrap(),
            inputs: vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint::COINBASE_PREVOUT,
                // Coinbase scriptSig must be 2-100 bytes
                script_sig: crate::script::ScriptSigBuf::from_bytes(vec![0x51, 0x51]),
                sequence: crate::sequence::Sequence::MAX,
                witness: crate::witness::Witness::new(),
            }],
            outputs: vec![crate::transaction::TxOut {
                amount: units::Amount::ONE_SAT,
                script_pubkey: crate::script::ScriptPubKeyBuf::new(),
            }],
        }];
        let original_block = Block::new_unchecked(header, transactions);

        // Encode + decode the block
        let encoded = encoding::encode_to_vec(&original_block);
        let decoded_block = encoding::decode_from_slice(encoded.as_slice()).unwrap();

        assert_eq!(original_block, decoded_block);
    }

    // Test vector provided by tm0 in issue #5023
    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn merkle_tree_hash_collision() {
        // https://learnmeabitcoin.com/explorer/block/00000000000008a662b4a95a46e4c54cb04852525ac0ef67d1bcac85238416d4
        // this block has 7 transactions
        const BLOCK_128461_HEX: &str = "01000000166208c96de305f2a304130a1b53727abf8fb77e8a3cfe2a831e000000000000d4fd086755b4d46221362a09a4228bed60d729d22362b87803ff44b72c138ec04a8ce94d2194261af9551f720701000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08042194261a026005ffffffff018076242a01000000434104390e51c3d66d5ee10327395872e33bc232e9e1660225c9f88fa594fdcdcd785d86b1152fb380a63cdf57d8cf2345a55878412a6864656b158704e0b734b3fd9dac000000000100000001f591edc180a889b21a45b6bd5b5e0017d4137dae9695703107ac1e6e878c9f02000000008b483045022100e066df28b29bf18bfcd8da11ea576a6f502f59e7b1d37e2e849ee4648008962b022023be840ec01ffa6860b5577bf0b8546541f40c287eb57b8b421a1396c7aea583014104add16286f51f68cee1b436d0c29a41a59fa8bd224eb6bec34b073512303c70fc3d630cb4952416ef02340c56bee2eef294659b4023ea8a3d90a297bdb54321f9ffffffff02508470b5000000001976a91472579bbeaeca0802fde07ce88f946b64da63989388ac40aeeb02000000001976a914d2a7410246b5ece345aa821af89bff0b6fa3bcaa88ac0000000001000000016197cb143d4cef51389076fdee3f62c294b65bc9aff217a6c71b9dd987e22754000000008c493046022100bf174e942e4619f4e470b5d8b1c0c8ded9e2f7a6616c073c5ab05cc9d699ede3022100a642fa9d0bcc89523635f9468e4813a120b233a249678de0ebf7ba398a4205f6014104122979c0ac1c3af2aa84b4c1d6a9b3b6fa491827f1a2ba37c4b58bdecd644438da715497a44b16aedbadbd18cf9765cdb36851284f643ed743c4365798dd314affffffff02c0404384000000001976a91443cd8fbad7421a53f9e899a2c9761259705d465b88acc0f4f50e000000001976a9142f6c963506b0a2c93a09a92171957e9e7e11a7a388ac00000000010000000228a11f953c26d558a8299ad9dc61279d7abc9a4059820b614bf403c05e471c481d0000008b48304502205baff189016e6fee8e0faa9eebdc8f150d2d3815007719ceccabd995607bb0b0022100f4cc49ef0b29561e976bf6f6f7ae135f665b8dd38a67634bb6bbe74c0da9c1f7014104dd5920aedc3f79ace9c8061f3724812f5b218ea81d175dd990071175874d6c79025f9db516ab23975e510645aabc4ee699cc5c24358a403d15a7736a504399f8ffffffff191b06773a7cec0bb30539f185edbf1d139f9756071c6ae395c1c29f3e2484f6010000008c493046022100c7123436476f923cd8dacbe132f5128b529baa194c9aedc570402d8d2d7902ac02210094e6974695265d96d5859ab493df00c90b62a84dcc33a05753aea23b38c249670141041d878bc5438ff439490e71d059e6b687e511336c0aa53e0d129663c91db71cfe20008891f1e4780bf1139ec9c9e81bfd2e3ea9009608a78d96a5a3a5bf7812baffffffff0200093d00000000001976a914fd0d4c3d0963db8358bd01ba6f386d4c5ef2e30288ac0084d717000000001976a914dcb1e8e699eb9f07a1ddfd5d764aa74359ddd93088ac00000000010000000118e2286c42643e6146669b0f5ee35454fe256aac2b1401dbeefd941f2e6d2074000000008b483045022100edec1c5078fed29d808282d62f167eb3f0ea6a6655f3869c12eca9c63d8463c2022031a3ae430be137932059b4a3e3fb7f1e1f2a05065dbc47c3142972de45c76daa01410423162e5ac10ec46c4a142fea3197cc66e614b9f28f014882ebc8271c4ab6022e474ccdc246445dd2479f9de217e8aaf4d770da15aff1078d329c02e0f4de8d77ffffffff02b00ac165000000001976a914f543a7f0dfcd621a05c646810ba94da791ed14c488ac80de8002000000001976a9144763f6309b3aca0bff49ed6365ffbd791b1afc5d88ac0000000001000000014e3632994e6cbcae4122bf9e8de242aa1d7c13bf6d045392fa69fa92353f13cf000000008c493046022100c6879938322e9945dae2404a2b104b534df7fdab5927a30a57a12418d619c3b8022100c53331f402010cbdc8297d7a827154e42263fc2f6cef6e56b85bbc061d5e30810141047e717e70b8c5e928bc2c482662dbe9007113f7a5fb0360da1d2f193add960fed97ab3163e85c02b127829d694ab4a796326918d4f639d0b19345f7558406667dffffffff0270c8b165000000001976a9146c908731300d5c0a4215ba3bb3041b4f313d14f688ac40420f00000000001976a91457b01e2a6bf178a10a0e36cd3e301a41ac58b68b88ac000000000100000001a2e94f26db15d7098104a3616b650cc7490eca961a23111c12c3d94f593ab3bc000000008c493046022100b355076f2c956d7565d44fdf589ebdbdff70abcd806c71845b47d31c3579cbc00221008352a03c5276ba481ae92a2327307ad1ce9b234be7386c105fb914ceb9c63341014104872ee8390f11c8ac309df772362614ff7c99f98e1fd68888c5e8765d630c93ae86fcd33922b17f5da490ea14a9f9002ef4e7fb11166ba399f9794296ca02e401ffffffff02f07d5460000000001976a914ff1da11fbd50b9906e78c694169c19902d2ee20388ac804a5d05000000001976a91444d5774b8277c59a07ed9dce1225e2d24a3faab188ac00000000";
        let bytes: [u8; 1948] = hex_unstable::FromHex::from_hex(BLOCK_128461_HEX).unwrap();
        let valid_block: Block<Unchecked> = encoding::decode_from_slice(&bytes).unwrap();
        let (header, mut transactions) = valid_block.clone().into_parts();
        transactions.push(transactions[6].clone());
        let forged_block = Block::new_unchecked(header, transactions);

        assert!(valid_block.validate().is_ok());
        assert!(forged_block.validate().is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn witness_commitment_from_coinbase_simple() {
        // Add witness commitment to the coinbase
        let magic = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        let mut pubkey_bytes = [0; 38];
        pubkey_bytes[0..6].copy_from_slice(&magic);
        let witness_commitment =
            WitnessCommitment::from_byte_array(pubkey_bytes[6..38].try_into().unwrap());
        let commitment_script = crate::script::ScriptBuf::from_bytes(pubkey_bytes.to_vec());

        // Create a coinbase transaction with witness commitment
        let tx = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: commitment_script,
            }],
        };

        // Test if the witness commitment is extracted properly
        let extracted = witness_commitment_from_coinbase(&tx);
        assert_eq!(extracted, Some(witness_commitment));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn witness_commitment_from_non_coinbase_returns_none() {
        let tx = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn {
                previous_output: crate::OutPoint {
                    txid: crate::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: crate::ScriptSigBuf::new(),
                sequence: units::Sequence::ENABLE_LOCKTIME_AND_RBF,
                witness: crate::Witness::new(),
            }],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::ScriptPubKeyBuf::new(),
            }],
        };

        assert!(witness_commitment_from_coinbase(&tx).is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_check_witness_commitment_empty_script_pubkey() {
        let mut txin = crate::TxIn::EMPTY_COINBASE;
        let push = [11_u8];
        txin.witness.push(push);

        let tx = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![txin],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                // Empty scriptbuf means there is no witness commitment due to no magic bytes.
                script_pubkey: crate::script::ScriptBuf::new(),
            }],
        };

        let block = Block::new_unchecked(dummy_header(), vec![tx]);
        let result = block.check_witness_commitment();
        assert_eq!(result, (false, None)); // (false, None) since there's no valid witness commitment
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_check_witness_commitment_no_transactions() {
        // Test case of block with no transactions
        let empty_block = Block::new_unchecked(dummy_header(), vec![]);
        let result = empty_block.check_witness_commitment();
        assert_eq!(result, (false, None));
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn block_check_witness_commitment_with_witness() {
        let mut txin = crate::TxIn::EMPTY_COINBASE;
        // Single witness item of 32 bytes.
        let witness_bytes: [u8; 32] = [11u8; 32];
        txin.witness.push(witness_bytes);

        // pubkey bytes must match the magic bytes followed by the hash of the witness bytes.
        let script_pubkey_bytes: [u8; 38] = hex_unstable::FromHex::from_hex(
            "6a24aa21a9ed3cde9e0b9f4ad8f9d0fd66d6b9326cd68597c04fa22ab64b8e455f08d2e31ceb",
        )
        .unwrap();
        let tx1 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![txin],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::from_bytes(script_pubkey_bytes.to_vec()),
            }],
        };

        let tx2 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::new(),
            }],
        };

        let block = Block::new_unchecked(dummy_header(), vec![tx1, tx2]);
        let result = block.check_witness_commitment();

        let exp_bytes: [u8; 32] = hex_unstable::FromHex::from_hex(
            "fb848679079938b249a12f14b72d56aeb116df79254e17cdf72b46523bcb49db",
        )
        .unwrap();
        let expected = WitnessMerkleNode::from_byte_array(exp_bytes);
        assert_eq!(result, (true, Some(expected)));
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "hex"))]
    fn block_check_witness_commitment_invalid_witness() {
        let mut txin = crate::TxIn::EMPTY_COINBASE;
        let witness_bytes: [u8; 32] = [11u8; 32];
        // First witness item is 32 bytes, but there are two witness elements.
        txin.witness.push(witness_bytes);
        txin.witness.push([12u8]);

        let script_pubkey_bytes: [u8; 38] = hex_unstable::FromHex::from_hex(
            "6a24aa21a9ed3cde9e0b9f4ad8f9d0fd66d6b9326cd68597c04fa22ab64b8e455f08d2e31ceb",
        )
        .unwrap();
        let tx1 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![txin],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::from_bytes(script_pubkey_bytes.to_vec()),
            }],
        };

        let tx2 = Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![crate::TxIn::EMPTY_COINBASE],
            outputs: vec![crate::TxOut {
                amount: units::Amount::MIN,
                script_pubkey: crate::script::ScriptBuf::new(),
            }],
        };

        let mut header = dummy_header();
        let transactions = vec![tx1, tx2];
        header.merkle_root = compute_merkle_root(&transactions).unwrap();

        let block = Block::new_unchecked(header, transactions);
        assert_eq!(block.check_witness_commitment(), (false, None));
        assert!(matches!(block.validate(), Err(InvalidBlockError::InvalidWitnessCommitment)));
    }

    #[test]
    fn version_encoder_emits_consensus_bytes() {
        let version = Version::from_consensus(123_456_789);
        let mut encoder = version.encoder();

        assert_eq!(encoder.current_chunk(), &version.to_consensus().to_le_bytes());
        assert!(!encoder.advance());
    }

    #[test]
    fn version_decoder_end_and_read_limit() {
        let mut decoder = VersionDecoder::new();
        let bytes_arr = Version::TWO.to_consensus().to_le_bytes();
        let mut bytes = bytes_arr.as_slice();

        assert!(decoder.read_limit() > 0);

        let needs_more = decoder.push_bytes(&mut bytes).unwrap();
        assert!(!needs_more);
        assert!(bytes.is_empty());

        assert_eq!(decoder.read_limit(), 0);
        let decoded = decoder.end().unwrap();
        assert_eq!(decoded, Version::TWO);
    }

    #[test]
    fn version_decoder_default_roundtrip() {
        let version = Version::from_consensus(123_456_789);
        let mut decoder = VersionDecoder::default();
        let consensus = version.to_consensus().to_le_bytes();
        let mut bytes = consensus.as_slice();
        decoder.push_bytes(&mut bytes).unwrap();

        assert_eq!(decoder.end().unwrap(), version);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn block_decoder_error() {
        let err_first = Block::decoder().end().unwrap_err();
        assert!(matches!(err_first.0, encoding::Decoder2Error::First(_)));
        assert!(!err_first.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(std::error::Error::source(&err_first).is_some());

        // Provide a complete header and a vec length prefix (1 tx) but omit any tx bytes.
        // This forces the inner VecDecoder to error when finalizing.
        let mut bytes = encoding::encode_to_vec(&dummy_header());
        bytes.push(1u8);
        let mut view = bytes.as_slice();

        let mut decoder = Block::decoder();
        assert!(decoder.push_bytes(&mut view).unwrap());
        assert!(view.is_empty());

        let err_second = decoder.end().unwrap_err();
        assert!(matches!(err_second.0, encoding::Decoder2Error::Second(_)));
        assert!(!err_second.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(std::error::Error::source(&err_second).is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn header_decoder_error() {
        let header_bytes = encoding::encode_to_vec(&dummy_header());
        // Number of bytes in the encoding up to the start of each field.
        let lengths = [0usize, 4, 36, 68, 72, 76];

        for &len in &lengths {
            let mut decoder = Header::decoder();
            let mut slice = header_bytes[..len].as_ref();
            decoder.push_bytes(&mut slice).unwrap();
            let err = decoder.end().unwrap_err();
            match len {
                0 => assert!(matches!(err, HeaderDecoderError::Version(_))),
                4 => assert!(matches!(err, HeaderDecoderError::PrevBlockhash(_))),
                36 => assert!(matches!(err, HeaderDecoderError::MerkleRoot(_))),
                68 => assert!(matches!(err, HeaderDecoderError::Time(_))),
                72 => assert!(matches!(err, HeaderDecoderError::Bits(_))),
                76 => assert!(matches!(err, HeaderDecoderError::Nonce(_))),
                _ => unreachable!(),
            }
            assert!(!err.to_string().is_empty());
            #[cfg(feature = "std")]
            assert!(std::error::Error::source(&err).is_some());
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn invalid_block_error() {
        #[cfg(feature = "std")]
        use std::error::Error as _;

        let variants = [
            InvalidBlockError::InvalidMerkleRoot,
            InvalidBlockError::InvalidWitnessCommitment,
            InvalidBlockError::NoTransactions,
            InvalidBlockError::InvalidCoinbase,
        ];

        for variant in variants {
            assert!(!variant.to_string().is_empty());
            #[cfg(feature = "std")]
            assert!(variant.source().is_none());
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn version_decoder_error() {
        let err = encoding::decode_from_slice::<Version>(&[0x01]).unwrap_err();
        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(std::error::Error::source(&err).is_some());
    }
}
