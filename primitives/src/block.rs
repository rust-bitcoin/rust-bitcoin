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
use crate::transaction::{TxMerkleNodeDecoder, TxMerkleNodeDecoderError};
use crate::{BlockTime, CompactTarget, TxMerkleNode};
#[cfg(feature = "alloc")]
use crate::{BlockTimeDecoder, BlockTimeDecoderError, Transaction, WitnessMerkleNode};

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
        Encoder2<HeaderEncoder, Encoder2<CompactSizeEncoder, SliceEncoder<'e, Transaction>>>
    );
}

#[cfg(feature = "alloc")]
impl Encodable for Block {
    type Encoder<'e>
        = Encoder2<HeaderEncoder, Encoder2<CompactSizeEncoder, SliceEncoder<'e, Transaction>>>
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

#[cfg(feature = "hex")]
impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write as _;
        use hex_unstable::DisplayHex as _;

        let mut buf = arrayvec::ArrayString::<160>::new();
        write!(
            &mut buf,
            "{}{}{}{}{}{}",
            self.version.to_consensus().to_le_bytes().as_hex(),
            self.prev_blockhash.as_byte_array().as_hex(),
            self.merkle_root.as_byte_array().as_hex(),
            self.time.to_u32().to_le_bytes().as_hex(),
            self.bits.to_consensus().to_le_bytes().as_hex(),
            self.nonce.to_le_bytes().as_hex(),
        )
        .expect("total length of written objects is 160 characters");
        fmt::Display::fmt(&buf, f)
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

encoding::encoder_newtype! {
    /// The encoder for the [`Header`] type.
    pub struct HeaderEncoder(
        encoding::Encoder6<
            VersionEncoder,
            BlockHashEncoder,
            crate::merkle_tree::TxMerkleNodeEncoder,
            crate::time::BlockTimeEncoder,
            crate::pow::CompactTargetEncoder,
            encoding::ArrayEncoder<4>,
        >
    );
}

impl Encodable for Header {
    type Encoder<'e> = HeaderEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        HeaderEncoder(encoding::Encoder6::new(
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
    pub fn to_consensus(self) -> i32 { self.0 }

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

impl Default for Version {
    #[inline]
    fn default() -> Self { Self::NO_SOFT_FORK_SIGNALLING }
}

encoding::encoder_newtype! {
    /// The encoder for the [`Version`] type.
    pub struct VersionEncoder(encoding::ArrayEncoder<4>);
}

impl Encodable for Version {
    type Encoder<'e> = VersionEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        VersionEncoder(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`Version`] type.
pub struct VersionDecoder(encoding::ArrayDecoder<4>);

impl VersionDecoder {
    /// Constructs a new [`Version`] decoder.
    pub fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

impl Default for VersionDecoder {
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for VersionDecoder {
    type Output = Version;
    type Error = VersionDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        Ok(self.0.push_bytes(bytes)?)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let n = i32::from_le_bytes(self.0.end()?);
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

impl From<encoding::UnexpectedEofError> for VersionDecoderError {
    fn from(e: encoding::UnexpectedEofError) -> Self { Self(e) }
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
    use alloc::{format, vec};

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
    #[cfg(feature = "alloc")]
    fn block_decode() {
        // Make a simple block, encode then decode. Verify equivalence.
        let header = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
                0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA, 0xDC, 0xBA,
                0xDC, 0xBA, 0xDC, 0xBA,
            ]),
            merkle_root: TxMerkleNode::from_byte_array([
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
                0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
                0xAB, 0xCD, 0xAB, 0xCD,
            ]),
            time: BlockTime::from(1_742_979_600), // 26 Mar 2025 9:00 UTC
            bits: CompactTarget::from_consensus(12_345_678),
            nonce: 1024,
        };

        let block: u32 = 741_521;
        let transactions = vec![Transaction {
            version: crate::transaction::Version::ONE,
            lock_time: units::absolute::LockTime::from_height(block).unwrap(),
            inputs: vec![crate::transaction::TxIn::EMPTY_COINBASE],
            outputs: Vec::new(),
        }];
        let original_block = Block::new_unchecked(header, transactions);

        // Encode + decode the block
        let encoded = encoding::encode_to_vec(&original_block);
        let decoded_block = encoding::decode_from_slice(encoded.as_slice()).unwrap();

        assert_eq!(original_block, decoded_block);
    }
}
