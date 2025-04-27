// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.

use core::fmt;
#[cfg(feature = "alloc")]
use core::marker::PhantomData;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::{sha256d, HashEngine as _};
use units::BlockTime;

use crate::merkle_tree::TxMerkleNode;
#[cfg(feature = "alloc")]
use crate::merkle_tree::WitnessMerkleNode;
use crate::pow::CompactTarget;
#[cfg(feature = "alloc")]
use crate::prelude::Vec;
#[cfg(feature = "alloc")]
use crate::transaction::Transaction;

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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Block<V = Unchecked>
where
    V: Validation,
{
    /// The block header
    header: Header,
    /// List of transactions contained in the block
    transactions: Vec<Transaction>,
    /// Cached witness root if its been computed.
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    witness_root: Option<WitnessMerkleNode>,
    /// Validation marker.
    marker: PhantomData<V>,
}

#[cfg(feature = "alloc")]
impl Block<Unchecked> {
    /// Constructs a new `Block` without doing any validation.
    #[inline]
    pub fn new_unchecked(header: Header, transactions: Vec<Transaction>) -> Block<Unchecked> {
        Block { header, transactions, witness_root: None, marker: PhantomData::<Unchecked> }
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
            marker: PhantomData::<Checked>,
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
    fn from(block: Block) -> BlockHash { block.block_hash() }
}

#[cfg(feature = "alloc")]
impl From<&Block> for BlockHash {
    #[inline]
    fn from(block: &Block) -> BlockHash { block.block_hash() }
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
        let mut engine = sha256d::Hash::engine();
        engine.input(&self.version.to_consensus().to_le_bytes());
        engine.input(self.prev_blockhash.as_byte_array());
        engine.input(self.merkle_root.as_byte_array());
        engine.input(&self.time.to_u32().to_le_bytes());
        engine.input(&self.bits.to_consensus().to_le_bytes());
        engine.input(&self.nonce.to_le_bytes());

        BlockHash::from_byte_array(sha256d::Hash::from_engine(engine).to_byte_array())
    }
}

#[cfg(feature = "hex")]
impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write as _;
        use hex::DisplayHex as _;

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

impl From<Header> for BlockHash {
    #[inline]
    fn from(header: Header) -> BlockHash { header.block_hash() }
}

impl From<&Header> for BlockHash {
    #[inline]
    fn from(header: &Header) -> BlockHash { header.block_hash() }
}

/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if version bits is
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// # Relevant BIPs
///
/// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-34 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-9 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-9 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Constructs a new [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    #[inline]
    pub const fn from_consensus(v: i32) -> Self { Version(v) }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    #[inline]
    pub fn to_consensus(self) -> i32 { self.0 }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-9 if the first 3 bits are `001` and
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
    fn default() -> Version { Self::NO_SOFT_FORK_SIGNALLING }
}

hashes::hash_newtype! {
    /// A bitcoin block hash.
    pub struct BlockHash(sha256d::Hash);
    /// A hash corresponding to the witness structure commitment in the coinbase transaction.
    pub struct WitnessCommitment(sha256d::Hash);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(BlockHash, WitnessCommitment);
#[cfg(not(feature = "hex"))]
hashes::impl_debug_only_for_newtype!(BlockHash, WitnessCommitment);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(BlockHash, WitnessCommitment);

impl BlockHash {
    /// Dummy hash used as the previous blockhash of the genesis block.
    pub const GENESIS_PREVIOUS_BLOCK_HASH: Self = Self::from_byte_array([0; 32]);
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for Block {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let header = Header::arbitrary(u)?;
        let transactions = Vec::<Transaction>::arbitrary(u)?;
        Ok(Block::new_unchecked(header, transactions))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Header {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Header {
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
            0 => Ok(Version::ONE),
            1 => Ok(Version::TWO),
            2 => Ok(Version::NO_SOFT_FORK_SIGNALLING),
            _ => Ok(Version::from_consensus(u.arbitrary()?)),
        }
    }
}

#[cfg(test)]
mod tests {
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
        // it's fields: version, prev_blockhash, merkle_root, time, bits, nonce.
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
}
