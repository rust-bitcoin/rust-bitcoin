// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::{sha256d, HashEngine as _};

use crate::merkle_tree::TxMerkleNode;
use crate::pow::CompactTarget;
use crate::transaction::Transaction;

/// Bitcoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// ### Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>,
}

impl Block {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }
}

impl From<Block> for BlockHash {
    fn from(block: Block) -> BlockHash { block.block_hash() }
}

impl From<&Block> for BlockHash {
    fn from(block: &Block) -> BlockHash { block.block_hash() }
}

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [Merkle tree] committing to all transactions in the block.
///
/// [Merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// ### Bitcoin Core References
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
    pub time: u32,
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
        engine.input(&self.time.to_le_bytes());
        engine.input(&self.bits.to_consensus().to_le_bytes());
        engine.input(&self.nonce.to_le_bytes());

        BlockHash::from_byte_array(sha256d::Hash::from_engine(engine).to_byte_array())
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
    fn from(header: Header) -> BlockHash { header.block_hash() }
}

impl From<&Header> for BlockHash {
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
/// ### Relevant BIPs
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

    /// Creates a [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    #[inline]
    pub const fn from_consensus(v: i32) -> Self { Version(v) }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn to_consensus(self) -> i32 { self.0 }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-9 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(&self, bit: u8) -> bool {
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
    fn default() -> Version { Self::NO_SOFT_FORK_SIGNALLING }
}

hashes::hash_newtype! {
    /// A bitcoin block hash.
    pub struct BlockHash(sha256d::Hash);
    /// A hash corresponding to the witness structure commitment in the coinbase transaction.
    pub struct WitnessCommitment(sha256d::Hash);
}

impl BlockHash {
    /// Dummy hash used as the previous blockhash of the genesis block.
    pub const GENESIS_PREVIOUS_BLOCK_HASH: Self = Self::from_byte_array([0; 32]);
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Block {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Block { header: Header::arbitrary(u)?, txdata: Vec::<Transaction>::arbitrary(u)? })
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

    #[test]
    fn test_version_is_not_signalling_with_invalid_bit() {
        let arbitrary_version = Version::from_consensus(1234567890);
        // The max bit number to signal is 28.
        assert!(!Version::is_signalling_soft_fork(&arbitrary_version, 29));
    }

    #[test]
    fn test_version_is_not_signalling_when_use_version_bit_not_set() {
        let version = Version::from_consensus(0b01000000000000000000000000000000);
        // Top three bits must be 001 to signal.
        assert!(!Version::is_signalling_soft_fork(&version, 1));
    }

    #[test]
    fn test_version_is_signalling() {
        let version = Version::from_consensus(0b00100000000000000000000000000010);
        assert!(Version::is_signalling_soft_fork(&version, 1));
    }

    #[test]
    fn test_version_is_not_signalling() {
        let version = Version::from_consensus(0b00100000000000000000000000000010);
        assert!(!Version::is_signalling_soft_fork(&version, 0));
    }
}
