// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use core::fmt;

use hashes::{Hash, HashEngine};

use super::Weight;
use crate::blockdata::script;
use crate::blockdata::transaction::Transaction;
use crate::consensus::{encode, Decodable, Encodable};
pub use crate::hash_types::BlockHash;
use crate::hash_types::{TxMerkleNode, WitnessCommitment, WitnessMerkleNode, Wtxid};
use crate::internal_macros::impl_consensus_encoding;
use crate::pow::{CompactTarget, Target, Work};
use crate::prelude::*;
use crate::{io, merkle_tree, VarInt};

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] commiting to all transactions in the block.
///
/// [merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// ### Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,

    pub aux_data: Option<AuxPow>,


}

//impl_consensus_encoding!(Header, version, prev_blockhash, merkle_root, time, bits, nonce);
impl Decodable for Header {
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, encode::Error> {
        let base = SimpleHeader::consensus_decode_from_finite_reader(reader)?;
        if (base.version.0 & 0x100) == 0 {
            return Ok(Header {
                version: base.version,
                prev_blockhash: base.prev_blockhash,
                merkle_root: base.merkle_root,
                time: base.time,
                bits: base.bits,
                nonce: base.nonce,
                aux_data: None,
            });
        }else{
            let aux_data = AuxPow::consensus_decode_from_finite_reader(reader)?;
            Ok(Header {
                version: base.version,
                prev_blockhash: base.prev_blockhash,
                merkle_root: base.merkle_root,
                time: base.time,
                bits: base.bits,
                nonce: base.nonce,
                aux_data: Some(aux_data),
            })
        }
    }

    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {

        use crate::io::Read as _;
        let mut r = reader.take(encode::MAX_VEC_SIZE as u64);
        let thing = SimpleHeader::consensus_decode(r.by_ref())?;
        if (thing.version.0 & 0x100) == 0 {
            return Ok(Header {
                version: thing.version,
                prev_blockhash: thing.prev_blockhash,
                merkle_root: thing.merkle_root,
                time: thing.time,
                bits: thing.bits,
                nonce: thing.nonce,
                aux_data: None,
            });
        }else{
            let aux_data = AuxPow::consensus_decode(r.by_ref())?;
            Ok(Header {
                version: thing.version,
                prev_blockhash: thing.prev_blockhash,
                merkle_root: thing.merkle_root,
                time: thing.time,
                bits: thing.bits,
                nonce: thing.nonce,
                aux_data: Some(aux_data),
            })
        }
    }
}
impl Encodable for Header {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = self.version.consensus_encode(writer)?;
        len += self.prev_blockhash.consensus_encode(writer)?;
        len += self.merkle_root.consensus_encode(writer)?;
        len += self.time.consensus_encode(writer)?;
        len += self.bits.consensus_encode(writer)?;
        len += self.nonce.consensus_encode(writer)?;
        if (self.version.0 & 0x100) != 0 {
            len += self.aux_data.as_ref().unwrap().consensus_encode(writer)?;
        }
        Ok(len)
    }
}

#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct SimpleHeader {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

impl_consensus_encoding!(SimpleHeader, version, prev_blockhash, merkle_root, time, bits, nonce);

impl Header {
    /// The number of bytes that the block header contributes to the size of a block.
    // Serialized length of fields (version, prev_blockhash, merkle_root, time, bits, nonce)

    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine).expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
    pub fn target(&self) -> Target { self.bits.into() }

    /// Computes the popular "difficulty" measure for mining.
    pub fn difficulty(&self) -> u128 { self.target().difficulty() }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    pub fn difficulty_float(&self) -> f64 { self.target().difficulty_float() }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError> {
        let target = self.target();
        if target != required_target {
            return Err(ValidationError::BadTarget);
        }
        let block_hash = self.block_hash();
        if target.is_met_by(block_hash) {
            Ok(block_hash)
        } else {
            Err(ValidationError::BadProofOfWork)
        }
    }

    /// Returns the total work of the block.
    pub fn work(&self) -> Work { self.target().to_work() }
    pub fn get_size(&self) -> usize {
        /*if self.aux_data.is_none() {
            return 80
        }else{
            80 + self.aux_data.unwrap().get_size()
        }*/
        80
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


impl fmt::Debug for SimpleHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            //.field("block_hash", &self.block_hash())
            .field("version", &self.version)
            .field("prev_blockhash", &self.prev_blockhash)
            .field("merkle_root", &self.merkle_root)
            .field("time", &self.time)
            .field("bits", &self.bits)
            .field("nonce", &self.nonce)
            .finish()
    }
}


#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct MerkleBranch {
    pub hashes: Vec<BlockHash>,
    // Bitmask of which side of the merkle hash function the branch_hash element should go on.
    // Zero means it goes on the right, One means on the left.
    // It is equal to the index of the starting hash within the widest level
    // of the merkle tree for this merkle branch.
    pub side_mask: u32,
}
impl_consensus_encoding!(MerkleBranch, hashes, side_mask);


#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]

pub struct AuxPow {

    pub coinbase_tx: Transaction,
    pub block_hash: BlockHash,
    pub coinbase_branch: MerkleBranch,
    pub blockchain_branch: MerkleBranch,
    pub parent_block: SimpleHeader,
}

impl_consensus_encoding!(AuxPow, coinbase_tx, block_hash, coinbase_branch, blockchain_branch, parent_block);
impl AuxPow {
    pub fn get_size(&self) -> usize {
        self.coinbase_tx.total_size()+32+self.coinbase_branch.hashes.len()*32+self.blockchain_branch.hashes.len()*32+80
        
    }
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
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(pub i32);

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
    pub fn from_consensus(v: i32) -> Self { Version(v) }

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

impl Encodable for Version {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version)
    }
}

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
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>,
}

impl_consensus_encoding!(Block, header, txdata);

impl Block {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }

    /// Checks if merkle root of header matches merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    pub fn check_witness_commitment(&self) -> bool {
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.txdata.iter().all(|t| t.input.iter().all(|i| i.witness.is_empty())) {
            return true;
        }

        if self.txdata.is_empty() {
            return false;
        }

        let coinbase = &self.txdata[0];
        if !coinbase.is_coinbase() {
            return false;
        }

        // Commitment is in the last output that starts with magic bytes.
        if let Some(pos) = coinbase
            .output
            .iter()
            .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
        {
            let commitment = WitnessCommitment::from_slice(
                &coinbase.output[pos].script_pubkey.as_bytes()[6..38],
            )
            .unwrap();
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some(witness_root) = self.witness_root() {
                    return commitment
                        == Self::compute_witness_commitment(&witness_root, witness_vec[0]);
                }
            }
        }

        false
    }

    /// Computes the transaction merkle root.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.txid().to_raw_hash());
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Computes the witness commitment for the block's transaction list.
    pub fn compute_witness_commitment(
        witness_root: &WitnessMerkleNode,
        witness_reserved_value: &[u8],
    ) -> WitnessCommitment {
        let mut encoder = WitnessCommitment::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_engine(encoder)
    }

    /// Computes the merkle root of transactions hashed for witness.
    pub fn witness_root(&self) -> Option<WitnessMerkleNode> {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::all_zeros().to_raw_hash()
            } else {
                t.wtxid().to_raw_hash()
            }
        });
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Returns the weight of the block.
    ///
    /// > Block weight is defined as Base size * 3 + Total size.
    pub fn weight(&self) -> Weight {
        // This is the exact definition of a weight unit, as defined by BIP-141 (quote above).
        let wu = self.base_size() * 3 + self.total_size();
        Weight::from_wu_usize(wu)
    }

    /// Returns the base block size.
    ///
    /// > Base size is the block size in bytes with the original transaction serialization without
    /// > any witness-related data, as seen by a non-upgraded node.
    fn base_size(&self) -> usize {
        let mut size = self.header.get_size();

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.base_size()).sum::<usize>();

        size
    }

    /// Returns the total block size.
    ///
    /// > Total size is the block size in bytes with transactions serialized as described in BIP144,
    /// > including base data and witness data.
    pub fn total_size(&self) -> usize {
        let mut size = self.header.get_size();

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.total_size()).sum::<usize>();

        size
    }

    /// Returns the stripped size of the block.
    #[deprecated(since = "0.31.0", note = "use Block::base_size() instead")]
    pub fn strippedsize(&self) -> usize { self.base_size() }

    /// Returns the coinbase transaction, if one is present.
    pub fn coinbase(&self) -> Option<&Transaction> { self.txdata.first() }

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).

        if self.header.version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase().ok_or(Bip34Error::NotPresent)?;
        let input = cb.input.first().ok_or(Bip34Error::NotPresent)?;
        let push = input.script_sig.instructions_minimal().next().ok_or(Bip34Error::NotPresent)?;
        match push.map_err(|_| Bip34Error::NotPresent)? {
            script::Instruction::PushBytes(b) => {
                // Check that the number is encoded in the minimal way.
                let h = script::read_scriptint(b.as_bytes())
                    .map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    Ok(h as u64)
                }
            }
            _ => Err(Bip34Error::NotPresent),
        }
    }
}

impl From<Header> for BlockHash {
    fn from(header: Header) -> BlockHash { header.block_hash() }
}

impl From<&Header> for BlockHash {
    fn from(header: &Header) -> BlockHash { header.block_hash() }
}

impl From<Block> for BlockHash {
    fn from(block: Block) -> BlockHash { block.block_hash() }
}

impl From<&Block> for BlockHash {
    fn from(block: &Block) -> BlockHash { block.block_hash() }
}

/// An error when looking up a BIP34 block height.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip34Error {
    /// The block does not support BIP34 yet.
    Unsupported,
    /// No push was present where the BIP34 push was expected.
    NotPresent,
    /// The BIP34 push was larger than 8 bytes.
    UnexpectedPush(Vec<u8>),
    /// The BIP34 push was negative.
    NegativeHeight,
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Bip34Error::*;

        match *self {
            Unsupported => write!(f, "block doesn't support BIP34"),
            NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            UnexpectedPush(ref p) => {
                write!(f, "unexpected byte push of > 8 bytes: {:?}", p)
            }
            NegativeHeight => write!(f, "negative BIP34 height"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Bip34Error::*;

        match *self {
            Unsupported | NotPresent | UnexpectedPush(_) | NegativeHeight => None,
        }
    }
}

/// A block validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The header hash is not below the target.
    BadProofOfWork,
    /// The `target` field of a block header did not match the expected difficulty.
    BadTarget,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ValidationError::*;

        match *self {
            BadProofOfWork => f.write_str("block target correct but not attained"),
            BadTarget => f.write_str("block target incorrect"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::ValidationError::*;

        match *self {
            BadProofOfWork | BadTarget => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::{test_hex_unwrap as hex, FromHex};

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};

    #[test]
    fn test_coinbase_and_bip34() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();

        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(block.coinbase().unwrap().txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // block with 9-byte bip34 push
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d09a08601112233445566000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();

        let push = Vec::<u8>::from_hex("a08601112233445566").unwrap();
        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::UnexpectedPush(push)));
    }
#[test]
fn block2(){
    let dd = hex!("010000009156352c1818b32e90c9e792efd6a11a82fe7956a630f03bbee236cedae3911a1c525f1049e519256961f407e96e22aef391581de98686524ef500769f777e5fafeda352f0ff0f1e001083540101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e04afeda3520102062f503253482fffffffff01004023ef3806000023210338bf57d51a50184cf5ef0dc42ecd519fb19e24574c057620262cc1df94da2ae5ac00000000");
    let block: Block = deserialize(&dd).unwrap();
    println!("{:?}",block);
}
    #[test]
    fn block_test() {
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        let some_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000");
        let merkle = hex!("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c");
        let work = Work::from(0x100010001_u128);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(1));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1231965655);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(486604799));
        assert_eq!(real_decode.header.nonce, 2067413810);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(), 1);
        assert_eq!(real_decode.header.difficulty_float(), 1.0);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.total_size(), some_block.len());
        assert_eq!(real_decode.base_size(), some_block.len());
        assert_eq!(
            real_decode.weight(),
            Weight::from_non_witness_data_size(some_block.len() as u64)
        );

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[test]
    fn segwit_block_test() {
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000");
        let merkle = hex!("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e");
        let work = Work::from(0x257c3becdacc64_u64);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(Version::USE_VERSION_BITS as i32)); // VERSIONBITS but no bits set
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(real_decode.header.time, 1472004949);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(0x1a06d450));
        assert_eq!(real_decode.header.nonce, 1879759182);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(), 2456598);
        assert_eq!(real_decode.header.difficulty_float(), 2456598.4399242126);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.total_size(), segwit_block.len());
        assert_eq!(real_decode.base_size(), 4283);
        assert_eq!(real_decode.weight(), Weight::from_wu(17168));

        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), segwit_block);
    }

#[test]
fn block_version_test() {
    let block = hex!("ffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    let decode: Result<Block, _> = deserialize(&block);
    assert!(decode.is_ok());
    let real_decode = decode.unwrap();
    assert_eq!(real_decode.header.version, Version(2147483647));

    let block2 = hex!("000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    let decode2: Result<Block, _> = deserialize(&block2);
    assert!(decode2.is_ok());
    let real_decode2 = decode2.unwrap();
    assert_eq!(real_decode2.header.version, Version(-2147483648));
}

#[test]
    fn block_version_test2() {
        let block = hex!("02000000be4ed111b4d13733bd0a245ee73d1233830e9075430e9e6c78fbe18f93a0ac12de14a8b25fc21e4273919d5ddd4bd60731663884fff22ee6bed10261267c75319d86fd52eb7e261b004821843101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2303a08601062f503253482f049186fd5208080030c207000000092f7374726174756d2f0000000001a8f80742a91f00001976a9146209ed8017ee7c7efcfccb5c971ba58a951749af88ac00000000010000000116b362b652c601435f94a6ecfc6c71a1fd240d58f5e4443cc6f3f31f7eae500b010000006b483045022100ca9176c3eccd6ab443b1259698c35a40f8274e5b87222e2a69a1d1937398c59f02205390042fa802df9a26923e6d972ed837cb7f297e307cb84a3cdee61c8d6f3a08012102f8ae61694000cff50ae14e80994c34fa6bb672d8503e904adc0f43dd7ec14f04ffffffff0200a0724e180900001976a914101f0445d2cee10c1f820dac0fdab961c35c594088acf2e893c4a45801001976a9146026526eeaff25b0dbf335e95241ff7ff990a59888ac000000000100000001d405cda6ec490b6189a09f22d3fa68795b91563aca04a91aa1964b70b2a0a674000000006a47304402200ef30fb2d38f4f28bcee60e9e5f9b0d45a09fc908ddf459eec231d128a2f14540220683d7eade3a0cce01ac986eed294cf8644cf0689ae67823853dca88591d98cdd0121039e8e4887fc41bbf3c2384548391b76e3e43ab8880416947f640b11fc665cbef5ffffffff02ce25bc125bd406001976a9140ca60499e9ccf01717dfd7a9c40f7bc8226a448f88ac0ff005b3520000001976a9142ce991b0fa2bb82b085382685c90b8f7f19513db88ac0000000001000000013f263cc3b5077e90920396055357b2d44535b222cff61579211cbaac51f388c8000000006a47304402206b12cd8abfea1a24cf90136b46f57d39cf0c826a5ec070296396ea2bc2c13152022054bf823e9dc35cb09867736189f31df1f51ce4cd6fcff06be51db8ba5e5ffd8501210287614929460d7acb7aef3b11194fff34e20d6253842d1f73e535a4fe7b5f70dfffffffff0276272c6fa30000001976a91427691601ceb91d590c42d52e6e90868ab2e5f23588ac00e87648170000001976a914ab215e1613facb3a426a4f553e6c7b20b58bf86088ac0000000001000000020045a1d9128ebf682cccae605df74316eb1b2644f656143866cad5f1ceebd99a010000006b4830450221008e71a618a5c424667664b52401fd42c2ce38f41b29a9250d72fa3781b1b4585c02200cde3f5ad65e61d5a8e792a2cd6f742ee0a8d08d6a194293b92940d85285cb080121030e2247d028860a11b4ca970f81dfac88a0dbecb44d4f11100045ce365b6155e1ffffffff33fafe002f76a2ddcb1862762eb6bffd75ad8d549277bdb047af211153187026010000006b483045022100f39be19e4786c4da61e58b46812b56e8b53ccb533a7dddc7695ae82ebb1e2bef02203fabde51827acb8fc918df241c02856bc3be01491c2aea9f07f4ea19aa78e2a40121030e2247d028860a11b4ca970f81dfac88a0dbecb44d4f11100045ce365b6155e1ffffffff01c1d2c57fec0100001976a914cf4f2986e58650a5acece7c81a56a374c9c5170188ac0000000001000000016b3a866916195b44b1ef1eeca6bd42444d30bd801653eae356827286d7170732000000006b48304502210095052e425fc05be614f6312bdcd8acb7ada011a1d3575d5dbcdd203c4ee09e6f022001f66b82f8c59c13a60f6aa84f5a991dd54cc47a89d189326e813665e7e7cb6e012103db50768756c7daaa9096e537afe542415da9649668023c26b9013ccb04a72db2ffffffff02711af552470e00001976a914301ab2c3a86972dee0bc2250be7e1e4f3f55886388aca3dede6fe20000001976a9142f119fccae2f2ea71689280aeec457b10fdd6e4488ac000000000100000004c61f35d758b2dd4c8aa93161a7e6597b078545942219c9e1eb9d2560206a385b010000006b483045022100d758b832dd4a379ca2ce15f23ea42263b47608e483316ee7bad9153ac7a9e2f202205ab6e79d3147042945e6e1710fd0c571b0a7b9c606a257f34bfbec8d1d17786f012103557da6fd76f671f830b68f9d52976e720dde17ba43c4d09575c017f6bddb3971ffffffff3b124474a1f49e26b62314d1ae2c72222b6a2022191b6733989382a844d386f6010000006a473044022036de6e36f40a8db90e565fc398b463742d6e6751b6c5eb758563138f4a063e3a022078234eda7e829eb9458c7ab35a210fa47f1355d48c61ff5cfb31be7e42ed33e001210303911d4a1c0ad1530ad241ca2caab9038b21ed86055ac940ea58e5634c385501ffffffff5b953461686be8fd321b14f90ec8f3bc5e1b83063e2bf2894345d4a90aad0022010000006b483045022100d98d5f9dbec259b2fce4e9f8201b07f27f4025853beb331be91e1704e304b2ba02205808df049a59145f9526cc37cbed772468e58c3d7bc50a37c752456681c7bfd501210303911d4a1c0ad1530ad241ca2caab9038b21ed86055ac940ea58e5634c385501ffffffff0046dde73f58ddeb824e8997f39a1b417bb45d5f69a16e57d65830cc0d3bd8a7000000006c4930460221008a2dfb6cdaeda83eaddc3e4e79b5f5a4b63b813470f7cfc1d4e380f0d45a5dd9022100e05932debf59fceebf7d0fb3b55e50eaac1746b2b3ed27a3a446d92579937143012102e3c99ec61db654fcb1829fdfb707f475b501829a945fe46d994db2cc24fd9b10ffffffff010012ca97310000001976a914c737ab4785a1e88d8b6152e7207fc3372ff61ee088ac0000000001000000012a3acddcefc9eeec8c3e3ad2842d8d1bd45285a89f30602b115678fba2ffdf0e000000006a4730440220263463850fda3f7e45c1f0926c0d5b9e16bb4fd5535eb8c23b77363f673973d702202b93f4623898f4e066e05077c6bc13e9122c427de55a329f54521927d9e6ee6a0121034bfaa8a15fe5d3384352580f1a84f7f49924115af4a7c8b02da899047c2314c4ffffffff02b61ffe532f0c00001976a91423c97abb9080b029155d4634f988783a00510ddc88ac08e2c7e0060000001976a9149b65a61c3413185d315ff12f326a9c3ac8a4debd88ac000000000100000001776a633c641b3ad5632bfd32acd0301c6686229b915f3c842b1cc24220804853000000006c493046022100e82121319e327d1070bd1b8afeeb060e88cbe10bd468d228dc77bb506f8b661d022100d00a705efd8265ef18113acf35ac9fbb46fe113902828e1d72eb4bcb9bdf7b6b0121036eb7d2dabc6560354251f252a51475c5ed559830681ba0838d89d494282d0c79ffffffff02bda713e9815500001976a91442f185de5643d0e4653d9f50b54eec6d016769fe88acab5dc8623a0000001976a91495e2bd1549e434d9528203966aed9f00ca101dee88ac00000000010000000186befd244b4ac06a0c93f3c84b31ffe8364aa270c359f49c24a27e38aa37542d000000006a4730440220401773baf69df3b93fb0b51c82b2c05e39ea665e3302d060d1005368a06143c102206535d87af7aed9886d68682b082a408e52f41ea1a92d4aca90cec83610af8a9a012103aa2c2048bf90b9a2de755412c6b0c0f66f21dc76cc14bcc4f64cacc3e515c4bdffffffff02ae70d1b54f4900001976a91450008196da21b76532b492ab97dc991456ad179a88ac521d8077260000001976a9146d0bc9d3c908d759b0e0a59a5c26d69e37256c1f88ac00000000010000000137ed67ebea136256834f48ffed22e469cf5e5659d52227ff28a5213482defdb7000000006c493046022100907a2c31acd9ed8cab0f2b8c94249d1a5bfd06c01024cefddfd2225f967d32ab022100f9cb99ddb4edc5eebe70d5f5588767a978e21a7fb8c86c037ed6c1ef83e63de20121038cb41f889e7658adee33cb1d8ec5f9586424ed2a4b92e56373e756b1aad300aeffffffff02a4ed016fa20b00001976a9148841590909747c0f97af158f22fadacb1652522088ac409d1a9c0a0000001976a914efb6158f75743c611858fdfd0f4aaec6cc6196bc88ac0000000001000000015ac6959f5f8e0d14df1c45da8567d0a2dc4cf682431359cab2a192c81a854e3f000000006b48304502204f4132692261b237ed877b76a722a7e58d48e9157f013fbba6f6adc6944e83ce022100a0a64c156aabd409fea754d225a8c16e6a2a2920b1b6b3f01162734e160dcd530121022b9fafc77f470ed11756a82e4d27dc8229196779525b73aa170d0adde7ef050fffffffff02008dff52da0900001976a9142f6c6ee207403395836335e4460e96e7f583701c88ac00b080f6450100001976a9143eda58dd12a5edca008ce105fe3847f96016f17188ac0000000001000000010daae87a56b318b250d9ae5c59573cdc555c5d1e73a2b6840b04755c1c2aba22010000006b4830450220720793be4b7812a7b4b7ae6dd75cf37da09ddd4630debc09c34bf95782d16bdc022100f5f609629a559bcd96dcf82cb1657aa6374af78d3114c2f57d9f6fb204c97718012103c584550e0b922323d39a357da5ee977e14a117fda1812ece91f33b06072cf49dffffffff0200943577000000001976a9142deeef21adf2cf1d0fc8cf31efcf11af2321595d88acba4c55c9000000001976a9148a10bf7df695647d408a07d765699d41280663d888ac00000000010000000830e60439eea77624e4b76424de72dc4345bad8e76d807459dce817155c39973c010000006b483045022021771a95a44f1acf88dcc0ac8b50f1756a96b648e0e8b130dfbc762c90d61806022100f40b7d1b643acf3b73ad32af99215fb8154cdd05b85d1d080fec154f7eefddb00121033779d94eb445e945e3c3ce7c815359e48a946dbf313b0375f979affd48d01fb4ffffffff5c506722bb545a465580685aeef32954da84574af3b805afbce40fac86029a5a010000006b483045022044b6c1506abf9823213034aea8c84f49435b1ac559bdc0bcd6d7d9f1d4b53207022100e22b75114b911a014cd42a24e243a42b22ee15422ef61cab61072ca547a9404e0121036774ad1017adb3fd13a756d7c76ad15c1dc49f37b71ea516c7cf93bbbd263c3cffffffff6afcf22f0f2db24119f4c3ddefee090be003430b72232170b8f3ab6c507074c6080000008c493046022100e36e614f3ec699fb3ecc9b7e496ddde2c91c583db9c6a64b94e46722d0e2dc22022100c55c3d38f915ecf046041b6e4594cddf86b27c5d83d7b291cb9815d58d33e7620141045d3e839d9eabede7593c0d89536f07904362dcbc2aa5cfeaa83aafa8ea9589a87bea418925a3db2f177b9c69d4fe48ed07b6960871e63828889e481a1e9c9a93ffffffffd0dd3a135633b1430afcd03e950dae8cacb097f0b8611b141124c057ddadca5a060000008c493046022100ec08de1e701770a39203c7063f8439e9f44fcb523b3c0aad33fa96d7a5e56988022100a36e1e438eb9b1856e9e03b7b783e1b1275045043f9aae10be42ab98e2428e6a0141045d3e839d9eabede7593c0d89536f07904362dcbc2aa5cfeaa83aafa8ea9589a87bea418925a3db2f177b9c69d4fe48ed07b6960871e63828889e481a1e9c9a93ffffffff9358deef5ff9ba99dc31189630f768cb4f879cb5764f587f71c1ccfd85ba51df150000008a47304402205536e7eee100668ec379b4fc39f1f33ada52b35514c0357d9df8a18750f675240220484100a77b44fd0c11ade5080e276558c3f9e23cc026539c86be1af30bd4e5720141045d3e839d9eabede7593c0d89536f07904362dcbc2aa5cfeaa83aafa8ea9589a87bea418925a3db2f177b9c69d4fe48ed07b6960871e63828889e481a1e9c9a93ffffffffd7f1a826d5cc65f19f91c0ec6fb84053e07683d6b115b4daf3b6a96548ddb0d2050000008b4830450220515a77a326e3e244b25cf9ba3baeb8636aad3bc2752a13c58d4792f65052c5b3022100b5edc14a0e2939dd3c0e352748513df88ca916aff9ea229cb0dd46f2d541ebb00141045d3e839d9eabede7593c0d89536f07904362dcbc2aa5cfeaa83aafa8ea9589a87bea418925a3db2f177b9c69d4fe48ed07b6960871e63828889e481a1e9c9a93ffffffff3cc94bda0348772bf4dd971f7f55a44f8131044fd92213d731dc2f5b4f2262b3000000006c4930460221008135f2ef5ffd16bb7d108cc71ebd23350933b479a73b9f48e2d682990fff5d29022100ac5a830a573e213dbbd4631ada472d523dcf64c072b58fbbef07613834430d93012102166b3359503760d953e25a996b1edac224b307d126392b2ac72a45105958891cffffffff5d6713f106f331dad761116e5550fa4ae73ef53a86e0542d9f98835cd9172d5e040000008a473044022006ebce6cb99658d714e226b2e941e490a32be41eb06fa8bc0ba824ea4cedf3c0022062bd83669800bd7ff0ac29b23fe5853cb61d633edb200af813a9d5cdea3e53da0141045d3e839d9eabede7593c0d89536f07904362dcbc2aa5cfeaa83aafa8ea9589a87bea418925a3db2f177b9c69d4fe48ed07b6960871e63828889e481a1e9c9a93ffffffff0200c96c4e170000001976a914e03b2b3d04e726d27a442d5421ec94decd16014888ac21371600000000001976a914803a518d40f3c7eea80fe8a1501a81f1d21074e488ac0000000001000000024b88e1b58dfa49925b1ca091e7d1b8c43d546abff36c9f41e062aa2ec8b3b22d010000006c493046022100fca35a551d811f047d7bc8d2c96c48fca7425fdc56c23aa88f1a5d3e8dd590ec022100a7ff992c9eb3fbea30de1f98444b3855287c608fbe549e847d295c24c461235e0121030182db728d46cb7e09bac5ea81607f412b71d960e9337a905ff27ca46cfb2f6bffffffffeb2c6f0507d80ed63213c0dd699926f300c87c4e61aa7d075206b1c0b3dead8c000000006c493046022100b7a2a3e62f84521b76f0229009327b6d532805d865871a184955a3b608c8ef6a022100d64a49c81dd3063f86ea82190074bc33953ec8fb40b22267bca89e01578710cd012103bb3381cb1421d7c77193a25b80c978c8badc3a4bc4a9d6fa4450aae0ff77daa3ffffffff0100e87648170000001976a9140c5c994d75cc4c188c11dbf406a041f08344727688ac000000000100000002edef21f2e6dbd1da2ee5371bdfbe9290359002cbe6816486a520873be909e6a6000000006b483045022100b0c043dc01eeb9dcf3851e8b41a101a01626b0c0d9ed051acc1822fb44b7818c022042752baafbfea2d8311577aa1c96582280904130c9df864c3428551ef6e4454e012102184363f5cfdd6138a5e574dba3fba87583d0073252e23542e572f284dc29d25fffffffff8e869d76156f8b545ccb31ff5ec09b4746bf6412a0a1e1c64d0f956a1aa851f7010000006a47304402204d1520941c1eb5cbd1f21a7d3a583c6ee240600faeda6ef5f881ba7a80c519cc02204e327651ef12d337176a324d52aa8a83b9511fa0dbab436c9995a5fec2e7778a012102184363f5cfdd6138a5e574dba3fba87583d0073252e23542e572f284dc29d25fffffffff0200205fa0120000001976a914aa72ef734a5414fc4249fcc4aee8a3b430b2892e88ac00eadd8d040000001976a91472285613b3fd6a077445991cad0046969ba5a62788ac000000000100000001ab6d5cb4ff11e8cdd710c403a8d33e5c3eafd87d7185879818b063f7efb8548e010000006a4730440220554a6519fe2755db4c1a3310574cafc0601cde7a424c898d86b43d1732a6b566022038ec16a38b8f7c69effe12c2c1eff4a29895ed446d173b32c65759b8161f09e0012103b8c8e44691a1811f355dc610fd322028e1f6937a2a5d32097e891dae605b810cffffffff0200e40b54020000001976a9143824aa2f78626ad32d3d6fc23ec0bf1380df4bfe88ac008dbce3180000001976a914c24e84b87e6ff62318799e2d86969b1cb3a5a68f88ac000000000100000001cdbee0abc61024d2d9d40e7119d73d5770203d7415b7297811a7e9e102ac5520000000006a4730440220648eb9b8160073b298fe4f5e3ce044c6b78665bd739fe44defc618ccfc839ec602201fa37293e3a466e746b690c9688bf97a6cc74572dcd4ab632750705574939025012102a8a7f85c202ea64ac08fd248388e60f62688d0505ea7210d7a36cd6d00ac3648ffffffff0236d96447810f00001976a914bbacd0ef6d81ba9910e2c8428041a65442a370ea88acc5973993240000001976a914ac0b37041f4e2b6337aee944364a614c942ac4fc88ac0000000001000000010591e2ab8b8a503aa69bfd5688862cee828d43c14c09bcd78e3920ba2fa37f18010000006a473044022079b1d0f7f649b8e5e8634f7deeb6482a57b0af090770e061b2c8d1cfba71cc3002203ce0560db5aca86716971b11fb9b03723d90272a49376d78ef0ecee7dff810e40121038fa4eabe1d7463d13d6c86a92fcc3e8000473adc41cb07c372ba9e06a3f43194ffffffff0280c52d8b010000001976a9143c4d481aa7776cc867de67143b9f9df65a445ff488ac8021f416030000001976a914706631056aa360576922550a808c268cfa578cd988ac0000000001000000013ac16d8d789c616a9908d1b2d8405c49594dd76f85b0102fda9cdaa2600f69e9010000006b483045022100e86e4db2ecd8e13333c6c6ea53576f9f66c19c7ed9bc3e4e62ad37a3fc89caa4022057d05333637ea5b9d76df538ce4302f0798f6e5d1e48d49eaba5bc629c1d41f2012103d7c35f0c7c24c510ba334ae5f3f7d86e5c0af94b8d2ccd7adc052b2f7e1d6b4dffffffff0200b1bcdd040000001976a914c3fa20522ee60c30e8e90f0d508336d49655823088ac00943577000000001976a914ae3d035ba09bce98918bb13021e650f1dfb3b08588ac000000000100000001688cd393eaf5aea8516e11dc5f395a449bab1ca6f5c6fc679cac6bd781d5d85d4c0000006b48304502204ce49efb622982dba187c0767c163560fd272f032470af9b1f7c0de04120b783022100d108d2f2878c78d5a4afcb4a1259310752f648e5383e10bec24cae296a1ab4ad012103979d6d85a49d18deb678c3dbfd9ec73a82ee61971c08e63d2e4db37361094212ffffffff01bdbe798c320000001976a9147936b878100ccc012d4eecc7124accc6774078de88ac0000000001000000019cb1fb0be32828d9a5fb4d8d2cad34e1d351a1a5990692c09fc9522f3c788d52010000006a47304402206a3fbe36f6e9c09ca3e6920cc5ec214950bec7db3144c407c8d58f0c7b1f05830220585881d965f59e53e9e5b83c3617c10595e7d362ebf7e00c0ba8bb3c2c102e100121023134cc9962bd55c25349192e30686f7e06b1e71effb83ea98bc142ab71d4976affffffff0100e721a2040000001976a914d68cb846739bd68d4bfe6346ca0e7de32268af8e88ac000000000100000001a42ca3dce24910f351f385912d8a37ea87cee8917ad4a90a95ccccd193405e13000000006b483045022100e1636331779607619dab8254b599f7191d5c9a1139529f38a8a7aefc406a152402206ae7739b822c205ae044507da67b6e356688841d093ec87d76cc60f7d223ff5001210318c5bd2030e074abc39f5b34f3642500dd2f33eb686f78983fb639417ad0645bffffffff0220b5a664310200001976a91453645d0ee901a62b5b91590c6cda95e42409cbe888ac80f0fa02000000001976a91488a65118c4d13c1a526f4de4fff41b9b35d816cc88ac00000000010000000184b219412d00a2e9431f60de222b1a96f4edf2f4c886bf7d5c2e226f4cf2f367000000006a47304402200aea45983a1b2fd6d3c521b9dc8b9b7a90f11f68c4beec7eacb755125c1074c5022054a938bfc624d5b7c0f74bf4eff2620babf41739675786f8f95f9ea2f89ca15901210210afe85ead8d32a4f338cc9b5e3ebe7e68fccfa1b05ceb846d51174bb6e5c8b8ffffffff0200cce06ccc0000001976a91485648c7c54342b76befc69a7f6a02d0b7e3c047988ac00e1f505000000001976a914289888fd9f4d032d43aad4485d5dba6b931834e988ac000000000100000001de633d4e614214b2c4f630f82f78cbf01cdbdb31265f99480204149a0d736dbf000000006a473044022068c5edbae3e6626bc7da3029d0df0cd59114ad5d2e8533f4f26439251361d88302204a940ea94bebb8e9d1d93822fa23e11c23037c7971f36b3b3e839aa243d4e2c3012103a93d999bb383a6bd9cf802101b66245e2c6cbbce302ac964893a8e7f187e9461ffffffff0200a3e111000000001976a9148849b263f7d808f2fc97241944b94f2849b2601488ac00b5cab32b0000001976a914a6f534602558d53a1aa3ed98bb8816ba3ceac02088ac000000000100000001d9b3c3b27f52d72e93c88e2bdf54ddfdb27027119401eb0c33a4b17b0640e2c0000000006b48304502203747cb4c101b4b2b8d3815cccd9baeefb36cea2f595e6306db56b242a08f74c2022100a8f83b573154c23f82f8d1ca002fb10fe8c55033ae86625d6a1644a9b00f27fd01210316d1f584e2a315261fefb1b1c77cdc22eecc4e34244ff46742100083a4a62498ffffffff0282fabeab080000001976a91412ece6e9180a15251177f66e39f0dca7fe1947c688acf3ba0401000000001976a9140be8cc678017ea9c9eafeaac63ddfa31fc2136e088ac00000000010000000168423f1633c4f503cc0971638c89e00f453dff809b11aefe65e48db83869f348000000006b48304502206dd4ecf7e1c79cb139b8bf4507f48f1bd5a3ce207ec10807496ca7a7dabf4526022100ba0a3b99eba4e0cb86d175fe82873b165b2f06f65663f43929424e6632d561290121021bfcc1615687c72e64cc9d06f57501602a09a3e8e612cdc9a66bee2668f3a3a1ffffffff0261c7bcae070000001976a914a24be5ff2adcb5fc0c5e360b553ceb22a425a64b88acbdbd174c130000001976a914d690e204b63c98c0470b2b7ea3367ba109719aa088ac000000000100000001f12e57c8b3456b9dc8a7403938a2822a57843fdb537543a73332d7e5e78f85f7000000006b48304502206978be3154ae94d58f6abd4cd916bce8f587d53f1646868463edbaaca82ab6c7022100cdd208ea5bfcaabfe37801a5fd29cd83db2e2ae28cf4a229fa1fa58beadf90860121036a59c0bad2fcda23a69c78adea325b58466ca59d5126bcc69faea043beaa1e25ffffffff014a2a95c60e0000001976a914e2c4c95cdb866f579f93977d668de345b8388e6a88ac000000000100000002acd75dffa180f9fa929653841e9c61c8553d067d00ea9a7141dad6880984a63f010000006a47304402206513136d876906f9917998e344cb080473e441c0be2b59900dae0221b04d077a02203409c91aae44643cdd98da8597372d53edd019af6936974eb04b292d53848b27012102a9bc6c4bc078f805cd1c7aca4404069adc7717879ebdd679ee1a246c7e6f4bf3ffffffffd19f37347a4549891e3dfd0e7eab911d9e67196ddcbf41502ffef1773bd7a98b000000006b48304502203d3f097f0eeea4f998347d842f564dc9e3f5d0612b4dbff3bfb84298814484e302210086e60299707e98f069aa99f9f05e1494b3ccae4e1cdd1e62c36dbf6a6049d27f012102e8d9f3ea4da6cb2dd65250fe694c94bf27788a98d5ef6b02e62da5f0bb6ab20bffffffff021d29473a000000001976a914af0f58fc983699ce76cb6ef18fc271dcdfb79ff588ac00904e5a030000001976a914fb1a23206fad89723d855e5a80ccb9daa149244088ac00000000010000000133a2e5e307a65f0345ea33901d307f63000139b3132a288d9a66016a8bb0abb8010000006a47304402200c66f408e869b1506f117c993d009df3b075a68b9ce4e62f1c92f783dcd860d702204b6aefac1539e90dd35b9c3fb0c8256a2f3c11c77c98c65121bfb80deba1f96b012102f7740849c2c6c4be311a1fb669e15b8af78bd201d15a4433d82d981724e3dfe8ffffffff0200eec1ee150000001976a914515ff6aef100b80aa0bc0f825e4197d398b4885688ac006d7c4d000000001976a914016b5977c4a98b00ce4bdd731d42896d3947149b88ac0000000001000000012371105379e58d8fa4d403ccd3d0bbd2f360e49e49d6fd81d2b94ca9aeba2290000000006c4930460221008210281a12b168f02c3f45e79996ff06f3aa7cfa25cf956d54c9bbc59403a7c30221008ac2008fe26f403d43e254c9ff4ef9534229bb7137aa57184e7e415354fa030f01210362027b5a4959973f0c005653e7bfbcdb557099ee42e9053aabf6138594fb2ebeffffffff0200ff0f270b0000001976a9148e6da23aea89b44790320e2821d77735b86d711288ac006d7c4d000000001976a91428dae9efa934162c0c4e17ea75687731eff374f188ac000000000100000001d0b5959c1487e2d4f3de202b52ce9286cba3060e3a8ebce06c735472d67bc813000000006c4930460221009fcf3285a07360f3fabd1306f66b1ac965e9d178ca9ceaf7487a292d96cc8792022100d74380ddb3da48f986ffb8b063124a97a79a1500f5bfd5181d97fb0cb026c7a3012102487c3f3cc9a5f443107c36fa06844b64dd8b23896d9491f6a6d698bdb511c8e9ffffffff02f00d7bcb010000001976a914318eced404c11e3c5fde840d5aaeeb9efc00c6b688ac005ed0b2000000001976a91462e9340893d0cf62a9e14eeed711e5764386f05e88ac000000000100000001c79ae575877f2670a88a53b8939c10ab6413c1ec6847f2381b9dd7d44f69bdde000000006c493046022100ed5787095d60824035f10043d2c218cffd7022f149bc6d0ad6aad7cc8a1ff7ba0221009a0fd8a6b9b74a2fba9b16da60061d5c44fd58b7e279ddc0bc5b604ada381d8901210369f29d6f5caac452d06eccb2899fdcd03ce385a050ab32c868ff29f7397eff68ffffffff0298bad24f040000001976a914171ff4c844a9eef6bb79cf374e684a70158e7d5388aca93bb11f050000001976a914a7124f6adeccce0e17e94f9a68161c52a32eafa288ac00000000010000000135a2a0611e0b326f05e48124e7a7592c0ca52a7f9a3efcadf03d74027a244018000000006c493046022100e296ff2f5a1b996c922c327c371b4e21f2fb40bdbba2f9b5befb5c74b09b9f8d02210091f07e275b035a784e4ed0a5c13c7836a90b52b739f2b3efcf47fab0dd6de59d0121038569c188cbc829f851ccda57a3235617c1909e1de2419c9c1169529b14fe0c00ffffffff0200d2496b000000001976a914b80be6e1a7bdd4b984bd5680db5179f7b645031488ac00410b38080000001976a914fc32581d33bd5eacda6158ea10cf4fd9c635d84d88ac0000000001000000038055caf093c8a044fa5429adfff3484e117fe4fe76cb27174d2b9d792b4fbb62010000006b48304502205ed4304d094741126acec996aff3fbca1c3ceac1d931886c5b9eb2575361df04022100a563593827d8f1e4d10f9cf325f51b901fc450adf0b2ff584ca4965ed1dbbb2d0121025916328cd6c38bf5f98693323158a4325fa8b333a215c2ae0b1ea4a92f673a38ffffffff8a1a976bcd51d0cf22b021b9803d7cbeb77a33e1a2dfc6ca4773320dcce7c8f7000000006b483045022100d446953828ddb670baa707ccb1ef9937d3e48660a1c90891f40ed983f71eaa0d02200413f37a60fd0cff0a99cd1e0a14d37c839e460c56771753d6f8fc99a6939927012102d7ddada145d1d5c081427f3913ce9f77e849425a2f2c4a4b66737b22a1c7488cffffffff7607d8257d5b492b8988e58186c00b6d214a401ae14105b7d9e89983fd33f584000000006c493046022100cf6bc9a14f631a69895662fad0e809e7afe4d1c11ed2c1348c40bcbc0aa6fe95022100c8fac9fbee9d8d6f637fcdcfb27c3aaa962bd80e9819bc5d64fceb078842bcd7012102d7ddada145d1d5c081427f3913ce9f77e849425a2f2c4a4b66737b22a1c7488cffffffff0280e06200000000001976a914841377b2b993ed53a7333b09856f1e02bc791ebd88ac00a3e111000000001976a914ab1b5cae43c1b925e0b89c2aa78494f1bc6f924e88ac00000000010000000181427281d6e26117258c9adb30b5d24ca412a73bb2b2613709c0af43ade44189000000006b483045022100d6bef6d56c92a90075e50ab20a0260e7e5fd5a4cec6d4943ef245bcb35df749d022013ad806ba85663476b7e0ee89ed0fa05ae2846932deeb620ff43e0d983f9a7ca012102c35c73eecb3f7498836706fab553a8a9881b5ab42ad1b726cac11a5e66f29e4bffffffff02a002c055310200001976a914605ab623319733a2ff3c7f749214cde3ab4cb05a88ac80f0fa02000000001976a914ed79e21df195f9701e91eebc2b4e69257058101b88ac0000000001000000016c873218e5dc062965e5a5179057cd27bf44c99abec60288c645f1c1c8ba9bfb000000006a47304402201412ad826f09485dcd32c11c521c80269fa077d1e19eefa828d40135e795b2bb02207dd7b8b4c065092e3f16038dec8676910aaa362d753416a3ef1600e24acca3b6012102d43a6e77148fa7584674817fccd77e564832bc623158b598ebde6812ef22b590ffffffff02a029c1e1010000001976a91445a8fb7e94982c104f1121d549c5f8d28df3ce8988ac603fa71d000000001976a9147de21cf2eb1b16f6b50dda20b9045d2ef729993c88ac000000000100000001246964d523055dcbd0e1844643ee90b05adadd1805dc5a8138e1d572109f1eb6000000006a47304402200f4874872c3f96659b59c63e219c7827e131242538ee58910ef7d37c7a440bda02200509d82aa2738a383f1f76f495ce37a20cc56530cd1139aaa009c4e4700d5f720121035f33520e83f96e1dfa8136e987471c906568959fa40ba8c0ca73a576bbe03b8dffffffff024054adf4000000001976a9146e782f433c0ed10dec2156fcf750da0f60f84f6988ac603fa71d000000001976a9148238d5ea6fdcec5b76b8792205be25b559386ac888ac000000000100000001c067ae3dbd1d8112ac2eee4e0a9455a035ff8079a57bcf035359f01896509042000000006b48304502200764a38588e468ee488372e49b111c2c060ef1dbb37bc5165216c2de7a799fe7022100bf5111c8c8f6098440513399abc45305404ab70b572feaec84379a193251c984012102ab2e8ebc9a14e3a2fea3a5dd1949a9c075664c2c57ab1b360a3ced60b5010e40ffffffff026cfb8e15000000001976a9149a41d5bc2ab936b2f6de2483cb0bef50169b6d9988ac00ca9a3b000000001976a91455c71f61392272e15347c027382677cfe67f5ad788ac000000000100000001262ed6364d4b45d407650a5374a37699b6c5ae01a70cfe034abe33c981f24b93010000006b483045022064f3cb97cf6af3a9fbb4f528b772c4486ce1050e560bc459e9d8756cbf2749de022100bfd821d47570fcbd01209f69c6b75a75c754f23a15ae9f365af59e2b88fc4f45012102b4ede20a853e1391b4a29f72fa1a76fc519ecd3b561d11ea8c0abfc638ab93b3ffffffff02a6e28d24010000001976a9149a383ebe681d88e0314d1dfb4f596dd17aa422bc88ac00ca9a3b000000001976a9147cb9e6d120be2bd152b748f8f590c926b47bf9c788ac0000000001000000010ee2653a9516e70405dccde6c2155514970fb6aa0d72b4145c844fbd929127ea000000006b4830450221009240281b701818e78f67bff775204071a9ea3215512acd8e7fff8886938cf257022043bb000937fd5c0cd99fbba19936731ec0b9a0b31c92742f62eaba2bd44625d9012102a296f5b4fd4e83cd78b5dc71e328b6ad97205f77137e26fa9c918f50ca29e71effffffff020064488a000000001976a91471f4bb8d47f4a0c0d0d87d091abb7405861e892488ac603fa71d000000001976a9141cd3b22d4ebb6f7d94187e4f7fedcea24cee11c688ac0000000001000000016d0c87bfbb6b049498ab2ab01f1bf492cf56daca99da882415c418d6700e1dd2010000006b48304502210096eb511d7c04a47fb8e2165db508253f7af87de4378a6830eb622a3527684df102203d9d823dea7ff0af1526dbb031f0dccbf520f6b294dd0c3993e05427f1c2cc2b01210214c0c53161cd86b81a01c8b12321a5f1fe8ab93b7b9ea0186fc7d606bbd03870ffffffff0200b33f71000000001976a914434608760e385a4b8d54178d41631b201c804e5b88ac008c8647000000001976a91445716aa96fbab4d30fe0355254a0954368d0987e88ac0000000001000000011d05c3c7c10aca998f5883f103e2f78f9e11e42f18d95618b782df333ea69a3e000000006b4830450221009b51194a564c121966444c476cf92b64c4667a152cb0c06875c01608924bfee702205b90d6837dd8814fcc2928d9d472521db25d5feaee69ee03e40852b75a6d57cf0121023732f8acf3eef3fea2226f2de4802b8d789d2b30909d4e9009c9d5138591605cffffffff027d9fd81c060000001976a914a5c1bad6b2e517d6df2ec67bae14e9ba77b5244f88ac057af088020000001976a9144bb19b49d47e77c216554eb718012ee1a8d58b7688ac000000000100000001e3789e9ae0d8271cde731c58f6ef02ccace4df32efa1d7aa9f719b07751a97e6010000006c493046022100c82f89daba81ffbfd05c5cb85a8238c7950e0ff6ef79994249552910eb77fee70221009f0e2c840e809d7414262c6dcb651cdaf030ff12c47b122b4409e82ef13823b401210389a12c3c8443c73ccbed2e2d529bea8edaf7a4efb8fa6c5b40d3ef68591f4ab5ffffffff0200fab459010000001976a9147ee2e69aa7226562024951cb09b15ae0520a06f888ac00943577000000001976a9144db9be540350646dc34fa78def8e04fed49d81ce88ac000000000100000001b36bf25e83b4e841acedfd08f6b81e7fde3678039a0fee8ea7cfc25b64341984000000006c493046022100a5ba6a649289c4bc5f21bc0bc0bba4b30ccee57197aead9eef44244c180bd6be022100cbb2a297103c85c434288bdd3196233231a763750e347f2bac212a10343e057e012102f4bb5a222354a9649740a8b8b300f3e1a0c7ade18a409bae7c2ea9f0ecac0575ffffffff027e04ed7ca70e00001976a914c660254bafe140f4a6ec8c248b61a5b7a427ba6788acb8f381c4d90000001976a914e0a032f63f59e7b7b9a79b9dcd7bb8121f672f3688ac00000000010000000113624b8e6c558c0b95645b5b4c611b6f07c4ae051eddd1470fc921878b158553000000006b483045022100ccdfdb7f9b45e5bf1d36b4963fa05714b0cb963e3f93d370f806166203904cd9022031d5d036bd92716e742756511a4be0ca85674f1d65cf8285eccb20bec9c09873012103d3e092b233a629befb6a2249024faebfddf944140f5403a7eedb3f011c47271dffffffff020c987287ec0d00001976a914c5207f84f009632513b304af1e69757f79d1df4588ac728b84efba0000001976a9143d9e306694eb9a55e00113a6f9b838392d15c71a88ac000000000100000001e194dd90db9b7fcf661327515006bd219636ae5b6dc23120146b52ffe508753f000000006c4930460221008e6cd035285d9434b47cca0a01d6ebb4898d1a04bf16a7ef53cdda2358283edd022100b95700890afea19b08a5b67a6bc13e85df5cce990b749e23f685986b4685076e01210273c7e637ceaa0f2fd102278d48c3d4cc60b4ba2ae24a3f5daed840e515757ed6ffffffff02a1f17efc000000001976a914110e90aa49171cc316e4d7876fed69fea686491888acc0f447ac060000001976a914c62cbb894e9889bf2898e902c57ecb79b2b0254d88ac000000000100000001a37afd10d48f0c5963c66f8b4ed5af4a546ecf2cdb8c4a1bbcc170de72df0fa0000000006b483045022100ceb7d06c357b3cf2b83f2bd50d0e498312c85e17344497193f77e020a3874afb0220296b0e6d0609c8469e7c7f8c13e3ef2212bf61ce04e898adb70348d45819eaa30121037b2e9c9fba6e830a2a12713f89ab42e87ca34ddd9a68b06768577b4f8d543801ffffffff026a9ab816000000001976a91465c5ba865bf8b0b533fb0be75856f51db71e46cf88ac3776d0df000000001976a91420717bf29cae8d800835d4a6621a8bcd92f24f2288ac0000000001000000015a021ed0fde77c37c49329b6dfeb629119710aa79706e18bd13bc89b34b17489000000006c493046022100f766c02b8be767b5e40ab2e5fca085b095883b24e76da75a7894f2134f85e2f60221008bb3fa3322b9f032eab5fbb9c3c3792629c5444a628e489bbef074507d2822bd0121039591af3b189bc9063110783ec97b1e061cd88dea2b374efcecdb2b4fdaf48d1affffffff02d8baa4478f0d00001976a9149fdbc530d583f6e0dc31e9281db0c9db39325e5a88ac34fcd7395d0000001976a914770d36fdf8a25cb438fed008540ae268e62addbf88ac00000000");
        let decode: Result<Block, _> = deserialize(&block);
        decode.unwrap();
        

        let header = hex!("02006200ea6a8fa7756fe4205c4f810655fe46148060ad2a5b4a087d98c750b3d806f5541ecc424f9c37dd88e9f49408caa6294c4faf93cc79560effdb3c760233df7fbb1699fb532781441b650f3eb7");
        let decode: Result<Header, _> = deserialize(&header);
        decode.unwrap();
    }
    
    #[test]
    fn validate_pow_test2() {
        let some_header = hex!("020162001b9db197bcb7d86e93991293f148f684e17efc6136e08b4688c6701f39d4403757dd5ccd9391273c118b600e0f497a04f3cbdebb7e6dbb699bae2fb17198d8f4b6aa8d5403f2041b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03a9970a062f503253482f04b8aa8d5408fabe6d6d92ae1083b7b3c22fd7b4ce2eae121d518f8e1aa81d0be9432ce5aa20a2954fcc0100000000000000402a29636829010018393436383834322f6d696e65722073686172705f66697265000000000100f2052a010000001976a9146a2ca895057c3b94136c8776e731cece18b46c8688ac00000000040290bc699f9cc500b676c9a782b2cd398524d6279079b3b59a74069396f81602edfe7f3fe6cd4224a01fa4bb59f5254acff79e988aaebc994337cb6d33721547417823cbe436061e508eb64060c54981df9a87f03875f84d0b70457dab12d21600000000000000000002000000f7e6f6aff383b6e2bb1d7968ccca5b6ceeaeda130879b50f09f29982431e26afbefd1c78ab2711ebd12d4c6c6e54e3ddab8cf2d860283a6ca7452f9865d32c9c6daa8d54e12a011b57975dc9");
        let some_header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");
println!("some_header: {:?}",some_header);
    }

    #[test]
    fn validate_pow_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");
        let some_header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(
            some_header.validate_pow(some_header.target()).unwrap(),
            some_header.block_hash()
        );

        // test with zero target
        match some_header.validate_pow(Target::ZERO) {
            Err(ValidationError::BadTarget) => (),
            _ => panic!("unexpected result from validate_pow"),
        }

        // test with modified header
        let mut invalid_header: Header = some_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_pow(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn compact_roundrtip_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");

        let header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");

        assert_eq!(header.bits, header.target().to_compact_lossy());
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ 1 << i) as i32;
            let version = Version(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version(0x20000000 ^ 1 << 1);
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::Block;
    use crate::consensus::{deserialize, Decodable, Encodable};
    use crate::EmptyWrite;

    #[bench]
    pub fn bench_stream_reader(bh: &mut Bencher) {
        let big_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        assert_eq!(big_block.len(), 1_381_836);
        let big_block = black_box(big_block);

        bh.iter(|| {
            let mut reader = &big_block[..];
            let block = Block::consensus_decode(&mut reader).unwrap();
            black_box(&block);
        });
    }

    #[bench]
    pub fn bench_block_serialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        let mut data = Vec::with_capacity(raw_block.len());

        bh.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        bh.iter(|| {
            let block: Block = deserialize(&raw_block[..]).unwrap();
            black_box(&block);
        });
    }
}
