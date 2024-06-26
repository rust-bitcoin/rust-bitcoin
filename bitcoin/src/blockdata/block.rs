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
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
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
}

impl_consensus_encoding!(Header, version, prev_blockhash, merkle_root, time, bits, nonce);

impl Header {
    /// The number of bytes that the block header contributes to the size of a block.
    // Serialized length of fields (version, prev_blockhash, merkle_root, time, bits, nonce)
    pub const SIZE: usize = 4 + 32 + 32 + 4 + 4 + 4; // 80

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
        let mut size = Header::SIZE;

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.base_size()).sum::<usize>();

        size
    }

    /// Returns the total block size.
    ///
    /// > Total size is the block size in bytes with transactions serialized as described in BIP144,
    /// > including base data and witness data.
    pub fn total_size(&self) -> usize {
        let mut size = Header::SIZE;

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
        let block = hex!("0401620046c8452c09390449fc239f1aba4aa0612cf1968310e7d6f47dd079989810d49ac0aece8cb6903fa2cacb1bab9eb15aa05f743fc4e5ba48c51c06dac384ce0449e22e7c66a1f3001a0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff54033e5929ce042f42696e616e63652f31fabe6d6d5b84f34baadcb2ffdf2bf43156d645b543cefd5a6bc8ccb44325092f8e297be50100000000000000be4a47109cebc5229d722a736ddc9418ce40dafa29000000ffffffff02d8e14925000000001976a91499ce4c0a552c646353cc9e0df4c824ba2d978de588ac0000000000000000266a24aa21a9ed7a631c21f44b821c5fe847b7f62eb1c5cc61ba7b96df22b9da7d0843920a8cdf000000002a3994694a0793302c9949cb452d619fe7aaa911cf676824e6ef2bbf8f783e97082a5350107f1cb4f5bdf5334e17f90c95b30a6a4aa3f76336022fcfc49fe3809c4195783d7993aad5db09a92ca64e3e7746789eb266d0714251dc9996f92ac5b1390e9bb0b517702816548a83eb66f407d7d0547b15009a39bd856e2b36740c31d35d19f91b1a024257330f4a5835a29cc6dd38046c0d1014eb1a2f24d5a91e9ecce1ea61aabded017ec5c4a641d592fd8eac0c1ec253425e204a5551e6975d03f0ab709674e5b00ce21eb7951ad6b159186e3251c97a0b987a5d0f8ff325fde7cfae6a3193ce123950684b532d66a9ad87592b2858e856ccccdd8e8c80228fd831d398b0c02dc9012276797b4e4e0f2b52078687810ee9c8a7d609a31b474e5500000000000000000000000020b7411126a870aab8fe23f23d56cb6f5e2539d3f599d547255434c5c9e04ff8d20dad61a4afc728e2d2270fb9e9fb718b84cf86ff1cfb18e41d6bc398cc75efc0e22e7c66e85e75191b4c4f4c0d01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0603cf68500101ffffffff01387676f0e80000001976a9140f9ce4cfa9193bd9d2a7c4af4867679b0c00c86488ac000000000100000001f666e20fd60af10a3327009d7fc8684f070a2b01a322dc8ef00efe806f3c0e3d010000006a47304402206f17c4956d8e7063376a02a760482795b8daced25f505ade058d02858ac28db90220043741d349f54c7eb5dd8eeac3b58a703246d4b808ef9da741ca53082daa431c0121023f351c143c1acc5c11416c496ff732a1bf8833bccc7c39d607f95da1a345de36ffffffff02c59c2d41290000001976a914393da93b0c625a7c521fb985d07f574734f350c588ac0c2963080e0000001976a9148f4a7b79a105bb35d486e70a1fb107f2a505c19f88ac00000000010000000164bd7b6146801d6a148711dea734ba45e8d4964791750f5966a852b7784b2b49000000006a47304402203448469bac9e3f85859719c68029107b7eb8b503768f1839b651667b5c64cfa8022051208f8e50aa8441cd4931adc34a5f5d376745cd9a1ae17d2177f1c680058e0b012102914032d35e9a95481a49083e753a909db2f55bc8a4ac54d2982a582965469314fdffffff024455f010060000001976a914050393299fd2b8bc50ded0eb1fb7a0a04aad2e1888acb7228622bdba00001976a91429b11acb7edac9caf824d43a460510b46e39c5a688ac0000000001000000100e8cffd1b75a1aad9e8460100b92c9276ce9f1773e9458a397e284d4443cbd57000000006b483045022100a0f2cdff1f5079aedfb6fe379509ba0bba492aa3504a038cbeb0b6a347ec7607022028b0a0e020079354473e33d2cb96d8b8450ae3caf947e4e6c86c545692893b9e012103c1f9dfb742d1994359b554cb0bb2812b0f2e39ce0cf057e52b4d2785ae84b276ffffffff7a232a2a60ff96492b78a00fef0e8e3b72938f089962f97ef8aba3150c0f2973020000006a47304402201e517d60cbc420c6f223d3048018b338c45ecb4e2e809ba01df0a00e15aef131022048d92d169b9b6c852a1c3855f3b5a30f3b9884774d2bb1d682f88aa54fdefbb601210304ef1df979bba4ce22f9eec879aee579ba9d808dab0efc654e11087087b4249cffffffffb54556b3464f7248ba3169a9e1a5f857ab3676fea29b03e32dd2463e410030f6010000006b483045022100901f9daedbf5d806c2cf452363dead4c2d3eb4347b60a6a6f10b5458a4d36e4a02200b84dfd3e3d19ada4a8efb5833b005a951d2d21bf915e1a9cabf27139f38103e0121023d0ff80b68af1ed4240b1f9f24fca6929f15864fa80c59f12c297d8b1d8e4c76ffffffff25f6da7e2f61e6d0ebb7ba40156691a32d58d4a418ad2270e4ad15c872319c41000000006a473044022037c6075ee2a2cdc5115a5ff00759f5a8412aa629fdcca6387c691cefcbb98f56022028faf09e2d34a2595d50fcabcdfb2bcfd080dfd3696dbeed9e8ab7acadceaad9012103ca8fb26d0fd5794814717b7d64fad2f3d48566b2a7de8ecff1ff74963b7906cfffffffffeadeb1dd728c15b42f979e8e8edb9047a3842ed7619b62a612b764248931cc24010000006a473044022067470c74d49db44214820e68cb318a6d63378ae71c5bf44f98b9f17c9eb9f1bb022074d0d7717f3c680b476c9501c4c93b9dda68a137ab5b31844fbeb9599a5c6e6d0121024553640e3ce5a0e89a2a1c16c4da787416bff5ed05ce1f0bfe498d4df9f3ab1effffffffb0ea4f9039ab43df9351ee57c757a6c6659dc4e91cc345c4f9beb3d81d39bd1a000000006a473044022019efe4315949b0830e5868260df0ce70d540fa3d5b9500bb600f66fe1df6fa3102200672261d7724fcea5359f76c373efd960a0b8a4e9b67e1a5fa650c5e39c9f4020121037c60a7c47315c1b2539879d8a768bb2f24491d3a75a86954d54ee3fc1cb8740affffffffd79a647259290725bf47ebfeb20d2b039087ea5835341f7d0afbfc02cbfd497d000000006a4730440220338f13e821a734c83012e619cf26908601c8f2cef0bfae05ba826f11c5cca15a022043dd8a0b2656dbc2c4a67ca34e339f227a371d233d1728805e2529ed2f47638a012102751dd867ed7ce3b4122e9a2c6c6a2717256eaef75f87d0a0814c4e786afa8e3affffffff973d55b3b2d1427e4531479baf3d5ad53d3e7713fc92119568920963b9b80462000000006a47304402203228a5b23ed6eba46e7b40717b1db1155ba790571ff1dbe8a617dbf93a6a993f02207a518bb3f42e4f9fde1ae5a2bcc0bec17753b27648a042fe6d352e71c659d42b0121024553640e3ce5a0e89a2a1c16c4da787416bff5ed05ce1f0bfe498d4df9f3ab1effffffff9b5c6e423cbc280346ec6dcf0f79fa858420c002efaaaf523e4851c2f7dbee30000000006a473044022046f3114799fedd5c0aafda2c1accdec1ad5fd450baa9373f08eefdf0dfebb7d002204e12f5b919dbf7605a1c15e4a1aedd3964a193bf4a47d9dec81b2c7c7467d5b6012102bf774789e85213d947512a9c9a3b68355c635803e2e30c8f49be0d8d4563fdfeffffffff644215dd7d00b0d1f19a5cb152210d5725c72b2bca3ff276ebdf52ffff24dcb4020000006a47304402205d63bdc9e5254209dcc2da582b42fff046ce1e4ef310368e342ad9af961b9330022037665e641b0866adadbd32d49592ca236f02d27af3de7d68cdc9f4c11a2703bc012102b455ba7f2838f6673297bbec885387799c874bfedaac0233734d0635102e6e71ffffffffe34d4cddae80df7183fbde2c48426642ba1f0d77d821c7ee0c758e8bdb5148ab070000006a473044022071405d25e0c4a558ba3b1541b39c5d48901594694820e08a7ea5522b193369390220758393109377aebeea1d4c1242fc370ed735aedba6ff517345ba824740f31e34012102c69712eab7aadc6e176bde80cab014ae26687fbabfae0697b1991960e2da2b00ffffffff9f71a306f349b3763e8091231fdf18f4cf1e2385740d306fe6684001d8f8de9f000000006b483045022100b45d24b0eb9f7f56fbc3a8e92374a51a64b5eeffbe2c784449dabac87829388f02201198bf8a4dd797c0b8e31bd4ff6f8d55a07878e9f5a816c4bf6237ed4d221b4c0121035f0a6d6568c2a92ff34703fe60dfb10ebdf412984f9148b71807f6ae2e5bc545ffffffffad381f1ded5344b7ed595cca5ad0d467862cd8a600056aa4aa07dc50fe256f7f010000006b483045022100d643fd38af71cb2ec2c85c1c23b96fd4b0a9313d9f4174f2e2f26e62b20811be0220508e7e2a76f8ff83eb9fb94b8c2c5555b8cfc6183ef19dd9916657be68a18070012103677364230c4b406d5572e7333003068ec1abc74294c3ad021779cb885f99df02fffffffff4f9c7d0e3b6f9abb0a4b3966cfd015663f3b062909d686fe5088b1cb3c2ac7a010000006b483045022100e9c2db849eb7cfa001422c0736a1fbe64a6bad20836eba0b46d54f1a6e1a54940220162837002639f5d46385d8165bdc76873bfd9902ac5860cf2d7a7571cb5d1b2f012102f521327d77819a1d6c8c3df545de5c51fe4f5796cbc043487d77186c98724ddbffffffff6435bb8397eac6b896fbf0dce601359d053cfa96dc615951d53f2268d670eac2060000006a47304402201f684350df451dc9b6d38587f6d7c82f56e44d8ed05ad3e87b24ae2e27825fd6022076f9a7b0fecb74fb6f8f00232f407e2990a8952081c6784431f170e5a3652f7f012102f521327d77819a1d6c8c3df545de5c51fe4f5796cbc043487d77186c98724ddbffffffff84da891e6617da8300e991aba6178d8785e59f650ce74378ce7ca4fab8094d61000000006b483045022100ff7f9ec69f6db52c48a6f054ac908317a6a60c994a370b114c36f037b145666e0220758e7223e5f4b0f2a178fcc90ec9991a35dd291ca251983c93d89fc79980b4a1012102cb4c09afb9634a937abd376bd059bfec3bb0786e8131e067dbe83ef89440498cffffffff0300ffd112170000001976a9140a29fa628c3ecf51be3914f63a8bb72ac8ae7b4688ac006001ed8b0200001976a914c680b0fbd30e450ebcf2c9a6911cee703500b4ba88acda0df41e000000001976a9141d3864f7991c7c365343f2aab5fb370ac212459488ac0000000001000000012fb848dde530fb332d84baaed01ac79c7afe4e5683c4c556be3978a40cbb9b54000000006a473044022073ad6f0543cdd74df8463bbf284c1014766a4924df997627e709ed9853fd895d0220350fc3d79666bacc6acdfcc34b0c0813f5e4a7a2ea57ee6c1bfafc1e0b61e18a012103228821c04d0de58ab319b5150c18e72ef8596bc29f799065ffb2e85a443419feffffffff0200d9db900a0000001976a9140a36996db567dcd5e9d88409ed668bf04860f0c688acdfcf5441000000001976a9143b112c9c5a56e6a1db2ea33b1879c005556ffe8e88ac0000000001000000017cf3f980e05ea12576c423110527f89e1badb1cffc76566519f1bdbcc23c0ed9010000006a47304402201c9a189df7a1d58440470390a5b69cf125d211fe44bf4e1bb591e00a53af88c102203ce7f2ca0e8a876a986205e1d648beff4b1cfd4e269858d6f358807b220577aa01210324eb49c64f810015c28f566c206713138825181df1312e0a3bb52d9b1b02a012ffffffff0200f0638c0b0000001976a914addfc80a88f93270156ac053c1f158eea6b5d3a788ace097b1e3150000001976a914069c5509707d2c66487ca3b93936188c2e22cac388ac000000000100000001824632cf78b97af490b77d1687db96ca529bd959384d4f2cf320943db51ec26b000000008b483045022100b8e90cb5815141c5a4cd967d41190fd4ac4dea813b835ff1e45e5fd16aee5566022044e6d479f6e38873059db400a77ce66df513d6723d0e9806aa6b3e9cc15de654014104ab065fb810bea08d82bef9f5e5a4a73367ad5689d2a2e8b32929ea6799aad0869058dab676e6c732aede8812df7835f1b98a36c6bb29a226c8e5ce31fccf0fbeffffffff017d88bf380e0000001976a9147e4f71f10c4072d3781d83db72c95b1e5764a66488ac000000000100000001c107f676364b9381fa94bdeab232daa351351316d0a18d012242d42480f37eb60100000094036f7264510a746578742f706c61696e000f353236393730382e646f67656d6170483045022100b13d605eeb15db07ae1a8cf610074e309ec1f819e626b7344350610c8b556feb022019eafcc6bafefaa66d11f0090610d4fbf26f2b3223be8411afcfb5343375f37d01292103ddff1be43a94e4c5d6282420639b2cac49037ebea45035fcceffc74cdc8baa78ad757575757551ffffffff02a0860100000000001976a914c28bd17e3c1187aa4343797ef986b2401f0a34a688ac6029ddac3200000017a9140f8061864dca9ee6e0c25c86d617d7be7c47503c87000000000100000001e6c6bf0f501058bceed43b6b5d559108660b6872e2af797da36b68776619f6270100000093036f7264510a746578742f706c61696e000f353236393730392e646f67656d617047304402204da808708486d34e646408950d060925bda45fc7cc228001b31fa9a4d59c25a5022041d50aa6372ece7712563fa89a70b9d0470c848ad95f67ae595cd2257297b4e501292103632e948da03cec16e82d69aeb215ada99ad94e604e5390632a8e26845b89f7ffad757575757551ffffffff02a0860100000000001976a914c28bd17e3c1187aa4343797ef986b2401f0a34a688acbf932bcd0d00000017a9142586f8d7c49d293ab28bd82647436974ca7d5d4187000000000100000001001e7f3ae9c3a544b3a271cf320c6ce2723b85fa84ced5066f847612734588c00100000093036f7264510a746578742f706c61696e000f353236393730392e646f67656d617047304402201d0a2185f0c8cae54dcd564304d65ff421fdabe6104d8ab21f0e98c81faf95f9022056ecbda2f5aac215a90fa84bef83bef648506ecbb99e18ebc8ec12408e79361301292103ddff1be43a94e4c5d6282420639b2cac49037ebea45035fcceffc74cdc8baa78ad757575757551ffffffff02a0860100000000001976a914c28bd17e3c1187aa4343797ef986b2401f0a34a688acc0f13cac3200000017a9140f8061864dca9ee6e0c25c86d617d7be7c47503c87000000000100000001bdc54d4b556ad207a4af5e65fd9c2bddca1e89add3aa4cc0bcfe68f7076195bc0100000093036f7264510a746578742f706c61696e000f353236393731302e646f67656d617047304402207a05dcc603a8a39ab5980206b135380471ab45961ec3e3d2d58d02096422445a02200ab59134a5d84243e64ce156988f66b2c2726ee6b22526450dd392e6c7082cc501292103ddff1be43a94e4c5d6282420639b2cac49037ebea45035fcceffc74cdc8baa78ad757575757551ffffffff02a0860100000000001976a914c28bd17e3c1187aa4343797ef986b2401f0a34a688ac60569dab3200000017a9140f8061864dca9ee6e0c25c86d617d7be7c47503c87000000000100000001a111183d6fd473e4b7346989be6f4a544def0e11c5d9839a6b2d6186107191cb0100000094036f7264510a746578742f706c61696e000f353236393731302e646f67656d6170483045022100928978616677ef35fbc76e7857a0d608a896a7e324b441f362d9f170964f0987022044642e79d9f217c7fe8c869194c10f1c433cc4ecc0257e9945fbe2b85fce4efb01292103632e948da03cec16e82d69aeb215ada99ad94e604e5390632a8e26845b89f7ffad757575757551ffffffff02a0860100000000001976a914c28bd17e3c1187aa4343797ef986b2401f0a34a688ac5f89dccc0d00000017a9142586f8d7c49d293ab28bd82647436974ca7d5d4187000000000100000001697f6eaea4bde0f01575ac3f8c4b0f6542bf8afe2da0d0f126ae2295aefec6770100000093036f7264510a746578742f706c61696e000f353236393731312e646f67656d617047304402206a56bf5c20ac62f002223515b599fdca8bde7093792420bd72b23a4d632c908a02200088c7779839bf9f8dc5529a69826f4fd8abb4c6220523ea0f25b9b5918adc5101292103632e948da03cec16e82d69aeb215ada99ad94e604e5390632a8e26845b89f7ffad757575757551ffffffff02a0860100000000001976a914c28bd17e3c1187aa4343797ef986b2401f0a34a688acdf308dcc0d00000017a9142586f8d7c49d293ab28bd82647436974ca7d5d418700000000");
        let decode: Result<Block, _> = deserialize(&block);
        decode.unwrap();
    }
    #[test]
    fn validate_pow_test2() {
        let some_header = hex!("0401620046c8452c09390449fc239f1aba4aa0612cf1968310e7d6f47dd079989810d49ac0aece8cb6903fa2cacb1bab9eb15aa05f743fc4e5ba48c51c06dac384ce0449e22e7c66a1f3001a0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff54033e5929ce042f42696e616e63652f31fabe6d6d5b84f34baadcb2ffdf2bf43156d645b543cefd5a6bc8ccb44325092f8e297be50100000000000000be4a47109cebc5229d722a736ddc9418ce40dafa29000000ffffffff02d8e14925000000001976a91499ce4c0a552c646353cc9e0df4c824ba2d978de588ac0000000000000000266a24aa21a9ed7a631c21f44b821c5fe847b7f62eb1c5cc61ba7b96df22b9da7d0843920a8cdf000000002a3994694a0793302c9949cb452d619fe7aaa911cf676824e6ef2bbf8f783e97082a5350107f1cb4f5bdf5334e17f90c95b30a6a4aa3f76336022fcfc49fe3809c4195783d7993aad5db09a92ca64e3e7746789eb266d0714251dc9996f92ac5b1390e9bb0b517702816548a83eb66f407d7d0547b15009a39bd856e2b36740c31d35d19f91b1a024257330f4a5835a29cc6dd38046c0d1014eb1a2f24d5a91e9ecce1ea61aabded017ec5c4a641d592fd8eac0c1ec253425e204a5551e6975d03f0ab709674e5b00ce21eb7951ad6b159186e3251c97a0b987a5d0f8ff325fde7cfae6a3193ce123950684b532d66a9ad87592b2858e856ccccdd8e8c80228fd831d398b0c02dc9012276797b4e4e0f2b52078687810ee9c8a7d609a31b474e5500000000000000000000000020b7411126a870aab8fe23f23d56cb6f5e2539d3f599d547255434c5c9e04ff8d20dad61a4afc728e2d2270fb9e9fb718b84cf86ff1cfb18e41d6bc398cc75efc0e22e7c66e85e75191b4c4f4c");
        let some_header: Header =
            deserialize(&some_header[0..80]).expect("Can't deserialize correct block header");
        
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
