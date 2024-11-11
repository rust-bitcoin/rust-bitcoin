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
use hashes::{sha256d, HashEngine};
use internals::compact_size;
use io::{BufRead, Write};

use super::Weight;
use crate::consensus::{encode, Decodable, Encodable};
use crate::internal_macros::{impl_consensus_encoding, impl_hashencode};
use crate::merkle_tree::{MerkleNode as _, TxMerkleNode, WitnessMerkleNode};
use crate::network::Params;
use crate::pow::{Target, Work};
use crate::prelude::Vec;
use crate::script::{self, ScriptExt as _};
use crate::transaction::{Transaction, TransactionExt as _, Wtxid};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::block::{Version, BlockHash, Header, WitnessCommitment};
#[doc(inline)]
pub use units::block::{BlockHeight, BlockInterval, TooBigForRelativeBlockHeightError};

impl_hashencode!(BlockHash);

impl_consensus_encoding!(Header, version, prev_blockhash, merkle_root, time, bits, nonce);

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Header`] type.
    pub trait HeaderExt impl for Header {
        /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
        fn target(&self) -> Target { self.bits.into() }

        /// Computes the popular "difficulty" measure for mining.
        ///
        /// Difficulty represents how difficult the current target makes it to find a block, relative to
        /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
        fn difficulty(&self, params: impl AsRef<Params>) -> u128 {
            self.target().difficulty(params)
        }

        /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
        fn difficulty_float(&self, params: impl AsRef<Params>) -> f64 {
            self.target().difficulty_float(params)
        }

        /// Checks that the proof-of-work for the block is valid, returning the block hash.
        fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError> {
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
        fn work(&self) -> Work { self.target().to_work() }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Header {}
}

impl Encodable for Version {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.to_consensus().consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version::from_consensus)
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

    /// Checks if Merkle root of header matches Merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    pub fn check_witness_commitment(&self) -> bool {
        // Consists of OP_RETURN, OP_PUSHBYTES_36, and four "witness header" bytes.
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
            let bytes = <[u8; 32]>::try_from(&coinbase.output[pos].script_pubkey.as_bytes()[6..38])
                .unwrap();
            let commitment = WitnessCommitment::from_byte_array(bytes);
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some(witness_root) = self.witness_root() {
                    return commitment
                        == Self::compute_witness_commitment(witness_root, witness_vec[0]);
                }
            }
        }

        false
    }

    /// Computes the transaction Merkle root.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.compute_txid());
        TxMerkleNode::calculate_root(hashes)
    }

    /// Computes the witness commitment for the block's transaction list.
    pub fn compute_witness_commitment(
        witness_root: WitnessMerkleNode,
        witness_reserved_value: &[u8],
    ) -> WitnessCommitment {
        let mut encoder = sha256d::Hash::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_byte_array(sha256d::Hash::from_engine(encoder).to_byte_array())
    }

    /// Computes the Merkle root of transactions hashed for witness.
    pub fn witness_root(&self) -> Option<WitnessMerkleNode> {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::COINBASE
            } else {
                t.compute_wtxid()
            }
        });
        WitnessMerkleNode::calculate_root(hashes)
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

        size += compact_size::encoded_size(self.txdata.len());
        size += self.txdata.iter().map(|tx| tx.base_size()).sum::<usize>();

        size
    }

    /// Returns the total block size.
    ///
    /// > Total size is the block size in bytes with transactions serialized as described in BIP144,
    /// > including base data and witness data.
    pub fn total_size(&self) -> usize {
        let mut size = Header::SIZE;

        size += compact_size::encoded_size(self.txdata.len());
        size += self.txdata.iter().map(|tx| tx.total_size()).sum::<usize>();

        size
    }

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
        let push = input
            .script_sig
            .instructions_minimal()
            .next()
            .ok_or(Bip34Error::NotPresent)?
            .map_err(to_bip34_error)?;
        match (push.script_num(), push.push_bytes().map(|b| b.read_scriptint())) {
            (Some(num), Some(Ok(_)) | None) =>
                Ok(num.try_into().map_err(|_| Bip34Error::NegativeHeight)?),
            (_, Some(Err(err))) => Err(to_bip34_error(err)),
            (None, _) => Err(Bip34Error::NotPresent),
        }
    }
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
    /// The BIP34 push was not minimally encoded.
    NonMinimalPush,
    /// The BIP34 push was negative.
    NegativeHeight,
}

internals::impl_from_infallible!(Bip34Error);

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Bip34Error::*;

        match *self {
            Unsupported => write!(f, "block doesn't support BIP34"),
            NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            NonMinimalPush => write!(f, "byte push not minimally encoded"),
            NegativeHeight => write!(f, "negative BIP34 height"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Bip34Error::*;

        match *self {
            Unsupported | NotPresent | NonMinimalPush | NegativeHeight => None,
        }
    }
}

#[inline]
fn to_bip34_error(err: script::Error) -> Bip34Error {
    match err {
        script::Error::NonMinimalPush => Bip34Error::NonMinimalPush,
        _ => Bip34Error::NotPresent,
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

internals::impl_from_infallible!(ValidationError);

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

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Block {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Block { header: Header::arbitrary(u)?, txdata: Vec::<Transaction>::arbitrary(u)? })
    }
}

#[cfg(test)]
mod tests {
    use hex::test_hex_unwrap as hex;
    use internals::ToU64 as _;

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::{CompactTarget, Network, TestnetVersion};

    #[test]
    fn test_coinbase_and_bip34() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();

        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(block.coinbase().unwrap().compute_txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // block with 3-byte bip34 push for height 0x03010000 (non-minimal 1)
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703010000000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();

        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::NonMinimalPush));

        // Block 15 on Testnet4 has height of 0x5f (15 PUSHNUM)
        const BLOCK_HEX_SMALL_HEIGHT_15: &str = "000000200fd8c4c1e88f313b561b2724542ff9be1bc54a7dab8db8ef6359d48a00000000705bf9145e6d3c413702cc61f32e4e7bfe3117b1eb928071a59adcf75694a3fb07d83866ffff001dcf4c5e8401010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff095f00062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX_SMALL_HEIGHT_15)).unwrap();

        assert_eq!(block.bip34_block_height(), Ok(15));

        // Block 42 on Testnet4 has height of 0x012a (42)
        const BLOCK_HEX_SMALL_HEIGHT_42: &str = "000000202803addb5a3f42f3e8d6c8536598b2d872b04f3b4f0698c26afdb17300000000463dd9a37a5d3d5c05f9c80a1485b41f1f513dee00338bbc33f5a6e836fce0345dda3866ffff001d872b9def01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff09012a062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX_SMALL_HEIGHT_42)).unwrap();

        assert_eq!(block.bip34_block_height(), Ok(42));

        // Block 42 on Testnet4 using OP_PUSHDATA1 0x4c012a (42) instead of 0x012a (42)
        const BLOCK_HEX_SMALL_HEIGHT_42_WRONG: &str = "000000202803addb5a3f42f3e8d6c8536598b2d872b04f3b4f0698c26afdb17300000000463dd9a37a5d3d5c05f9c80a1485b41f1f513dee00338bbc33f5a6e836fce0345dda3866ffff001d872b9def01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0a4c012a062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX_SMALL_HEIGHT_42_WRONG)).unwrap();

        assert_eq!(block.bip34_block_height(), Err(super::Bip34Error::NonMinimalPush));

        // Block with a 5 byte height properly minimally encoded
        // this is an overflow for ScriptNum (i32) parsing
        const BLOCK_HEX_5_BYTE_HEIGHT: &str = "000000202803addb5a3f42f3e8d6c8536598b2d872b04f3b4f0698c26afdb17300000000463dd9a37a5d3d5c05f9c80a1485b41f1f513dee00338bbc33f5a6e836fce0345dda3866ffff001d872b9def01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0d052a2a2a2a2a062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX_5_BYTE_HEIGHT)).unwrap();

        assert_eq!(block.bip34_block_height(), Err(super::Bip34Error::NotPresent));
    }

    #[test]
    fn block_test() {
        let params = Params::new(Network::Bitcoin);
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
        assert_eq!(real_decode.header.version, Version::from_consensus(1));
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
        assert_eq!(real_decode.header.difficulty(&params), 1);
        assert_eq!(real_decode.header.difficulty_float(&params), 1.0);

        assert_eq!(real_decode.total_size(), some_block.len());
        assert_eq!(real_decode.base_size(), some_block.len());
        assert_eq!(
            real_decode.weight(),
            Weight::from_non_witness_data_size(some_block.len().to_u64())
        );

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[test]
    fn segwit_block_test() {
        let params = Params::new(Network::Testnet(TestnetVersion::V3));
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000");
        let merkle = hex!("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e");
        let work = Work::from(0x257c3becdacc64_u64);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version::from_consensus(0x2000_0000)); // VERSIONBITS but no bits set
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
        assert_eq!(real_decode.header.difficulty(&params), 2456598);
        assert_eq!(real_decode.header.difficulty_float(&params), 2456598.4399242126);

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
        assert_eq!(real_decode.header.version, Version::from_consensus(2147483647));

        let block2 = hex!("000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap();
        assert_eq!(real_decode2.header.version, Version::from_consensus(-2147483648));
    }

    #[test]
    fn validate_pow_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");
        let some_header: Header =
            deserialize(&some_header).expect("can't deserialize correct block header");
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
        invalid_header.version = Version::from_consensus(invalid_header.version.to_consensus() + 1);
        match invalid_header.validate_pow(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    fn header() -> Header {
        let header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");
        deserialize(&header).expect("can't deserialize correct block header")
    }

    #[test]
    fn compact_roundrtip_test() {
        let header = header();
        assert_eq!(header.bits, header.target().to_compact_lossy());
    }

    #[test]
    fn header_block_hash_regression() {
        let header = header();
        let block_hash = "00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7";

        let want = block_hash.parse::<BlockHash>().unwrap();
        let got = header.block_hash();
        assert_eq!(got, want)
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ 1 << i) as i32;
            let version = Version::from_consensus(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version::from_consensus(0x20000000 ^ 1 << 1);
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }
}

#[cfg(bench)]
mod benches {
    use io::sink;
    use test::{black_box, Bencher};

    use super::Block;
    use crate::consensus::{deserialize, Decodable, Encodable};

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
            let size = block.consensus_encode(&mut sink());
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
