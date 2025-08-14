// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.

use core::convert::Infallible;
use core::fmt;

use hashes::{sha256d, HashEngine};
use internals::{compact_size, ToU64};
use io::{BufRead, Write};

use crate::consensus::encode::{self, Decodable, Encodable, WriteExt as _};
use crate::merkle_tree::{MerkleNode as _, TxMerkleNode, WitnessMerkleNode};
use crate::network::Params;
use crate::pow::{Target, Work};
use crate::prelude::Vec;
use crate::script::{self, ScriptExt as _};
use crate::transaction::{Coinbase, Transaction, TransactionExt as _, Wtxid};
use crate::{internal_macros, BlockTime, Weight};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::block::{Block, Checked, Unchecked, Validation, Version, BlockHash, Header, WitnessCommitment};
#[doc(no_inline)]
pub use units::block::TooBigForRelativeHeightError;
#[doc(inline)]
pub use units::block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval};

#[deprecated(since = "TBD", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;

internal_macros::impl_hashencode!(BlockHash);

#[rustfmt::skip]
internal_macros::impl_consensus_encoding!(Header, version, prev_blockhash, merkle_root, time, bits, nonce);

internal_macros::define_extension_trait! {
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

impl Encodable for BlockTime {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.to_u32().consensus_encode(w)
    }
}

impl Decodable for BlockTime {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(BlockTime::from_u32)
    }
}

/// Extension functionality for the [`Block<Unchecked>`] type.
pub trait BlockUncheckedExt: sealed::Sealed {
    /// Validates (or checks) a block.
    ///
    /// We define valid as:
    ///
    /// * The Merkle root of the header matches Merkle root of the transaction list.
    /// * The witness commitment in coinbase matches the transaction list.
    fn validate(self) -> Result<Block<Checked>, InvalidBlockError>;
}

impl BlockUncheckedExt for Block<Unchecked> {
    fn validate(self) -> Result<Block<Checked>, InvalidBlockError> {
        let (header, transactions) = self.into_parts();

        if transactions.is_empty() {
            return Err(InvalidBlockError::NoTransactions);
        }

        if !transactions[0].is_coinbase() {
            return Err(InvalidBlockError::InvalidCoinbase);
        }

        if !check_merkle_root(&header, &transactions) {
            return Err(InvalidBlockError::InvalidMerkleRoot);
        }

        match check_witness_commitment(&transactions) {
            (false, _) => Err(InvalidBlockError::InvalidWitnessCommitment),
            (true, witness_root) => {
                let block = Block::new_unchecked(header, transactions);
                Ok(block.assume_checked(witness_root))
            }
        }
    }
}

/// Computes the Merkle root for a list of transactions.
pub fn compute_merkle_root(transactions: &[Transaction]) -> Option<TxMerkleNode> {
    let hashes = transactions.iter().map(|obj| obj.compute_txid());
    TxMerkleNode::calculate_root(hashes)
}

/// Computes the witness commitment for a list of transactions.
pub fn compute_witness_commitment(
    transactions: &[Transaction],
    witness_reserved_value: &[u8],
) -> Option<(WitnessMerkleNode, WitnessCommitment)> {
    compute_witness_root(transactions).map(|witness_root| {
        let mut encoder = sha256d::Hash::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        let witness_commitment =
            WitnessCommitment::from_byte_array(sha256d::Hash::from_engine(encoder).to_byte_array());
        (witness_root, witness_commitment)
    })
}

/// Computes the Merkle root of transactions hashed for witness.
pub fn compute_witness_root(transactions: &[Transaction]) -> Option<WitnessMerkleNode> {
    let hashes = transactions.iter().enumerate().map(|(i, t)| {
        if i == 0 {
            // Replace the first hash with zeroes.
            Wtxid::COINBASE
        } else {
            t.compute_wtxid()
        }
    });
    WitnessMerkleNode::calculate_root(hashes)
}

/// Checks if Merkle root of header matches Merkle root of the transaction list.
fn check_merkle_root(header: &Header, transactions: &[Transaction]) -> bool {
    match compute_merkle_root(transactions) {
        Some(merkle_root) => header.merkle_root == merkle_root,
        None => false,
    }
}

/// Checks if witness commitment in coinbase matches the transaction list.
// Returns the Merkle root if it was computed (so it can be cached in `assume_checked`).
fn check_witness_commitment(transactions: &[Transaction]) -> (bool, Option<WitnessMerkleNode>) {
    // Witness commitment is optional if there are no transactions using SegWit in the block.
    if transactions.iter().all(|t| t.inputs.iter().all(|i| i.witness.is_empty())) {
        return (true, None);
    }

    if transactions.is_empty() {
        return (false, None);
    }

    if transactions[0].is_coinbase() {
        let coinbase = transactions[0].clone();
        if let Some(commitment) = witness_commitment_from_coinbase(&coinbase) {
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.inputs[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some((witness_root, witness_commitment)) =
                    compute_witness_commitment(transactions, witness_vec[0])
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

/// Extension functionality for the [`Block<Checked>`] type.
pub trait BlockCheckedExt: sealed::Sealed {
    /// Constructs a new [`Block`].
    ///
    /// # Returns
    ///
    /// Return the block if it is valid, `None` if not. See [`Block::validate`].
    fn new_checked(
        header: Header,
        transactions: Vec<Transaction>,
    ) -> Result<Block<Checked>, InvalidBlockError>;

    /// Returns the transaction Merkle root.
    fn merkle_root(&self) -> TxMerkleNode;

    /// Returns the Merkle root of transactions hashed for witness.
    ///
    /// This value was computed during block validation and was cached at that time.
    fn witness_root(&mut self) -> Option<WitnessMerkleNode>;

    /// Returns the weight of the block.
    ///
    /// > Block weight is defined as Base size * 3 + Total size.
    fn weight(&self) -> Weight;

    /// Returns the total block size.
    ///
    /// > Total size is the block size in bytes with transactions serialized as described in BIP144,
    /// > including base data and witness data.
    fn total_size(&self) -> usize;

    /// Returns the coinbase transaction.
    ///
    /// This method is infallible for checked blocks because validation ensures
    /// that a valid coinbase transaction is always present.
    fn coinbase(&self) -> &Coinbase;

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    fn bip34_block_height(&self) -> Result<u64, Bip34Error>;
}

impl BlockCheckedExt for Block<Checked> {
    fn new_checked(
        header: Header,
        transactions: Vec<Transaction>,
    ) -> Result<Block<Checked>, InvalidBlockError> {
        let block = Block::new_unchecked(header, transactions);
        block.validate()
    }

    fn merkle_root(&self) -> TxMerkleNode { self.header().merkle_root }

    fn witness_root(&mut self) -> Option<WitnessMerkleNode> { self.cached_witness_root() }

    fn weight(&self) -> Weight {
        // This is the exact definition of a weight unit, as defined by BIP-141 (quote above).
        let wu = block_base_size(self.transactions()) * 3 + self.total_size();
        Weight::from_wu(wu.to_u64())
    }

    fn total_size(&self) -> usize {
        let mut size = Header::SIZE;

        size += compact_size::encoded_size(self.transactions().len());
        size += self.transactions().iter().map(|tx| tx.total_size()).sum::<usize>();

        size
    }

    fn coinbase(&self) -> &Coinbase {
        let first_tx = &self.transactions()[0];
        Coinbase::assume_coinbase_ref(first_tx)
    }

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).

        if self.header().version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase();
        let input = cb.first_input();
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

fn block_base_size(transactions: &[Transaction]) -> usize {
    let mut size = Header::SIZE;

    size += compact_size::encoded_size(transactions.len());
    size += transactions.iter().map(|tx| tx.base_size()).sum::<usize>();

    size
}

impl Encodable for Block<Unchecked> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        // TODO: Should we be able to encode without cloning?
        // This is ok, we decode as unchecked anyway.
        let block = self.clone().assume_checked(None);
        block.consensus_encode(w)
    }
}

impl Encodable for Block<Checked> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.header().consensus_encode(w)?;

        let transactions = self.transactions();
        len += w.emit_compact_size(transactions.len())?;
        for c in transactions.iter() {
            len += c.consensus_encode(w)?;
        }

        Ok(len)
    }
}

impl Decodable for Block<Unchecked> {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Block, encode::Error> {
        let header = Decodable::consensus_decode_from_finite_reader(r)?;
        let transactions = Decodable::consensus_decode_from_finite_reader(r)?;

        Ok(Block::new_unchecked(header, transactions))
    }

    #[inline]
    fn consensus_decode<R: io::BufRead + ?Sized>(r: &mut R) -> Result<Block, encode::Error> {
        let mut r = r.take(internals::ToU64::to_u64(encode::MAX_VEC_SIZE));
        let header = Decodable::consensus_decode(&mut r)?;
        let transactions = Decodable::consensus_decode(&mut r)?;

        Ok(Block::new_unchecked(header, transactions))
    }
}

mod sealed {
    /// Seals the extension traits.
    pub trait Sealed {}
    impl Sealed for super::Header {}
    impl<V: super::Validation> Sealed for super::Block<V> {}
}

/// Invalid block error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidBlockError {
    /// Header Merkle root does not match the calculated Merkle root.
    InvalidMerkleRoot,
    /// The witness commitment in coinbase transaction does not match the calculated witness_root.
    InvalidWitnessCommitment,
    /// Block has no transactions (missing coinbase).
    NoTransactions,
    /// The first transaction is not a valid coinbase transaction.
    InvalidCoinbase,
}

impl From<Infallible> for InvalidBlockError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for InvalidBlockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InvalidBlockError::*;

        match *self {
            InvalidMerkleRoot => write!(f, "header Merkle root does not match the calculated Merkle root"),
            InvalidWitnessCommitment => write!(f, "the witness commitment in coinbase transaction does not match the calculated witness_root"),
            NoTransactions => write!(f, "block has no transactions (missing coinbase)"),
            InvalidCoinbase => write!(f, "the first transaction is not a valid coinbase transaction"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBlockError {}

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

impl From<Infallible> for Bip34Error {
    fn from(never: Infallible) -> Self { match never {} }
}

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

impl From<Infallible> for ValidationError {
    fn from(never: Infallible) -> Self { match never {} }
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
    use hex_lit::hex;
    use internals::ToU64 as _;

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::pow::test_utils::{u128_to_work, u64_to_work};
    use crate::script::ScriptBuf;
    use crate::transaction::{OutPoint, Transaction, TxIn, TxOut, Txid};
    use crate::{block, Amount, CompactTarget, Network, Sequence, TestnetVersion, Witness};

    #[test]
    fn static_vector() {
        // testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw");
        let block: Block = deserialize(&segwit_block[..]).expect("failed to deserialize block");
        let (header, transactions) = block.into_parts();

        assert!(block::check_merkle_root(&header, &transactions));
        let block = Block::new_unchecked(header, transactions).assume_checked(None);

        // Same as `block.check_merkle_root` but do it explicitly.
        let hashes_iter = block.transactions().iter().map(|obj| obj.compute_txid());
        let from_iter = TxMerkleNode::calculate_root(hashes_iter.clone());
        assert_eq!(from_iter, Some(block.header().merkle_root));
    }

    #[test]
    fn coinbase_and_bip34() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();
        let block = block.assume_checked(None);

        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(block.coinbase().compute_txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // block with 3-byte bip34 push for height 0x03010000 (non-minimal 1)
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703010000000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();
        let bad = bad.assume_checked(None);

        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::NonMinimalPush));

        // Block 15 on Testnet4 has height of 0x5f (15 PUSHNUM)
        const BLOCK_HEX_SMALL_HEIGHT_15: &str = "000000200fd8c4c1e88f313b561b2724542ff9be1bc54a7dab8db8ef6359d48a00000000705bf9145e6d3c413702cc61f32e4e7bfe3117b1eb928071a59adcf75694a3fb07d83866ffff001dcf4c5e8401010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff095f00062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX_SMALL_HEIGHT_15)).unwrap();
        let block = block.assume_checked(None);

        assert_eq!(block.bip34_block_height(), Ok(15));

        // Block 42 on Testnet4 has height of 0x012a (42)
        const BLOCK_HEX_SMALL_HEIGHT_42: &str = "000000202803addb5a3f42f3e8d6c8536598b2d872b04f3b4f0698c26afdb17300000000463dd9a37a5d3d5c05f9c80a1485b41f1f513dee00338bbc33f5a6e836fce0345dda3866ffff001d872b9def01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff09012a062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX_SMALL_HEIGHT_42)).unwrap();
        let block = block.assume_checked(None);

        assert_eq!(block.bip34_block_height(), Ok(42));

        // Block 42 on Testnet4 using OP_PUSHDATA1 0x4c012a (42) instead of 0x012a (42)
        const BLOCK_HEX_SMALL_HEIGHT_42_WRONG: &str = "000000202803addb5a3f42f3e8d6c8536598b2d872b04f3b4f0698c26afdb17300000000463dd9a37a5d3d5c05f9c80a1485b41f1f513dee00338bbc33f5a6e836fce0345dda3866ffff001d872b9def01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0a4c012a062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX_SMALL_HEIGHT_42_WRONG)).unwrap();
        let block = block.assume_checked(None);

        assert_eq!(block.bip34_block_height(), Err(super::Bip34Error::NonMinimalPush));

        // Block with a 5 byte height properly minimally encoded
        // this is an overflow for ScriptNum (i32) parsing
        const BLOCK_HEX_5_BYTE_HEIGHT: &str = "000000202803addb5a3f42f3e8d6c8536598b2d872b04f3b4f0698c26afdb17300000000463dd9a37a5d3d5c05f9c80a1485b41f1f513dee00338bbc33f5a6e836fce0345dda3866ffff001d872b9def01010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0d052a2a2a2a2a062f4077697a2fffffffff0200f2052a010000001976a9140a59837ccd4df25adc31cdad39be6a8d97557ed688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX_5_BYTE_HEIGHT)).unwrap();
        let block = block.assume_checked(None);

        assert_eq!(block.bip34_block_height(), Err(super::Bip34Error::NotPresent));
    }

    #[test]
    fn block() {
        let params = Params::new(Network::Bitcoin);
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        let some_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000");
        let merkle = hex!("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c");
        let work = u128_to_work(0x100010001_u128);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());

        let (header, transactions) = decode.unwrap().into_parts();
        // should be also ok for a non-witness block as commitment is optional in that case
        let (witness_commitment_matches, witness_root) =
            block::check_witness_commitment(&transactions);
        assert!(witness_commitment_matches);

        let real_decode =
            Block::new_unchecked(header, transactions.clone()).assume_checked(witness_root);

        assert_eq!(real_decode.header().version, Version::from_consensus(1));
        assert_eq!(serialize(&real_decode.header().prev_blockhash), prevhash);
        assert_eq!(
            real_decode.header().merkle_root,
            block::compute_merkle_root(&transactions).unwrap()
        );
        assert_eq!(serialize(&real_decode.header().merkle_root), merkle);
        assert_eq!(real_decode.header().time, BlockTime::from_u32(1231965655));
        assert_eq!(real_decode.header().bits, CompactTarget::from_consensus(486604799));
        assert_eq!(real_decode.header().nonce, 2067413810);
        assert_eq!(real_decode.header().work(), work);

        assert_eq!(real_decode.header().difficulty(&params), 1);
        assert_eq!(real_decode.header().difficulty_float(&params), 1.0);

        assert_eq!(
            real_decode.header().validate_pow(real_decode.header().target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.total_size(), some_block.len());
        assert_eq!(block_base_size(real_decode.transactions()), some_block.len());
        assert_eq!(
            real_decode.weight(),
            Weight::from_non_witness_data_size(some_block.len().to_u64())
        );

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[test]
    fn segwit_block() {
        let params = Params::new(Network::Testnet(TestnetVersion::V3));
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000");
        let merkle = hex!("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e");
        let work = u64_to_work(0x257c3becdacc64_u64);

        assert!(decode.is_ok());

        let (header, transactions) = decode.unwrap().into_parts();
        let (witness_commitment_matches, witness_root) =
            block::check_witness_commitment(&transactions);
        assert!(witness_commitment_matches);

        let real_decode =
            Block::new_unchecked(header, transactions.clone()).assume_checked(witness_root);

        assert_eq!(real_decode.header().version, Version::from_consensus(0x2000_0000)); // VERSIONBITS but no bits set
        assert_eq!(serialize(&real_decode.header().prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header().merkle_root), merkle);
        assert_eq!(
            real_decode.header().merkle_root,
            block::compute_merkle_root(&transactions).unwrap()
        );
        assert_eq!(real_decode.header().time, BlockTime::from_u32(1472004949));
        assert_eq!(real_decode.header().bits, CompactTarget::from_consensus(0x1a06d450));
        assert_eq!(real_decode.header().nonce, 1879759182);
        assert_eq!(real_decode.header().work(), work);
        assert_eq!(real_decode.header().difficulty(&params), 2456598);
        assert_eq!(real_decode.header().difficulty_float(&params), 2456598.4399242126);

        assert_eq!(
            real_decode.header().validate_pow(real_decode.header().target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.total_size(), segwit_block.len());
        assert_eq!(block_base_size(real_decode.transactions()), 4283);
        assert_eq!(real_decode.weight(), Weight::from_wu(17168));

        assert_eq!(serialize(&real_decode), segwit_block);
    }

    #[test]
    fn block_version() {
        let block = hex!("ffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());

        let real_decode = decode.unwrap().assume_checked(None);
        assert_eq!(real_decode.header().version, Version::from_consensus(2147483647));

        let block2 = hex!("000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap().assume_checked(None);
        assert_eq!(real_decode2.header().version, Version::from_consensus(-2147483648));
    }

    #[test]
    fn validate_pow() {
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
    fn compact_roundtrip() {
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
            let version_int = (0x20000000u32 ^ (1 << i)) as i32;
            let version = Version::from_consensus(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version::from_consensus(0x20000000 ^ (1 << 1));
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }

    #[test]
    fn block_validation_no_transactions() {
        let header = header();
        let transactions = Vec::new(); // Empty transactions

        let block = Block::new_unchecked(header, transactions);
        match block.validate() {
            Err(InvalidBlockError::NoTransactions) => (),
            other => panic!("Expected NoTransactions error, got: {:?}", other),
        }
    }

    #[test]
    fn block_validation_invalid_coinbase() {
        let header = header();

        // Create a non-coinbase transaction (has a real previous output, not all zeros)
        let non_coinbase_tx = Transaction {
            version: primitives::transaction::Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1; 32]), // Not all zeros
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_AND_RBF,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { value: Amount::ONE_BTC, script_pubkey: ScriptBuf::new() }],
        };

        let transactions = vec![non_coinbase_tx];
        let block = Block::new_unchecked(header, transactions);

        match block.validate() {
            Err(InvalidBlockError::InvalidCoinbase) => (),
            other => panic!("Expected InvalidCoinbase error, got: {:?}", other),
        }
    }

    #[test]
    fn block_validation_success_with_coinbase() {
        use crate::constants;

        // Use the genesis block which has a valid coinbase
        let genesis = constants::genesis_block(Network::Bitcoin);

        let header = *genesis.header();
        let transactions = genesis.transactions().to_vec();

        let unchecked_block = Block::new_unchecked(header, transactions);
        let validated_block = unchecked_block.validate();

        assert!(validated_block.is_ok(), "Genesis block should validate successfully");
    }

    #[test]
    fn checked_block_coinbase_method() {
        use crate::constants;

        let genesis = constants::genesis_block(Network::Bitcoin);
        let coinbase = genesis.coinbase();

        // Test that coinbase method returns the expected transaction
        let expected_txid = genesis.transactions()[0].compute_txid();
        assert_eq!(coinbase.compute_txid(), expected_txid);
        assert_eq!(coinbase.wtxid(), Wtxid::COINBASE);

        // Test that as_inner() returns the correct transaction
        assert_eq!(coinbase.as_transaction(), &genesis.transactions()[0]);
    }

    #[test]
    fn block_new_checked_validation() {
        use crate::constants;

        // Test successful validation with genesis block
        let genesis = constants::genesis_block(Network::Bitcoin);
        let header = *genesis.header();
        let transactions = genesis.transactions().to_vec();

        let checked_block = Block::new_checked(header, transactions.clone());
        assert!(checked_block.is_ok(), "Genesis block should validate via new_checked");

        // Test validation failure with empty transactions
        let empty_result = Block::new_checked(header, Vec::new());
        match empty_result {
            Err(InvalidBlockError::NoTransactions) => (),
            other => panic!("Expected NoTransactions error, got: {:?}", other),
        }

        // Test validation failure with invalid coinbase
        let non_coinbase_tx = Transaction {
            version: primitives::transaction::Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1; 32]), // Not all zeros
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_AND_RBF,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { value: Amount::ONE_BTC, script_pubkey: ScriptBuf::new() }],
        };

        let invalid_coinbase_result = Block::new_checked(header, vec![non_coinbase_tx]);
        match invalid_coinbase_result {
            Err(InvalidBlockError::InvalidCoinbase) => (),
            other => panic!("Expected InvalidCoinbase error, got: {:?}", other),
        }
    }

    #[test]
    fn coinbase_bip34_height_with_coinbase_type() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();
        let block = block.assume_checked(None);

        // Test that BIP34 height extraction works with the Coinbase type
        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // Test that coinbase method returns a Coinbase type
        let coinbase = block.coinbase();
        assert!(coinbase.as_transaction().is_coinbase());

        // Test that the coinbase transaction ID matches expected
        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(coinbase.compute_txid().to_string(), cb_txid);
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
