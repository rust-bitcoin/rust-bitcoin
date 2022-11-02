// Written by John L. Jegutanis
// SPDX-License-Identifier: CC0-1.0
//
// This code was translated from merkleblock.h, merkleblock.cpp and pmt_tests.cpp
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// SPDX-License-Identifier: MIT

//! Merkle Block and Partial Merkle Tree.
//!
//! Support proofs that transaction(s) belong to a block.
//!
//! # Examples
//!
//! ```rust
//! use bitcoin::hash_types::Txid;
//! use bitcoin::hashes::hex::FromHex;
//! use bitcoin::{Block, MerkleBlock};
//!
//! // Get the proof from a bitcoind by running in the terminal:
//! // $ TXID="5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2"
//! // $ bitcoin-cli gettxoutproof [\"$TXID\"]
//! let mb_bytes = Vec::from_hex("01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b913719\
//!     0000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b\
//!     1b01e32f570200000002252bf9d75c4f481ebb6278d708257d1f12beb6dd30301d26c623f789b2ba6fc0e2d3\
//!     2adb5f8ca820731dff234a84e78ec30bce4ec69dbd562d0b2b8266bf4e5a0105").unwrap();
//! let mb: MerkleBlock = bitcoin::consensus::deserialize(&mb_bytes).unwrap();
//!
//! // Authenticate and extract matched transaction ids
//! let mut matches: Vec<Txid> = vec![];
//! let mut index: Vec<u32> = vec![];
//! assert!(mb.extract_matches(&mut matches, &mut index).is_ok());
//! assert_eq!(1, matches.len());
//! assert_eq!(
//!     "5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2".parse::<Txid>().unwrap(),
//!     matches[0]
//! );
//! assert_eq!(1, index.len());
//! assert_eq!(1, index[0]);
//! ```

use core::fmt;

use self::MerkleBlockError::*;
use crate::blockdata::block::{self, Block};
use crate::blockdata::constants::{MAX_BLOCK_WEIGHT, MIN_TRANSACTION_WEIGHT};
use crate::blockdata::transaction::Transaction;
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::hash_types::{TxMerkleNode, Txid};
use crate::hashes::Hash;
use crate::io;
use crate::prelude::*;

/// Data structure that represents a block header paired to a partial merkle tree.
///
/// NOTE: This assumes that the given Block has *at least* 1 transaction. If the Block has 0 txs,
/// it will hit an assertion.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct MerkleBlock {
    /// The block header
    pub header: block::Header,
    /// Transactions making up a partial merkle tree
    pub txn: PartialMerkleTree,
}

impl MerkleBlock {
    /// Create a MerkleBlock from a block, that contains proofs for specific txids.
    ///
    /// The `block` is a full block containing the header and transactions and `match_txids` is a
    /// function that returns true for the ids that should be included in the partial merkle tree.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::hash_types::Txid;
    /// use bitcoin::hashes::hex::FromHex;
    /// use bitcoin::{Block, MerkleBlock};
    ///
    /// // Block 80000
    /// let block_bytes = Vec::from_hex("01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad2\
    ///     7b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33\
    ///     a5914ce6ed5b1b01e32f5702010000000100000000000000000000000000000000000000000000000000\
    ///     00000000000000ffffffff0704e6ed5b1b014effffffff0100f2052a01000000434104b68a50eaa0287e\
    ///     ff855189f949c1c6e5f58b37c88231373d8a59809cbae83059cc6469d65c665ccfd1cfeb75c6e8e19413\
    ///     bba7fbff9bc762419a76d87b16086eac000000000100000001a6b97044d03da79c005b20ea9c0e1a6d9d\
    ///     c12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aee\
    ///     d3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d\
    ///     5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b6\
    ///     5d35549d88ac00000000").unwrap();
    /// let block: Block = bitcoin::consensus::deserialize(&block_bytes).unwrap();
    ///
    /// // Create a merkle block containing a single transaction
    /// let txid = "5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2".parse::<Txid>().unwrap();
    /// let match_txids: Vec<Txid> = vec![txid].into_iter().collect();
    /// let mb = MerkleBlock::from_block_with_predicate(&block, |t| match_txids.contains(t));
    ///
    /// // Authenticate and extract matched transaction ids
    /// let mut matches: Vec<Txid> = vec![];
    /// let mut index: Vec<u32> = vec![];
    /// assert!(mb.extract_matches(&mut matches, &mut index).is_ok());
    /// assert_eq!(txid, matches[0]);
    /// ```
    pub fn from_block_with_predicate<F>(block: &Block, match_txids: F) -> Self
    where
        F: Fn(&Txid) -> bool,
    {
        let block_txids: Vec<_> = block.txdata.iter().map(Transaction::txid).collect();
        Self::from_header_txids_with_predicate(&block.header, &block_txids, match_txids)
    }

    /// Create a MerkleBlock from the block's header and txids, that contain proofs for specific txids.
    ///
    /// The `header` is the block header, `block_txids` is the full list of txids included in the block and
    /// `match_txids` is a function that returns true for the ids that should be included in the partial merkle tree.
    pub fn from_header_txids_with_predicate<F>(
        header: &block::Header,
        block_txids: &[Txid],
        match_txids: F,
    ) -> Self
    where
        F: Fn(&Txid) -> bool,
    {
        let matches: Vec<bool> = block_txids.iter().map(match_txids).collect();

        let pmt = PartialMerkleTree::from_txids(block_txids, &matches);
        MerkleBlock { header: *header, txn: pmt }
    }

    /// Extract the matching txid's represented by this partial merkle tree
    /// and their respective indices within the partial tree.
    /// returns Ok(()) on success, or error in case of failure
    pub fn extract_matches(
        &self,
        matches: &mut Vec<Txid>,
        indexes: &mut Vec<u32>,
    ) -> Result<(), MerkleBlockError> {
        let merkle_root = self.txn.extract_matches(matches, indexes)?;

        if merkle_root.eq(&self.header.merkle_root) {
            Ok(())
        } else {
            Err(MerkleRootMismatch)
        }
    }
}

impl Encodable for MerkleBlock {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let len = self.header.consensus_encode(w)? + self.txn.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for MerkleBlock {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(MerkleBlock {
            header: Decodable::consensus_decode(r)?,
            txn: Decodable::consensus_decode(r)?,
        })
    }
}

/// Data structure that represents a partial merkle tree.
///
/// It represents a subset of the txid's of a known block, in a way that
/// allows recovery of the list of txid's and the merkle root, in an
/// authenticated way.
///
/// The encoding works as follows: we traverse the tree in depth-first order,
/// storing a bit for each traversed node, signifying whether the node is the
/// parent of at least one matched leaf txid (or a matched txid itself). In
/// case we are at the leaf level, or this bit is 0, its merkle node hash is
/// stored, and its children are not explored further. Otherwise, no hash is
/// stored, but we recurse into both (or the only) child branch. During
/// decoding, the same depth-first traversal is performed, consuming bits and
/// hashes as they written during encoding.
///
/// The serialization is fixed and provides a hard guarantee about the
/// encoded size:
///
///   SIZE <= 10 + ceil(32.25*N)
///
/// Where N represents the number of leaf nodes of the partial tree. N itself
/// is bounded by:
///
///   N <= total_transactions
///   N <= 1 + matched_transactions*tree_height
///
/// The serialization format:
///  - uint32     total_transactions (4 bytes)
///  - varint     number of hashes   (1-3 bytes)
///  - uint256[]  hashes in depth-first order (<= 32*N bytes)
///  - varint     number of bytes of flag bits (1-3 bytes)
///  - byte[]     flag bits, packed per 8 in a byte, least significant bit first (<= 2*N-1 bits)
/// The size constraints follow from this.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PartialMerkleTree {
    /// The total number of transactions in the block
    num_transactions: u32,
    /// node-is-parent-of-matched-txid bits
    bits: Vec<bool>,
    /// Transaction ids and internal hashes
    hashes: Vec<TxMerkleNode>,
}

impl PartialMerkleTree {
    /// Returns the total number of transactions in the block.
    pub fn num_transactions(&self) -> u32 { self.num_transactions }

    /// Returns the node-is-parent-of-matched-txid bits of the partial merkle tree.
    pub fn bits(&self) -> &Vec<bool> { &self.bits }

    /// Returns the transaction ids and internal hashes of the partial merkle tree.
    pub fn hashes(&self) -> &Vec<TxMerkleNode> { &self.hashes }

    /// Construct a partial merkle tree
    /// The `txids` are the transaction hashes of the block and the `matches` is the contains flags
    /// wherever a tx hash should be included in the proof.
    ///
    /// Panics when `txids` is empty or when `matches` has a different length
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::hash_types::Txid;
    /// use bitcoin::hashes::hex::FromHex;
    /// use bitcoin::merkle_tree::{MerkleBlock, PartialMerkleTree};
    ///
    /// // Block 80000
    /// let txids: Vec<Txid> = [
    ///     "c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25",
    ///     "5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2",
    /// ]
    /// .iter()
    /// .map(|hex| hex.parse::<Txid>().unwrap())
    /// .collect();
    ///
    /// // Select the second transaction
    /// let matches = vec![false, true];
    /// let tree = PartialMerkleTree::from_txids(&txids, &matches);
    /// assert!(tree.extract_matches(&mut vec![], &mut vec![]).is_ok());
    /// ```
    pub fn from_txids(txids: &[Txid], matches: &[bool]) -> Self {
        // We can never have zero txs in a merkle block, we always need the coinbase tx
        assert_ne!(txids.len(), 0);
        assert_eq!(txids.len(), matches.len());

        let mut pmt = PartialMerkleTree {
            num_transactions: txids.len() as u32,
            bits: Vec::with_capacity(txids.len()),
            hashes: vec![],
        };
        // calculate height of tree
        let mut height = 0;
        while pmt.calc_tree_width(height) > 1 {
            height += 1;
        }
        // traverse the partial tree
        pmt.traverse_and_build(height, 0, txids, matches);
        pmt
    }

    /// Extract the matching txid's represented by this partial merkle tree
    /// and their respective indices within the partial tree.
    /// returns the merkle root, or error in case of failure
    pub fn extract_matches(
        &self,
        matches: &mut Vec<Txid>,
        indexes: &mut Vec<u32>,
    ) -> Result<TxMerkleNode, MerkleBlockError> {
        matches.clear();
        indexes.clear();
        // An empty set will not work
        if self.num_transactions == 0 {
            return Err(NoTransactions);
        };
        // check for excessively high numbers of transactions
        if self.num_transactions > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT {
            return Err(TooManyTransactions);
        }
        // there can never be more hashes provided than one for every txid
        if self.hashes.len() as u32 > self.num_transactions {
            return Err(TooManyHashes);
        };
        // there must be at least one bit per node in the partial tree, and at least one node per hash
        if self.bits.len() < self.hashes.len() {
            return Err(NotEnoughBits);
        };
        // calculate height of tree
        let mut height = 0;
        while self.calc_tree_width(height) > 1 {
            height += 1;
        }
        // traverse the partial tree
        let mut bits_used = 0u32;
        let mut hash_used = 0u32;
        let hash_merkle_root =
            self.traverse_and_extract(height, 0, &mut bits_used, &mut hash_used, matches, indexes)?;
        // Verify that all bits were consumed (except for the padding caused by
        // serializing it as a byte sequence)
        if (bits_used + 7) / 8 != (self.bits.len() as u32 + 7) / 8 {
            return Err(NotAllBitsConsumed);
        }
        // Verify that all hashes were consumed
        if hash_used != self.hashes.len() as u32 {
            return Err(NotAllHashesConsumed);
        }
        Ok(TxMerkleNode::from_byte_array(hash_merkle_root.to_byte_array()))
    }

    /// Helper function to efficiently calculate the number of nodes at given height
    /// in the merkle tree
    #[inline]
    fn calc_tree_width(&self, height: u32) -> u32 {
        (self.num_transactions + (1 << height) - 1) >> height
    }

    /// Calculate the hash of a node in the merkle tree (at leaf level: the txid's themselves)
    fn calc_hash(&self, height: u32, pos: u32, txids: &[Txid]) -> TxMerkleNode {
        if height == 0 {
            // Hash at height 0 is the txid itself
            TxMerkleNode::from_byte_array(txids[pos as usize].to_byte_array())
        } else {
            // Calculate left hash
            let left = self.calc_hash(height - 1, pos * 2, txids);
            // Calculate right hash if not beyond the end of the array - copy left hash otherwise
            let right = if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                self.calc_hash(height - 1, pos * 2 + 1, txids)
            } else {
                left
            };
            // Combine subhashes
            PartialMerkleTree::parent_hash(left, right)
        }
    }

    /// Recursive function that traverses tree nodes, storing the data as bits and hashes
    fn traverse_and_build(&mut self, height: u32, pos: u32, txids: &[Txid], matches: &[bool]) {
        // Determine whether this node is the parent of at least one matched txid
        let mut parent_of_match = false;
        let mut p = pos << height;
        while p < (pos + 1) << height && p < self.num_transactions {
            parent_of_match |= matches[p as usize];
            p += 1;
        }
        // Store as flag bit
        self.bits.push(parent_of_match);

        if height == 0 || !parent_of_match {
            // If at height 0, or nothing interesting below, store hash and stop
            let hash = self.calc_hash(height, pos, txids);
            self.hashes.push(hash);
        } else {
            // Otherwise, don't store any hash, but descend into the subtrees
            self.traverse_and_build(height - 1, pos * 2, txids, matches);
            if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                self.traverse_and_build(height - 1, pos * 2 + 1, txids, matches);
            }
        }
    }

    /// Recursive function that traverses tree nodes, consuming the bits and hashes produced by
    /// TraverseAndBuild. It returns the hash of the respective node and its respective index.
    fn traverse_and_extract(
        &self,
        height: u32,
        pos: u32,
        bits_used: &mut u32,
        hash_used: &mut u32,
        matches: &mut Vec<Txid>,
        indexes: &mut Vec<u32>,
    ) -> Result<TxMerkleNode, MerkleBlockError> {
        if *bits_used as usize >= self.bits.len() {
            return Err(BitsArrayOverflow);
        }
        let parent_of_match = self.bits[*bits_used as usize];
        *bits_used += 1;
        if height == 0 || !parent_of_match {
            // If at height 0, or nothing interesting below, use stored hash and do not descend
            if *hash_used as usize >= self.hashes.len() {
                return Err(HashesArrayOverflow);
            }
            let hash = self.hashes[*hash_used as usize];
            *hash_used += 1;
            if height == 0 && parent_of_match {
                // in case of height 0, we have a matched txid
                matches.push(Txid::from_byte_array(hash.to_byte_array()));
                indexes.push(pos);
            }
            Ok(hash)
        } else {
            // otherwise, descend into the subtrees to extract matched txids and hashes
            let left = self.traverse_and_extract(
                height - 1,
                pos * 2,
                bits_used,
                hash_used,
                matches,
                indexes,
            )?;
            let right;
            if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                right = self.traverse_and_extract(
                    height - 1,
                    pos * 2 + 1,
                    bits_used,
                    hash_used,
                    matches,
                    indexes,
                )?;
                if right == left {
                    // The left and right branches should never be identical, as the transaction
                    // hashes covered by them must each be unique.
                    return Err(IdenticalHashesFound);
                }
            } else {
                right = left;
            }
            // and combine them before returning
            Ok(PartialMerkleTree::parent_hash(left, right))
        }
    }

    /// Helper method to produce SHA256D(left + right)
    fn parent_hash(left: TxMerkleNode, right: TxMerkleNode) -> TxMerkleNode {
        let mut encoder = TxMerkleNode::engine();
        left.consensus_encode(&mut encoder).expect("engines don't error");
        right.consensus_encode(&mut encoder).expect("engines don't error");
        TxMerkleNode::from_engine(encoder)
    }
}

impl Encodable for PartialMerkleTree {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let ret = self.num_transactions.consensus_encode(w)? + self.hashes.consensus_encode(w)?;
        let mut bytes: Vec<u8> = vec![0; (self.bits.len() + 7) / 8];
        for p in 0..self.bits.len() {
            bytes[p / 8] |= (self.bits[p] as u8) << (p % 8) as u8;
        }
        Ok(ret + bytes.consensus_encode(w)?)
    }
}

impl Decodable for PartialMerkleTree {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let num_transactions: u32 = Decodable::consensus_decode(r)?;
        let hashes: Vec<TxMerkleNode> = Decodable::consensus_decode(r)?;

        let bytes: Vec<u8> = Decodable::consensus_decode(r)?;
        let mut bits: Vec<bool> = vec![false; bytes.len() * 8];

        for (p, bit) in bits.iter_mut().enumerate() {
            *bit = (bytes[p / 8] & (1 << (p % 8) as u8)) != 0;
        }
        Ok(PartialMerkleTree { num_transactions, hashes, bits })
    }
}

/// An error when verifying the merkle block.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum MerkleBlockError {
    /// Merkle root in the header doesn't match to the root calculated from partial merkle tree.
    MerkleRootMismatch,
    /// Partial merkle tree contains no transactions.
    NoTransactions,
    /// There are too many transactions.
    TooManyTransactions,
    /// There are too many hashes
    TooManyHashes,
    /// There must be at least one bit per node in the partial tree,
    /// and at least one node per hash
    NotEnoughBits,
    /// Not all bits were consumed
    NotAllBitsConsumed,
    /// Not all hashes were consumed
    NotAllHashesConsumed,
    /// Overflowed the bits array
    BitsArrayOverflow,
    /// Overflowed the hashes array
    HashesArrayOverflow,
    /// The left and right branches should never be identical
    IdenticalHashesFound,
}

impl fmt::Display for MerkleBlockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::MerkleBlockError::*;

        match *self {
            MerkleRootMismatch => write!(f, "merkle header root doesn't match to the root calculated from the partial merkle tree"),
            NoTransactions => write!(f, "partial merkle tree contains no transactions"),
            TooManyTransactions => write!(f, "too many transactions"),
            TooManyHashes => write!(f, "proof contains more hashes than transactions"),
            NotEnoughBits => write!(f, "proof contains less bits than hashes"),
            NotAllBitsConsumed => write!(f, "not all bit were consumed"),
            NotAllHashesConsumed => write!(f, "not all hashes were consumed"),
            BitsArrayOverflow => write!(f, "overflowed the bits array"),
            HashesArrayOverflow => write!(f, "overflowed the hashes array"),
            IdenticalHashesFound => write!(f, "found identical transaction hashes"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for MerkleBlockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::MerkleBlockError::*;

        match *self {
            MerkleRootMismatch | NoTransactions | TooManyTransactions | TooManyHashes
            | NotEnoughBits | NotAllBitsConsumed | NotAllHashesConsumed | BitsArrayOverflow
            | HashesArrayOverflow | IdenticalHashesFound => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "rand-std")]
    use secp256k1::rand::prelude::*;

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};
    #[cfg(feature = "rand-std")]
    use crate::hash_types::TxMerkleNode;
    #[cfg(feature = "rand-std")]
    use crate::hashes::Hash;
    use crate::internal_macros::hex;
    use crate::{Block, Txid};

    #[cfg(feature = "rand-std")]
    macro_rules! pmt_tests {
        ($($name:ident),* $(,)?) => {
            $(
                #[test]
                fn $name() {
                    pmt_test_from_name(stringify!($name));
                }
            )*
        }
    }

    #[cfg(feature = "rand-std")]
    pmt_tests!(
        pmt_test_1,
        pmt_test_4,
        pmt_test_7,
        pmt_test_17,
        pmt_test_56,
        pmt_test_100,
        pmt_test_127,
        pmt_test_256,
        pmt_test_312,
        pmt_test_513,
        pmt_test_1000,
        pmt_test_4095
    );

    /// Parses the transaction count out of `name` with form: `pmt_test_$num`.
    #[cfg(feature = "rand-std")]
    fn pmt_test_from_name(name: &str) { pmt_test(name[9..].parse().unwrap()) }

    #[cfg(feature = "rand-std")]
    fn pmt_test(tx_count: usize) {
        use core::cmp::min;

        use crate::merkle_tree;

        let mut rng = thread_rng();
        // Create some fake tx ids
        let tx_ids = (1..=tx_count)
            .map(|i| format!("{:064x}", i).parse::<Txid>().unwrap())
            .collect::<Vec<_>>();

        // Calculate the merkle root and height
        let hashes = tx_ids.iter().map(|t| t.to_raw_hash());
        let merkle_root_1: TxMerkleNode =
            merkle_tree::calculate_root(hashes).expect("hashes is not empty").into();
        let mut height = 1;
        let mut ntx = tx_count;
        while ntx > 1 {
            ntx = (ntx + 1) / 2;
            height += 1;
        }

        // Check with random subsets with inclusion chances 1, 1/2, 1/4, ..., 1/128
        for att in 1..15 {
            let mut matches = vec![false; tx_count];
            let mut match_txid1 = vec![];
            for j in 0..tx_count {
                // Generate `att / 2` random bits
                let rand_bits = match att / 2 {
                    0 => 0,
                    bits => rng.gen::<u64>() >> (64 - bits),
                };
                let include = rand_bits == 0;
                matches[j] = include;

                if include {
                    match_txid1.push(tx_ids[j]);
                };
            }

            // Build the partial merkle tree
            let pmt1 = PartialMerkleTree::from_txids(&tx_ids, &matches);
            let serialized = serialize(&pmt1);

            // Verify PartialMerkleTree's size guarantees
            let n = min(tx_count, 1 + match_txid1.len() * height);
            assert!(serialized.len() <= 10 + (258 * n + 7) / 8);

            // Deserialize into a tester copy
            let pmt2: PartialMerkleTree =
                deserialize(&serialized).expect("Could not deserialize own data");

            // Extract merkle root and matched txids from copy
            let mut match_txid2: Vec<Txid> = vec![];
            let mut indexes = vec![];
            let merkle_root_2 = pmt2
                .extract_matches(&mut match_txid2, &mut indexes)
                .expect("Could not extract matches");

            // Check that it has the same merkle root as the original, and a valid one
            assert_eq!(merkle_root_1, merkle_root_2);
            assert_ne!(merkle_root_2, TxMerkleNode::all_zeros());

            // check that it contains the matched transactions (in the same order!)
            assert_eq!(match_txid1, match_txid2);

            // check that random bit flips break the authentication
            for _ in 0..4 {
                let mut pmt3: PartialMerkleTree = deserialize(&serialized).unwrap();
                pmt3.damage(&mut rng);
                let mut match_txid3 = vec![];
                let merkle_root_3 = pmt3.extract_matches(&mut match_txid3, &mut indexes).unwrap();
                assert_ne!(merkle_root_3, merkle_root_1);
            }
        }
    }

    #[test]
    fn pmt_malleability() {
        // Create some fake tx ids with the last 2 hashes repeating
        let txids: Vec<Txid> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 9, 10]
            .iter()
            .map(|i| format!("{:064x}", i).parse::<Txid>().unwrap())
            .collect();

        let matches =
            vec![false, false, false, false, false, false, false, false, false, true, true, false];

        let tree = PartialMerkleTree::from_txids(&txids, &matches);
        // Should fail due to duplicate txs found
        let result = tree.extract_matches(&mut vec![], &mut vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn merkleblock_serialization() {
        // Got it by running the rpc call
        // `gettxoutproof '["220ebc64e21abece964927322cba69180ed853bb187fbc6923bac7d010b9d87a"]'`
        let mb_hex = include_str!("../../tests/data/merkle_block.hex");

        let mb: MerkleBlock = deserialize(&hex!(mb_hex)).unwrap();
        assert_eq!(get_block_13b8a().block_hash(), mb.header.block_hash());
        assert_eq!(
            mb.header.merkle_root,
            mb.txn.extract_matches(&mut vec![], &mut vec![]).unwrap()
        );
        // Serialize again and check that it matches the original bytes
        assert_eq!(mb_hex, serialize(&mb).to_lower_hex_string().as_str());
    }

    /// Create a CMerkleBlock using a list of txids which will be found in the
    /// given block.
    #[test]
    fn merkleblock_construct_from_txids_found() {
        let block = get_block_13b8a();

        let txids: Vec<Txid> = [
            "74d681e0e03bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20",
            "f9fc751cb7dc372406a9f8d738d5e6f8f63bab71986a39cf36ee70ee17036d07",
        ]
        .iter()
        .map(|hex| hex.parse::<Txid>().unwrap())
        .collect();

        let txid1 = txids[0];
        let txid2 = txids[1];
        let txids = vec![txid1, txid2];

        let merkle_block = MerkleBlock::from_block_with_predicate(&block, |t| txids.contains(t));

        assert_eq!(merkle_block.header.block_hash(), block.block_hash());

        let mut matches: Vec<Txid> = vec![];
        let mut index: Vec<u32> = vec![];

        assert_eq!(
            merkle_block.txn.extract_matches(&mut matches, &mut index).unwrap(),
            block.header.merkle_root
        );
        assert_eq!(matches.len(), 2);

        // Ordered by occurrence in depth-first tree traversal.
        assert_eq!(matches[0], txid2);
        assert_eq!(index[0], 1);

        assert_eq!(matches[1], txid1);
        assert_eq!(index[1], 8);
    }

    /// Create a CMerkleBlock using a list of txids which will not be found in the given block
    #[test]
    fn merkleblock_construct_from_txids_not_found() {
        let block = get_block_13b8a();
        let txids: Vec<Txid> = ["c0ffee00003bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20"]
            .iter()
            .map(|hex| hex.parse::<Txid>().unwrap())
            .collect();

        let merkle_block = MerkleBlock::from_block_with_predicate(&block, |t| txids.contains(t));

        assert_eq!(merkle_block.header.block_hash(), block.block_hash());

        let mut matches: Vec<Txid> = vec![];
        let mut index: Vec<u32> = vec![];

        assert_eq!(
            merkle_block.txn.extract_matches(&mut matches, &mut index).unwrap(),
            block.header.merkle_root
        );
        assert_eq!(matches.len(), 0);
        assert_eq!(index.len(), 0);
    }

    #[cfg(feature = "rand-std")]
    impl PartialMerkleTree {
        /// Flip one bit in one of the hashes - this should break the authentication
        fn damage(&mut self, rng: &mut ThreadRng) {
            let n = rng.gen_range(0..self.hashes.len());
            let bit = rng.gen::<u8>();
            let hashes = &mut self.hashes;
            let mut hash = hashes[n].to_byte_array();
            hash[(bit >> 3) as usize] ^= 1 << (bit & 7);
            hashes[n] = TxMerkleNode::from_slice(&hash).unwrap();
        }
    }

    /// Returns a real block (0000000000013b8ab2cd513b0261a14096412195a72a0c4827d229dcc7e0f7af)
    /// with 9 txs.
    fn get_block_13b8a() -> Block {
        use crate::hashes::hex::FromHex;
        let block_hex = include_str!("../../tests/data/block_13b8a.hex");
        deserialize(&Vec::from_hex(block_hex).unwrap()).unwrap()
    }
}
