// Rust Bitcoin Library
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! BIP152 Compact Blocks
//!
//! Implementation of compact blocks data structure and algorithms.
//!

use std::{convert, error, fmt, io, mem};

use hashes::{hex, sha256, siphash24, Hash};

use hash_types::BlockHash;
use blockdata::block::{Block, BlockHeader};
use blockdata::transaction::Transaction;
use consensus::encode::{self, Decodable, Encodable, VarInt};
use util::endian;

/// A BIP-152 error
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// An unknown version number was used.
    UnknownVersion,
    /// A transaction index is requested that is out
    /// of range from the corresponding block.
    TxIndexOutOfRange(u64),
    /// The prefill slice provided was invalid.
    InvalidPrefill,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownVersion => write!(f, "an unknown version number was used"),
            Error::TxIndexOutOfRange(i) => write!(f, "a transaction index is requested that is \
                out of range from the corresponding block: {}", i,
            ),
            Error::InvalidPrefill => write!(f, "the prefill slice provided was invalid"),
        }
    }
}

impl error::Error for Error {}

/// A [PrefilledTransaction] structure is used in [HeaderAndShortIDs] to
/// provide a list of a few transactions explicitly.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PrefilledTransaction {
    /// The index of the transaction in the block.
    ///
    /// This field is differentially encoded relative to the previous
    /// prefilled transaction as described as follows:
    ///
    /// > Several uses of CompactSize below are "differentially encoded". For
    /// > these, instead of using raw indexes, the number encoded is the
    /// > difference between the current index and the previous index, minus one.
    /// > For example, a first index of 0 implies a real index of 0, a second
    /// > index of 0 thereafter refers to a real index of 1, etc.
    pub idx: u16,
    /// The actual transaction.
    pub tx: Transaction,
}

impl convert::AsRef<Transaction> for PrefilledTransaction {
    fn as_ref(&self) -> &Transaction {
        &self.tx
    }
}

impl Encodable for PrefilledTransaction {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        Ok(VarInt(self.idx as u64).consensus_encode(&mut s)? + self.tx.consensus_encode(s)?)
    }
}

impl Decodable for PrefilledTransaction {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<PrefilledTransaction, encode::Error> {
        let idx = VarInt::consensus_decode(&mut d)?.0;
        if idx > u16::max_value() as u64 {
            //TODO use TryInto instead when MSRV exceeds 1.34
            return Err(encode::Error::ParseFailed("BIP152 prefilled tx index out of bounds"));
        }
        let tx = Transaction::consensus_decode(d)?;
        Ok(PrefilledTransaction { idx: idx as u16, tx: tx })
    }
}

/// Short transaction IDs are used to represent a transaction without sending a full 256-bit hash.
#[derive(PartialEq, Eq, Clone, Copy, Hash, Default)]
pub struct ShortId(pub [u8; 6]);

impl ShortId {
    /// Calculate the SipHash24 keys used to calculate short IDs.
    pub fn calculate_siphash_keys(header: &BlockHeader, nonce: u64) -> (u64, u64) {
        // 1. single-SHA256 hashing the block header with the nonce appended (in little-endian)
        let h = {
            let mut engine = sha256::Hash::engine();
            header.consensus_encode(&mut engine).expect("engines don't error");
            nonce.consensus_encode(&mut engine).expect("engines don't error");
            sha256::Hash::from_engine(engine)
        };

        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        (endian::slice_to_u64_le(&h[0..8]), endian::slice_to_u64_le(&h[8..16]))
    }

    /// Calculate the short ID with the given (w)txid and using the provided SipHash keys.
    pub fn with_siphash_keys<T: AsRef<[u8]>>(txid: &T, siphash_keys: (u64, u64)) -> ShortId {
        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        let hash = siphash24::Hash::hash_with_keys(siphash_keys.0, siphash_keys.1, txid.as_ref());

        // 3. Dropping the 2 most significant bytes from the SipHash output to make it 6 bytes.
        let mut id = ShortId([0; 6]);
        id.0.copy_from_slice(&hash[0..6]);
        id
    }
}

impl hex::FromHex for ShortId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where
        I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        Ok(ShortId(hex::FromHex::from_byte_iter(iter)?))
    }
}

impl fmt::LowerHex for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::format_hex(&self.0[..], f)
    }
}

impl fmt::Display for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::Debug for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Encodable for ShortId {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        self.0.consensus_encode(s)
    }
}

impl Decodable for ShortId {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<ShortId, encode::Error> {
        Ok(ShortId(Decodable::consensus_decode(d)?))
    }
}

/// A [HeaderAndShortIDs] structure is used to relay a block header, the short
/// transactions IDs used for matching already-available transactions, and a
/// select few transactions which we expect a peer may be missing.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct HeaderAndShortIds {
    /// The header of the block being provided.
    pub header: BlockHeader,
    ///  A nonce for use in short transaction ID calculations.
    pub nonce: u64,
    ///  The short transaction IDs calculated from the transactions
    ///  which were not provided explicitly in prefilled_txs.
    pub short_ids: Vec<ShortId>,
    ///  Used to provide the coinbase transaction and a select few
    ///  which we expect a peer may be missing.
    pub prefilled_txs: Vec<PrefilledTransaction>,
}
impl_consensus_encoding!(HeaderAndShortIds, header, nonce, short_ids, prefilled_txs);

impl HeaderAndShortIds {
    /// Create a new [HeaderAndShortIds] from a full block.
    ///
    /// The version number must be either 1 or 2.
    ///
    /// The [prefill] slice indicates which transactions should be prefilled in
    /// the block. It should contain the indexes in the block of the txs to
    /// prefill. It must be ordered. 0 should not be included as the
    /// coinbase tx is always prefilled.
    ///
    /// > Nodes SHOULD NOT use the same nonce across multiple different blocks.
    ///
    /// Possible [Error] variants:
    /// - [UnknownVersion]: If the version is not 1 or 2.
    /// - [InvalidPrefill]: If the [prefill] slice was invalid.
    pub fn from_block(
        block: &Block,
        nonce: u64,
        version: u32,
        mut prefill: &[usize],
    ) -> Result<HeaderAndShortIds, Error> {
        if version != 1 && version != 2 {
            return Err(Error::UnknownVersion);
        }

        let siphash_keys = ShortId::calculate_siphash_keys(&block.header, nonce);

        let mut prefilled = vec![];
        let mut short_ids = vec![];
        let mut last_prefill = 0;
        for (idx, tx) in block.txdata.iter().enumerate() {
            // Check if we should prefill this tx.
            let prefill_tx = if prefill.get(0) == Some(&idx) {
                prefill = &prefill[1..];
                true
            } else {
                idx == 0 // Always prefill coinbase.
            };

            if prefill_tx {
                let diff_idx = idx - last_prefill;
                last_prefill = idx + 1;
                prefilled.push(PrefilledTransaction {
                    idx: diff_idx as u16,
                    tx: match version {
                        1 => {
                            // strip witness for version 1
                            let mut no_witness = tx.clone();
                            no_witness.input.iter_mut().for_each(|i| i.witness.clear());
                            no_witness
                        }
                        2 => tx.clone(),
                        _ => unreachable!(),
                    },
                });
            } else {
                short_ids.push(ShortId::with_siphash_keys(
                    &match version {
                        1 => tx.txid().as_hash(),
                        2 => tx.wtxid().as_hash(),
                        _ => unreachable!(),
                    },
                    siphash_keys,
                ));
            }
        }

        if !prefill.is_empty() {
            return Err(Error::InvalidPrefill);
        }

        Ok(HeaderAndShortIds {
            header: block.header.clone(),
            nonce: nonce,
            // Provide coinbase prefilled.
            prefilled_txs: prefilled,
            short_ids: short_ids,
        })
    }
}

/// A [BlockTransactionsRequest] structure is used to list transaction indexes
/// in a block being requested.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BlockTransactionsRequest {
    ///  The blockhash of the block which the transactions being requested are in.
    pub block_hash: BlockHash,
    ///  The indexes of the transactions being requested in the block.
    pub indexes: Vec<u64>,
}

impl Encodable for BlockTransactionsRequest {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = self.block_hash.consensus_encode(&mut s)?;
        // Manually encode indexes because they are differentially encoded VarInts.
        len += VarInt(self.indexes.len() as u64).consensus_encode(&mut s)?;
        let mut last_idx = 0;
        for idx in &self.indexes {
            len += VarInt(*idx - last_idx).consensus_encode(&mut s)?;
            last_idx = *idx + 1;
        }
        Ok(len)
    }
}

impl Decodable for BlockTransactionsRequest {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<BlockTransactionsRequest, encode::Error> {
        Ok(BlockTransactionsRequest {
            block_hash: BlockHash::consensus_decode(&mut d)?,
            indexes: {
                // Manually decode indexes because they are differentially encoded VarInts.
                let nb_indexes = VarInt::consensus_decode(&mut d)?.0 as usize;

                // Since the number of indices ultimately represent transactions,
                // we can limit the number of indices to the maximum number of
                // transactions that would be allowed in a vector.
                let byte_size = (nb_indexes as usize)
                                    .checked_mul(mem::size_of::<Transaction>())
                                    .ok_or(encode::Error::ParseFailed("Invalid length"))?;
                if byte_size > encode::MAX_VEC_SIZE {
                    return Err(encode::Error::OversizedVectorAllocation {
                        requested: byte_size,
                        max: encode::MAX_VEC_SIZE,
                    });
                }

                let mut indexes = Vec::with_capacity(nb_indexes);
                let mut last_index: u64 = 0;
                for _ in 0..nb_indexes {
                    let differential: VarInt = Decodable::consensus_decode(&mut d)?;
                    last_index  = match last_index.checked_add(differential.0 + 1) {
                        Some(r) => r,
                        None => return Err(encode::Error::ParseFailed("block index overflow")),
                    };
                    indexes.push(last_index);
                }
                indexes
            },
        })
    }
}

/// A [BlockTransactions] structure is used to provide some of the transactions
/// in a block, as requested.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BlockTransactions {
    ///  The blockhash of the block which the transactions being provided are in.
    pub block_hash: BlockHash,
    ///  The transactions provided.
    pub transactions: Vec<Transaction>,
}
impl_consensus_encoding!(BlockTransactions, block_hash, transactions);

impl BlockTransactions {
    /// Construct a [BlockTransactions] from a [BlockTransactionsRequest] and
    /// the corresponsing full [Block] by providing all requested transactions.
    ///
    /// Possible [Error] variants:
    /// - [TxIndexOutOfRange]: When a transaction index is requested that is our
    /// of range from the corresponding block.
    pub fn from_request(
        request: &BlockTransactionsRequest,
        block: &Block,
    ) -> Result<BlockTransactions, Error> {
        Ok(BlockTransactions {
            block_hash: request.block_hash,
            transactions: {
                let mut txs = Vec::with_capacity(request.indexes.len());
                for idx in &request.indexes {
                    if *idx >= block.txdata.len() as u64 {
                        return Err(Error::TxIndexOutOfRange(*idx));
                    }
                    txs.push(block.txdata[*idx as usize].clone());
                }
                txs
            },
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hashes::hex::FromHex;
    use consensus::encode::deserialize;
    use ::{Block, Transaction, TxIn, TxOut, OutPoint, Txid, BlockHash, TxMerkleNode, Script, BlockHeader};

    fn dummy_tx(nonce: &[u8]) -> Transaction {
        Transaction {
            version: 1, lock_time: 2,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::hash(nonce), 0),
                script_sig: Script::new(), sequence: 1, witness: Vec::new(),
            }],
            output: vec![TxOut { value: 1, script_pubkey: Script::new() }],
        }
    }

    fn dummy_block() -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::hash(&[0]),
                merkle_root: TxMerkleNode::hash(&[1]),
                time: 2, bits: 3, nonce: 4,
            },
            txdata: vec![dummy_tx(&[2]), dummy_tx(&[3]), dummy_tx(&[4])],
        }
    }

    #[test]
    fn test_header_and_short_ids_from_block() {
        let block = dummy_block();

        let compact = HeaderAndShortIds::from_block(&block, 42, 2, &[]).unwrap();
        assert_eq!(compact.nonce, 42);
        assert_eq!(compact.short_ids.len(), 2);
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].idx, 0);
        assert_eq!(&compact.prefilled_txs[0].tx, &block.txdata[0]);

        let compact = HeaderAndShortIds::from_block(&block, 42, 2, &[0,1,2]).unwrap();
        let idxs = compact.prefilled_txs.iter().map(|t| t.idx).collect::<Vec<_>>();
        assert_eq!(idxs, vec![0, 0, 0]);

        let compact = HeaderAndShortIds::from_block(&block, 42, 2, &[2]).unwrap();
        let idxs = compact.prefilled_txs.iter().map(|t| t.idx).collect::<Vec<_>>();
        assert_eq!(idxs, vec![0, 1]);
    }

    #[test]
    fn test_compact_block_vector() {
        // Tested with Elements implementation of compact blocks.
        let raw_block = Vec::<u8>::from_hex("000000206c750a364035aefd5f81508a08769975116d9195312ee4520dceac39e1fdc62c4dc67473b8e354358c1e610afeaff7410858bd45df43e2940f8a62bd3d5e3ac943c2975cffff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04016b0101ffffffff020006062a0100000001510000000000000000266a24aa21a9ed4a3d9f3343dafcc0d6f6d4310f2ee5ce273ed34edca6c75db3a73e7f368734200120000000000000000000000000000000000000000000000000000000000000000000000000020000000001021fc20ba2bd745507b8e00679e3b362558f9457db374ca28ffa5243f4c23a4d5f00000000171600147c9dea14ffbcaec4b575e03f05ceb7a81cd3fcbffdffffff915d689be87b43337f42e26033df59807b768223368f189a023d0242d837768900000000171600147c9dea14ffbcaec4b575e03f05ceb7a81cd3fcbffdffffff0200cdf5050000000017a9146803c72d9154a6a20f404bed6d3dcee07986235a8700e1f5050000000017a9144e6a4c7cb5b5562904843bdf816342f4db9f5797870247304402205e9bf6e70eb0e4b495bf483fd8e6e02da64900f290ef8aaa64bb32600d973c450220670896f5d0e5f33473e5f399ab680cc1d25c2d2afd15abd722f04978f28be887012103e4e4d9312b2261af508b367d8ba9be4f01b61d6d6e78bec499845b4f410bcf2702473044022045ac80596a6ac9c8c572f94708709adaf106677221122e08daf8b9741a04f66a022003ccd52a3b78f8fd08058fc04fc0cffa5f4c196c84eae9e37e2a85babe731b57012103e4e4d9312b2261af508b367d8ba9be4f01b61d6d6e78bec499845b4f410bcf276a000000").unwrap();
        let raw_compact = Vec::<u8>::from_hex("000000206c750a364035aefd5f81508a08769975116d9195312ee4520dceac39e1fdc62c4dc67473b8e354358c1e610afeaff7410858bd45df43e2940f8a62bd3d5e3ac943c2975cffff7f2000000000a4df3c3744da89fa010a6979e971450100020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04016b0101ffffffff020006062a0100000001510000000000000000266a24aa21a9ed4a3d9f3343dafcc0d6f6d4310f2ee5ce273ed34edca6c75db3a73e7f368734200120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let block: Block = deserialize(&raw_block).unwrap();
        let nonce = 18053200567810711460;
        let compact = HeaderAndShortIds::from_block(&block, nonce, 2, &[]).unwrap();
        let compact_expected = deserialize(&raw_compact).unwrap();

        assert_eq!(compact, compact_expected);
    }
}
