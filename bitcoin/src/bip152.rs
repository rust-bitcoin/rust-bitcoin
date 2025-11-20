// SPDX-License-Identifier: CC0-1.0

//! BIP-0152 Compact Blocks.
//!
//! Implementation of compact blocks data structure and algorithms.

use core::convert::Infallible;
use core::{convert, fmt, mem};
#[cfg(feature = "std")]
use std::error;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::{sha256, siphash24};
use internals::array::ArrayExt as _;
use internals::ToU64 as _;
use io::{BufRead, Write};

use crate::consensus::encode::{self, Decodable, Encodable, ReadExt, WriteExt};
use crate::internal_macros::{self, impl_array_newtype, impl_array_newtype_stringify};
use crate::prelude::Vec;
use crate::transaction::TxIdentifier;
use crate::{block, consensus, Block, BlockChecked, BlockHash, Transaction};

/// A BIP-0152 error
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An unknown version number was used.
    UnknownVersion,
    /// The prefill slice provided was invalid.
    InvalidPrefill,
}

impl From<Infallible> for Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::UnknownVersion => write!(f, "an unknown version number was used"),
            Self::InvalidPrefill => write!(f, "the prefill slice provided was invalid"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            UnknownVersion | InvalidPrefill => None,
        }
    }
}

/// A [`PrefilledTransaction`] structure is used in [`HeaderAndShortIds`] to
/// provide a list of a few transactions explicitly.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
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
    fn as_ref(&self) -> &Transaction { &self.tx }
}

impl Encodable for PrefilledTransaction {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        Ok(w.emit_compact_size(self.idx)? + self.tx.consensus_encode(w)?)
    }
}

impl Decodable for PrefilledTransaction {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let idx = r.read_compact_size()?;
        let idx = u16::try_from(idx).map_err(|_| {
            consensus::parse_failed_error("BIP-0152 prefilled tx index out of bounds")
        })?;
        let tx = Transaction::consensus_decode(r)?;
        Ok(Self { idx, tx })
    }
}

/// Short transaction IDs are used to represent a transaction without sending a full 256-bit hash.
#[derive(PartialEq, Eq, Clone, Copy, Hash, Default, PartialOrd, Ord)]
pub struct ShortId([u8; 6]);
impl_array_newtype!(ShortId, u8, 6);
impl_array_newtype_stringify!(ShortId, 6);

impl ShortId {
    /// Calculates the SipHash24 keys used to calculate short IDs.
    pub fn calculate_siphash_keys(header: &block::Header, nonce: u64) -> (u64, u64) {
        // 1. single-SHA256 hashing the block header with the nonce appended (in little-endian)
        let h = {
            let mut engine = sha256::Hash::engine();
            header.consensus_encode(&mut engine).expect("engines don't error");
            nonce.consensus_encode(&mut engine).expect("engines don't error");
            sha256::Hash::from_engine(engine)
        };

        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        (
            u64::from_le_bytes(*h.as_byte_array().sub_array::<0, 8>()),
            u64::from_le_bytes(*h.as_byte_array().sub_array::<8, 8>()),
        )
    }

    /// Calculates the short ID with the given (w)txid and using the provided SipHash keys.
    pub fn with_siphash_keys<T: TxIdentifier>(txid: &T, siphash_keys: (u64, u64)) -> Self {
        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        let hash = siphash24::Hash::hash_with_keys(siphash_keys.0, siphash_keys.1, txid.as_ref());

        // 3. Dropping the 2 most significant bytes from the SipHash output to make it 6 bytes.
        let mut id = Self([0; 6]);
        id.0.copy_from_slice(&hash.as_byte_array()[0..6]);
        id
    }
}

impl Encodable for ShortId {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ShortId {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self(Decodable::consensus_decode(r)?))
    }
}

/// A structure to relay a block header, short IDs, and a select few transactions.
///
/// A [`HeaderAndShortIds`] structure is used to relay a block header, the short
/// transactions IDs used for matching already-available transactions, and a
/// select few transactions which we expect a peer may be missing.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct HeaderAndShortIds {
    /// The header of the block being provided.
    pub header: block::Header,
    ///  A nonce for use in short transaction ID calculations.
    pub nonce: u64,
    ///  The short transaction IDs calculated from the transactions
    ///  which were not provided explicitly in prefilled_txs.
    pub short_ids: Vec<ShortId>,
    ///  Used to provide the coinbase transaction and a select few
    ///  which we expect a peer may be missing.
    pub prefilled_txs: Vec<PrefilledTransaction>,
}

impl Decodable for HeaderAndShortIds {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let header_short_ids = Self {
            header: Decodable::consensus_decode(r)?,
            nonce: Decodable::consensus_decode(r)?,
            short_ids: Decodable::consensus_decode(r)?,
            prefilled_txs: Decodable::consensus_decode(r)?,
        };
        match header_short_ids.short_ids.len().checked_add(header_short_ids.prefilled_txs.len()) {
            Some(x) if x <= u16::MAX.into() => Ok(header_short_ids),
            _ => Err(consensus::parse_failed_error("indexes overflowed 16 bits")),
        }
    }
}

impl Encodable for HeaderAndShortIds {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.header.consensus_encode(w)?;
        len += self.nonce.consensus_encode(w)?;
        len += self.short_ids.consensus_encode(w)?;
        len += self.prefilled_txs.consensus_encode(w)?;
        Ok(len)
    }
}

impl HeaderAndShortIds {
    /// Constructs a new [`HeaderAndShortIds`] from a full block.
    ///
    /// The version number must be either 1 or 2.
    ///
    /// The `prefill` slice indicates which transactions should be prefilled in
    /// the block. It should contain the indexes in the block of the txs to
    /// prefill. It must be ordered. 0 should not be included as the
    /// coinbase tx is always prefilled.
    ///
    /// > Nodes SHOULD NOT use the same nonce across multiple different blocks.
    pub fn from_block(
        block: &Block<BlockChecked>,
        nonce: u64,
        version: u32,
        mut prefill: &[usize],
    ) -> Result<Self, Error> {
        if version != 1 && version != 2 {
            return Err(Error::UnknownVersion);
        }

        let siphash_keys = ShortId::calculate_siphash_keys(block.header(), nonce);

        let mut prefilled = Vec::with_capacity(prefill.len() + 1); // +1 for coinbase tx
        let mut short_ids = Vec::with_capacity(block.transactions().len() - prefill.len());
        let mut last_prefill = 0;
        for (idx, tx) in block.transactions().iter().enumerate() {
            // Check if we should prefill this tx.
            let prefill_tx = if prefill.first() == Some(&idx) {
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
                        // >  As encoded in "tx" messages sent in response to getdata MSG_TX
                        1 => {
                            // strip witness for version 1
                            let mut no_witness = tx.clone();
                            no_witness.inputs.iter_mut().for_each(|i| i.witness.clear());
                            no_witness
                        }
                        // > Transactions inside cmpctblock messages (both those used as direct
                        // > announcement and those in response to getdata) and in blocktxn should
                        // > include witness data, using the same format as responses to getdata
                        // > MSG_WITNESS_TX, specified in BIP-0144.
                        2 => tx.clone(),
                        _ => unreachable!(),
                    },
                });
            } else {
                match version {
                    1 =>
                        short_ids.push(ShortId::with_siphash_keys(&tx.compute_txid(), siphash_keys)),
                    2 => short_ids
                        .push(ShortId::with_siphash_keys(&tx.compute_wtxid(), siphash_keys)),
                    _ => unreachable!(),
                }
            }
        }

        if !prefill.is_empty() {
            return Err(Error::InvalidPrefill);
        }

        Ok(Self {
            header: *block.header(),
            nonce,
            // Provide coinbase prefilled.
            prefilled_txs: prefilled,
            short_ids,
        })
    }
}

/// A [`BlockTransactionsRequest`] structure is used to list transaction indexes
/// in a block being requested.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct BlockTransactionsRequest {
    ///  The blockhash of the block which the transactions being requested are in.
    pub block_hash: BlockHash,
    ///  The indexes of the transactions being requested in the block.
    ///
    ///  Warning: Encoding panics with [`u64::MAX`] values. See [`BlockTransactionsRequest::consensus_encode()`]
    pub indexes: Vec<u64>,
}

impl Encodable for BlockTransactionsRequest {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.block_hash.consensus_encode(w)?;
        // Manually encode indexes because they are differentially encoded as CompactSize.
        len += w.emit_compact_size(self.indexes.len())?;
        let mut last_idx = 0;
        for idx in &self.indexes {
            len += w.emit_compact_size(*idx - last_idx)?;
            last_idx = *idx + 1; // can panic here
        }
        Ok(len)
    }
}

impl Decodable for BlockTransactionsRequest {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            block_hash: BlockHash::consensus_decode(r)?,
            indexes: {
                // Manually decode indexes because they are differentially encoded as CompactSize.
                let nb_indexes = r.read_compact_size()? as usize;

                // Since the number of indices ultimately represent transactions,
                // we can limit the number of indices to the maximum number of
                // transactions that would be allowed in a vector.
                let byte_size = nb_indexes
                    .checked_mul(mem::size_of::<Transaction>())
                    .ok_or(consensus::parse_failed_error("invalid length"))?;
                if byte_size > encode::MAX_VEC_SIZE {
                    return Err(encode::ParseError::OversizedVectorAllocation {
                        requested: byte_size,
                        max: encode::MAX_VEC_SIZE,
                    }
                    .into());
                }

                let mut indexes = Vec::with_capacity(nb_indexes);
                let mut last_index: u64 = 0;
                for _ in 0..nb_indexes {
                    let differential = r.read_compact_size()?;
                    last_index = match last_index.checked_add(differential) {
                        Some(i) => i,
                        None => return Err(consensus::parse_failed_error("block index overflow")),
                    };
                    indexes.push(last_index);
                    last_index = match last_index.checked_add(1) {
                        Some(i) => i,
                        None => return Err(consensus::parse_failed_error("block index overflow")),
                    };
                }
                indexes
            },
        })
    }
}

/// A transaction index is requested that is out of range from the
/// corresponding block.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TxIndexOutOfRangeError(u64);

impl fmt::Display for TxIndexOutOfRangeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "a transaction index is requested that is \
            out of range from the corresponding block: {}",
            self.0,
        )
    }
}

#[cfg(feature = "std")]
impl error::Error for TxIndexOutOfRangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// A [`BlockTransactions`] structure is used to provide some of the transactions
/// in a block, as requested.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct BlockTransactions {
    ///  The blockhash of the block which the transactions being provided are in.
    pub block_hash: BlockHash,
    ///  The transactions provided.
    pub transactions: Vec<Transaction>,
}
internal_macros::impl_consensus_encoding!(BlockTransactions, block_hash, transactions);

impl BlockTransactions {
    /// Constructs a new [`BlockTransactions`] from a [`BlockTransactionsRequest`] and
    /// the corresponding full [`Block`] by providing all requested transactions.
    pub fn from_request(
        request: &BlockTransactionsRequest,
        block: &Block<BlockChecked>,
    ) -> Result<Self, TxIndexOutOfRangeError> {
        Ok(Self {
            block_hash: request.block_hash,
            transactions: {
                let mut txs = Vec::with_capacity(request.indexes.len());
                for idx in &request.indexes {
                    if *idx >= block.transactions().len().to_u64() {
                        return Err(TxIndexOutOfRangeError(*idx));
                    }
                    txs.push(block.transactions()[*idx as usize].clone());
                }
                txs
            },
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ShortId {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> { Ok(Self(u.arbitrary()?)) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for PrefilledTransaction {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { idx: u.arbitrary()?, tx: u.arbitrary()? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for HeaderAndShortIds {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            header: u.arbitrary()?,
            nonce: u.arbitrary()?,
            short_ids: Vec::<ShortId>::arbitrary(u)?,
            prefilled_txs: Vec::<PrefilledTransaction>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BlockTransactions {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { block_hash: u.arbitrary()?, transactions: Vec::<Transaction>::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BlockTransactionsRequest {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { block_hash: u.arbitrary()?, indexes: Vec::<u64>::arbitrary(u)? })
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::locktime::absolute;
    use crate::merkle_tree::TxMerkleNode;
    use crate::transaction::OutPointExt;
    use crate::{
        transaction, Amount, BlockChecked, BlockTime, CompactTarget, OutPoint, ScriptPubKeyBuf,
        ScriptSigBuf, Sequence, TxIn, TxOut, Txid, Witness,
    };

    fn dummy_tx(nonce: &[u8]) -> Transaction {
        let dummy_txid = Txid::from_byte_array(hashes::sha256::Hash::hash(nonce).to_byte_array());
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::from_consensus(2),
            inputs: vec![TxIn {
                previous_output: OutPoint::new(dummy_txid, 0),
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence(1),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
        }
    }

    fn dummy_block() -> Block<BlockChecked> {
        let header = block::Header {
            version: block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0x77; 32]),
            time: BlockTime::from_u32(2),
            bits: CompactTarget::from_consensus(3),
            nonce: 4,
        };
        let transactions = vec![dummy_tx(&[2]), dummy_tx(&[3]), dummy_tx(&[4])];
        Block::new_unchecked(header, transactions).assume_checked(None)
    }

    #[test]
    fn header_and_short_ids_from_block() {
        let block = dummy_block();

        let compact = HeaderAndShortIds::from_block(&block, 42, 2, &[]).unwrap();
        assert_eq!(compact.nonce, 42);
        assert_eq!(compact.short_ids.len(), 2);
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].idx, 0);
        assert_eq!(&compact.prefilled_txs[0].tx, &block.transactions()[0]);

        let compact = HeaderAndShortIds::from_block(&block, 42, 2, &[0, 1, 2]).unwrap();
        let idxs = compact.prefilled_txs.iter().map(|t| t.idx).collect::<Vec<_>>();
        assert_eq!(idxs, [0, 0, 0]);

        let compact = HeaderAndShortIds::from_block(&block, 42, 2, &[2]).unwrap();
        let idxs = compact.prefilled_txs.iter().map(|t| t.idx).collect::<Vec<_>>();
        assert_eq!(idxs, [0, 1]);
    }

    #[test]
    fn compact_block_vector() {
        // Tested with Elements implementation of compact blocks.
        let raw_block = Vec::<u8>::from_hex("000000206c750a364035aefd5f81508a08769975116d9195312ee4520dceac39e1fdc62c4dc67473b8e354358c1e610afeaff7410858bd45df43e2940f8a62bd3d5e3ac943c2975cffff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04016b0101ffffffff020006062a0100000001510000000000000000266a24aa21a9ed4a3d9f3343dafcc0d6f6d4310f2ee5ce273ed34edca6c75db3a73e7f368734200120000000000000000000000000000000000000000000000000000000000000000000000000020000000001021fc20ba2bd745507b8e00679e3b362558f9457db374ca28ffa5243f4c23a4d5f00000000171600147c9dea14ffbcaec4b575e03f05ceb7a81cd3fcbffdffffff915d689be87b43337f42e26033df59807b768223368f189a023d0242d837768900000000171600147c9dea14ffbcaec4b575e03f05ceb7a81cd3fcbffdffffff0200cdf5050000000017a9146803c72d9154a6a20f404bed6d3dcee07986235a8700e1f5050000000017a9144e6a4c7cb5b5562904843bdf816342f4db9f5797870247304402205e9bf6e70eb0e4b495bf483fd8e6e02da64900f290ef8aaa64bb32600d973c450220670896f5d0e5f33473e5f399ab680cc1d25c2d2afd15abd722f04978f28be887012103e4e4d9312b2261af508b367d8ba9be4f01b61d6d6e78bec499845b4f410bcf2702473044022045ac80596a6ac9c8c572f94708709adaf106677221122e08daf8b9741a04f66a022003ccd52a3b78f8fd08058fc04fc0cffa5f4c196c84eae9e37e2a85babe731b57012103e4e4d9312b2261af508b367d8ba9be4f01b61d6d6e78bec499845b4f410bcf276a000000").unwrap();
        let raw_compact = Vec::<u8>::from_hex("000000206c750a364035aefd5f81508a08769975116d9195312ee4520dceac39e1fdc62c4dc67473b8e354358c1e610afeaff7410858bd45df43e2940f8a62bd3d5e3ac943c2975cffff7f2000000000a4df3c3744da89fa010a6979e971450100020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04016b0101ffffffff020006062a0100000001510000000000000000266a24aa21a9ed4a3d9f3343dafcc0d6f6d4310f2ee5ce273ed34edca6c75db3a73e7f368734200120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let block: Block = deserialize(&raw_block).unwrap();
        let block = block.assume_checked(None);
        let nonce = 18053200567810711460;
        let compact = HeaderAndShortIds::from_block(&block, nonce, 2, &[]).unwrap();
        let compact_expected = deserialize(&raw_compact).unwrap();

        assert_eq!(compact, compact_expected);
    }

    #[test]
    fn getblocktx_differential_encoding_de_and_serialization() {
        let testcases = vec![
            // differentially encoded CompactSizes, indices
            (vec![4, 0, 5, 1, 10], vec![0, 6, 8, 19]),
            (vec![1, 0], vec![0]),
            (vec![5, 0, 0, 0, 0, 0], vec![0, 1, 2, 3, 4]),
            (vec![3, 1, 1, 1], vec![1, 3, 5]),
            (vec![3, 0, 0, 253, 0, 1], vec![0, 1, 258]), // .., 253, 0, 1] == CompactSize(256)
        ];
        let deser_errorcases = vec![
            vec![2, 255, 254, 255, 255, 255, 255, 255, 255, 255, 0], // .., 255, 254, .., 255] == CompactSize(u64::MAX-1)
            vec![1, 255, 255, 255, 255, 255, 255, 255, 255, 255], // .., 255, 255, .., 255] == CompactSize(u64::MAX)
        ];
        for testcase in testcases {
            {
                // test deserialization
                let mut raw: Vec<u8> = vec![0u8; 32];
                raw.extend(testcase.0.clone());
                let btr: BlockTransactionsRequest = deserialize(&raw.to_vec()).unwrap();
                assert_eq!(testcase.1, btr.indexes);
            }
            {
                // test serialization
                let raw: Vec<u8> = serialize(&BlockTransactionsRequest {
                    block_hash: BlockHash::from_byte_array([0; 32]),
                    indexes: testcase.1,
                });
                let mut expected_raw: Vec<u8> = [0u8; 32].to_vec();
                expected_raw.extend(testcase.0);
                assert_eq!(expected_raw, raw);
            }
        }
        for errorcase in deser_errorcases {
            {
                // test that we return Err() if deserialization fails (and don't panic)
                let mut raw: Vec<u8> = [0u8; 32].to_vec();
                raw.extend(errorcase);
                assert!(deserialize::<BlockTransactionsRequest>(&raw.to_vec()).is_err());
            }
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic] // 'attempt to add with overflow' in consensus_encode()
    fn getblocktx_panic_when_encoding_u64_max() {
        serialize(&BlockTransactionsRequest {
            block_hash: BlockHash::from_byte_array([0; 32]),
            indexes: vec![u64::MAX],
        });
    }
}
