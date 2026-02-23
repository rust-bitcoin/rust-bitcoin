// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Merkle tree functions.
//!
//! # Examples
//!
//! ```
//! # use bitcoin::Txid;
//! # use bitcoin::merkle_tree::TxMerkleNode;
//! # let tx1 = Txid::from_byte_array([0xAA; 32]);  // Arbitrary dummy hash values.
//! # let tx2 = Txid::from_byte_array([0xFF; 32]);
//! let tx_hashes = [tx1, tx2]; // All the hashes we wish to merkelize.
//! let root = TxMerkleNode::calculate_root(tx_hashes.into_iter());
//! assert!(root.is_some());
//! ```

use io::{BufRead, Write};

#[rustfmt::skip]
#[doc(inline)]
pub use primitives::{
    TxMerkleNode, WitnessMerkleNode,
    merkle_tree::{TxMerkleNodeDecoder, TxMerkleNodeEncoder},
};
#[doc(no_inline)]
pub use primitives::merkle_tree::TxMerkleNodeDecoderError;

use crate::consensus::{encode, Decodable, Encodable};

impl Encodable for TxMerkleNode {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.to_byte_array().consensus_encode(w)
    }
}

impl Decodable for TxMerkleNode {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self::from_byte_array(<[u8; 32]>::consensus_decode(r)?))
    }
}

impl Encodable for WitnessMerkleNode {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.to_byte_array().consensus_encode(w)
    }
}

impl Decodable for WitnessMerkleNode {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self::from_byte_array(<[u8; 32]>::consensus_decode(r)?))
    }
}
