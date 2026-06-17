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

#[rustfmt::skip]
#[doc(inline)]
pub use primitives::merkle_tree::{TxMerkleNodeDecoder, TxMerkleNodeEncoder, TxMerkleNode, WitnessMerkleNode};
#[doc(no_inline)]
pub use primitives::merkle_tree::TxMerkleNodeDecoderError;
