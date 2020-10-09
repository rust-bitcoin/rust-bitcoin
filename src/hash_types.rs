// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! File defines types for hashes used throughout the library. These types are needed in order
//! to avoid mixing data of the same hash format (like SHA256d) but of different meaning
//! (transaction id, block hash etc).

use hashes::{Hash, sha256, sha256d, hash160};

macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl $crate::consensus::Encodable for $hashtype {
            fn consensus_encode<S: ::std::io::Write>(&self, s: S) -> Result<usize, $crate::consensus::encode::Error> {
                self.0.consensus_encode(s)
            }
        }

        impl $crate::consensus::Decodable for $hashtype {
            fn consensus_decode<D: ::std::io::Read>(d: D) -> Result<Self, $crate::consensus::encode::Error> {
                use $crate::hashes::Hash;
                Ok(Self::from_inner(<<$hashtype as $crate::hashes::Hash>::Inner>::consensus_decode(d)?))
            }
        }
    }
}

hash_newtype!(Txid, sha256d::Hash, 32, doc="A bitcoin transaction hash/transaction ID.");
hash_newtype!(Wtxid, sha256d::Hash, 32, doc="A bitcoin witness transaction ID.");
hash_newtype!(BlockHash, sha256d::Hash, 32, doc="A bitcoin block hash.");
hash_newtype!(SigHash, sha256d::Hash, 32, doc="Hash of the transaction according to the signature algorithm");

hash_newtype!(PubkeyHash, hash160::Hash, 20, doc="A hash of a public key.");
hash_newtype!(ScriptHash, hash160::Hash, 20, doc="A hash of Bitcoin Script bytecode.");
hash_newtype!(WPubkeyHash, hash160::Hash, 20, doc="SegWit version of a public key hash.");
hash_newtype!(WScriptHash, sha256::Hash, 32, doc="SegWit version of a Bitcoin Script bytecode hash.");

hash_newtype!(TxMerkleNode, sha256d::Hash, 32, doc="A hash of the Merkle tree branch or root for transactions");
hash_newtype!(WitnessMerkleNode, sha256d::Hash, 32, doc="A hash corresponding to the Merkle tree root for witness data");
hash_newtype!(WitnessCommitment, sha256d::Hash, 32, doc="A hash corresponding to the witness structure commitment in the coinbase transaction");
hash_newtype!(XpubIdentifier, hash160::Hash, 20, doc="XpubIdentifier as defined in BIP-32.");

hash_newtype!(FilterHash, sha256d::Hash, 32, doc="Bloom filter souble-SHA256 locator hash, as defined in BIP-168");


impl_hashencode!(Txid);
impl_hashencode!(Wtxid);
impl_hashencode!(SigHash);
impl_hashencode!(BlockHash);
impl_hashencode!(TxMerkleNode);
impl_hashencode!(WitnessMerkleNode);
impl_hashencode!(FilterHash);
