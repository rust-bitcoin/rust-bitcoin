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

use std::io;

use consensus::encode::{Encodable, Decodable, Error};
use hashes::{sha256, sha256d, hash160, Hash};
use hashes::hex::{ToHex, FromHex};

macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl Encodable for $hashtype {
            fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, Error> {
                self.0.consensus_encode(s)
            }
        }

        impl Decodable for $hashtype {
            fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
                let inner = <<$hashtype as Hash>::Inner>::consensus_decode(d)?;
                Ok(Self::from_slice(&inner).unwrap())
            }
        }
    }
}

hash_newtype!(Txid, sha256d::Hash, 32, doc="A bitcoin transaction hash/transaction ID.");
hash_newtype!(Wtxid, sha256d::Hash, 32, doc="A bitcoin witness transaction ID.");
hash_newtype!(BlockHash, sha256d::Hash, 32, doc="A bitcoin block hash.");
hash_newtype!(PubkeyHash, hash160::Hash, 20, doc="A hash of a public key.");
hash_newtype!(ScriptHash, hash160::Hash, 20, doc="A hash of Bitcoin Script bytecode.");
hash_newtype!(WPubkeyHash, hash160::Hash, 20, doc="SegWit version of a public key hash.");
hash_newtype!(WScriptHash, sha256::Hash, 32, doc="SegWit version of a Bitcoin Script bytecode hash.");
hash_newtype!(XpubIdentifier, hash160::Hash, 20, doc="XpubIdentifier as defined in BIP-32.");

impl_hashencode!(Txid);
