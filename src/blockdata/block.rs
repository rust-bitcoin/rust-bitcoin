// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Bitcoin Block
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which attaches to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use num::{FromPrimitive, Zero};

use util;
use util::Error::{SpvBadTarget, SpvBadProofOfWork};
use util::hash::Sha256dHash;
use util::uint::Uint256;
use network::encodable::{ConsensusEncodable, VarInt};
use network::serialize::BitcoinHash;
use blockdata::transaction::Transaction;

/// A block header, which contains all the block's information except
/// the actual transactions
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub struct BlockHeader {
    /// The protocol version. Should always be 1.
    pub version: u32,
    /// Reference to the previous block in the chain
    pub prev_blockhash: Sha256dHash,
    /// The root hash of the merkle tree of transactions in the block
    pub merkle_root: Sha256dHash,
    /// The timestamp of the block, as claimed by the mainer
    pub time: u32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course)
    pub bits: u32,
    /// The nonce, selected to obtain a low enough blockhash
    pub nonce: u32,
}

/// A Bitcoin block, which is a collection of transactions with an attached
/// proof of work.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Block {
    /// The block header
    pub header: BlockHeader,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>
}

/// A block header with txcount attached, which is given in the `headers`
/// network message.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct LoneBlockHeader {
    /// The actual block header
    pub header: BlockHeader,
    /// The number of transactions in the block. This will always be zero
    /// when the LoneBlockHeader is returned as part ef a `headers` message.
    pub tx_count: VarInt
}

impl BlockHeader {
    /// Computes the target [0, T] that a blockhash must land in to be valid
    pub fn target(&self) -> Uint256 {
        // This is a floating-point "compact" encoding originally used by
        // OpenSSL, which satoshi put into consensus code, so we're stuck
        // with it. The exponent needs to have 3 subtracted from it, hence
        // this goofy decoding code:
        let (mant, expt) = {
            let unshifted_expt = self.bits >> 24;
            if unshifted_expt <= 3 {
                ((self.bits & 0xFFFFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
            } else {
                (self.bits & 0xFFFFFF, 8 * ((self.bits >> 24) - 3))
            }
        };

        // The mantissa is signed but may not be negative
        if mant > 0x7FFFFF {
            Zero::zero()
        } else {
            <Uint256 as FromPrimitive>::from_u64(mant as u64).unwrap() << (expt as usize)
        }
    }

    /// Performs an SPV validation of a block, which confirms that the proof-of-work
    /// is correct, but does not verify that the transactions are valid or encoded
    /// correctly.
    pub fn spv_validate(&self, required_target: &Uint256) -> Result<(), util::Error> {
        let target = &self.target();
        if target != required_target {
            return Err(SpvBadTarget);
        }
        let hash = &self.bitcoin_hash().into_le();
        if hash <= target { Ok(()) } else { Err(SpvBadProofOfWork) }
    }

    /// Returns the total work of the block
    pub fn work(&self) -> Uint256 {
        // 2**256 / (target + 1) == ~target / (target+1) + 1    (eqn shamelessly stolen from bitcoind)
        let mut ret = !self.target();
        let mut ret1 = self.target();
        ret1.increment();
        ret = ret / ret1;
        ret.increment();
        ret
    }
}

impl BitcoinHash for BlockHeader {
    fn bitcoin_hash(&self) -> Sha256dHash {
        use network::serialize::serialize;
        Sha256dHash::from_data(&serialize(self).unwrap())
    }
}

impl BitcoinHash for Block {
    fn bitcoin_hash(&self) -> Sha256dHash {
        self.header.bitcoin_hash()
    }
}

impl_consensus_encoding!(BlockHeader, version, prev_blockhash, merkle_root, time, bits, nonce);
impl_consensus_encoding!(Block, header, txdata);
impl_consensus_encoding!(LoneBlockHeader, header, tx_count);

#[cfg(test)]
mod tests {
    use serialize::hex::FromHex;

    use blockdata::block::Block;
    use network::serialize::{deserialize, serialize};

    #[test]
    fn block_test() {
        let some_block = "010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000".from_hex().unwrap();
        let cutoff_block = "010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac".from_hex().unwrap();

        let prevhash = "4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000".from_hex().unwrap();
        let merkle = "bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c".from_hex().unwrap();

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, 1);
        assert_eq!(serialize(&real_decode.header.prev_blockhash).ok(), Some(prevhash));
        // [test] TODO: actually compute the merkle root
        assert_eq!(serialize(&real_decode.header.merkle_root).ok(), Some(merkle));
        assert_eq!(real_decode.header.time, 1231965655);
        assert_eq!(real_decode.header.bits, 486604799);
        assert_eq!(real_decode.header.nonce, 2067413810);
        // [test] TODO: check the transaction data
    
        assert_eq!(serialize(&real_decode).ok(), Some(some_block));
    }
}

