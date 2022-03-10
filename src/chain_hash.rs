//! Provides the chain hash type.
//!
//! ref: https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash
//!

use Network;
use blockdata::constants;
use hashes::Hash;

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    /// Returns the chain hash for `network`.
    pub fn for_network(network: Network) -> Self {
        let genesis = constants::genesis_block(network);
        ChainHash(genesis.block_hash().into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_chain_hash() {
        let mainnet = ChainHash::for_network(Network::Bitcoin);

        // Taken from BOLT 0 (linked above).
        let want = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
        let got = format!("{:x}", mainnet);

        assert_eq!(got, want);
    }
}
