// SPDX-License-Identifier: CC0-1.0

//! Bitcoin block data.
//!
//! This module defines structures and functions for storing the blocks and
//! transactions which make up the Bitcoin system.

pub mod constants;
pub mod script;
pub mod transaction;
pub mod witness;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    fee_rate::FeeRate,
    weight::Weight
};

pub mod block {
    //! Bitcoin blocks.
    //!
    //! A block is a bundle of transactions with a proof-of-work attached,
    //! which commits to an earlier block to form the blockchain. This
    //! module describes structures and functions needed to describe
    //! these blocks and the blockchain.

    /// Re-export everything from the [`primitives::block`] module.
    #[doc(inline)]
    pub use crate::primitives::block::*;
}

pub mod locktime {
    //! Provides absolute and relative locktimes.

    pub mod absolute {
        //! Provides type [`LockTime`] that implements the logic around nLockTime/OP_CHECKLOCKTIMEVERIFY.
        //!
        //! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
        //! whether `LockTime < LOCKTIME_THRESHOLD`.

        /// Re-export everything from the [`primitives::locktime::absolute`] module.
        #[doc(inline)]
        pub use primitives::locktime::absolute::*;
    }

    pub mod relative {
        //! Provides type [`LockTime`] that implements the logic around nSequence/OP_CHECKSEQUENCEVERIFY.
        //!
        //! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
        //! whether bit 22 of the `u32` consensus value is set.

        /// Re-export everything from the [`primitives::locktime::relative`] module.
        #[doc(inline)]
        pub use crate::primitives::locktime::relative::*;
    }
}

/// Implements `FeeRate` and assoctiated features.
pub mod fee_rate {
    /// Re-export everything from the [`units::fee_rate`] module.
    pub use units::fee_rate::*;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fee_convenience_functions_agree() {
            use hex::test_hex_unwrap as hex;

            use crate::blockdata::transaction::Transaction;
            use crate::consensus::Decodable;

            const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

            let raw_tx = hex!(SOME_TX);
            let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

            let rate = FeeRate::from_sat_per_vb(1).expect("1 sat/byte is valid");

            assert_eq!(rate.fee_vb(tx.vsize() as u64), rate.fee_wu(tx.weight()));
        }
    }
}

pub mod opcodes {
    //! Bitcoin script opcodes.
    //!
    //! Bitcoin's script uses a stack-based assembly language. This module defines
    //! all of the opcodes for that language.

    /// Re-export everything from the [`primitives::opcodes`] module.
    #[doc(inline)]
    pub use crate::primitives::opcodes::*;
}

/// Implements `Weight` and associated features.
pub mod weight {
    /// Re-export everything from the [`units::weight`] module.
    pub use units::weight::*;
}
