// SPDX-License-Identifier: CC0-1.0

//! Bitcoin block data.
//!
//! This module defines structures and functions for storing the blocks and
//! transactions which make up the Bitcoin system.

pub mod block;
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

/// Implements `FeeRate` and assoctiated features.
pub mod fee_rate {
    /// Re-export everything from the [`units::fee_rate`] module.
    pub use units::fee_rate::*;

    #[cfg(test)]
    mod tests {
        use internals::ToU64 as _;

        use super::*;

        #[test]
        fn fee_convenience_functions_agree() {
            use hex::test_hex_unwrap as hex;

            use crate::consensus::Decodable;
            use crate::transaction::Transaction;

            const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

            let raw_tx = hex!(SOME_TX);
            let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

            let rate = FeeRate::from_sat_per_vb(1).expect("1 sat/byte is valid");

            assert_eq!(rate.fee_vb(tx.vsize().to_u64()), rate.fee_wu(tx.weight()));
        }
    }
}

/// Provides absolute and relative locktimes.
pub mod locktime {
    pub mod absolute {
        //! Provides type [`LockTime`] that implements the logic around nLockTime/OP_CHECKLOCKTIMEVERIFY.
        //!
        //! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
        //! whether `LockTime < LOCKTIME_THRESHOLD`.

        use io::{BufRead, Write};

        pub use crate::consensus::encode::{self, Decodable, Encodable};

        /// Re-export everything from the `primitives::locktime::absolute` module.
        #[rustfmt::skip]        // Keep public re-exports separate.
        pub use primitives::locktime::absolute::*;

        impl Encodable for LockTime {
            #[inline]
            fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
                let v = self.to_consensus_u32();
                v.consensus_encode(w)
            }
        }

        impl Decodable for LockTime {
            #[inline]
            fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
                u32::consensus_decode(r).map(LockTime::from_consensus)
            }
        }
    }

    pub mod relative {
        //! Provides type [`LockTime`] that implements the logic around nSequence/OP_CHECKSEQUENCEVERIFY.
        //!
        //! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
        //! whether bit 22 of the `u32` consensus value is set.

        /// Re-export everything from the `primitives::locktime::relative` module.
        pub use primitives::locktime::relative::*;
    }
}

/// Bitcoin script opcodes.
pub mod opcodes {
    /// Re-export everything from the [`primitives::opcodes`] module.
    pub use primitives::opcodes::*;
}

/// Implements `Weight` and associated features.
pub mod weight {
    /// Re-export everything from the [`units::weight`] module.
    pub use units::weight::*;
}
