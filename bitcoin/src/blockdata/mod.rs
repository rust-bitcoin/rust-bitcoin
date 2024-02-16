// SPDX-License-Identifier: CC0-1.0

//! Bitcoin block data.
//!
//! This module defines structures and functions for storing the blocks and
//! transactions which make up the Bitcoin system.
//!

pub mod block;
pub mod constants;
pub mod fee_rate;
pub mod opcodes;
pub mod script;
pub mod transaction;
pub mod weight;
pub mod witness;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    fee_rate::FeeRate,
    weight::Weight
};

/// Provides absolute and relative locktimes.
pub mod locktime {
    /// Provides type [`LockTime`] that implements the logic around nLockTime/OP_CHECKLOCKTIMEVERIFY.
    pub mod absolute {
        use crate::consensus::encode::{self, Encodable, Decodable};
        use crate::io::{BufRead, Write};

        #[rustfmt::skip]                // Keep public re-exports separate.
        #[doc(inline)]
        pub use primitives::locktime::absolute::LockTime;
        #[doc(inline)]
        pub use units::locktime::absolute::{Height, Time};

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

    /// Provides type [`LockTime`] that implements the logic around nSequence/OP_CHECKSEQUENCEVERIFY.
    pub mod relative {
        #[doc(inline)]
        pub use primitives::locktime::relative::LockTime;
        #[doc(inline)]
        pub use units::locktime::relative::{Height, Time};
    }
}
