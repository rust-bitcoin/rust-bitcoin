// SPDX-License-Identifier: CC0-1.0

//! Stable compatibility layer.
//!
//! This module re-exports types from stable crates (e.g. `bitcoin-units-1.0.0`). The aim is to ease
//! the upgrade path from `bitcoin 0.32` to subsequent `bitcoin` versions as we release them.
//!
//! With this module, coupled with the `to_stable`/`from_stable` functions, downstream projects can
//! update to use stable crates at their leisure without the whole ecosystem having to upgrade at
//! once. The intention is to provide stable types for the most common `rust-bitcoin` types used by
//! downstream libraries.

#[doc(inline)]
pub use bitcoin_units_stable::{
    amount, block, fee_rate, locktime, parse_int, pow, result, sequence, time, weight
};
#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::FeeRate,
    locktime::{absolute, relative},
    pow::{CompactTarget, Target, Work},
    result::NumOpResult,
    sequence::Sequence,
    time::BlockTime,
    weight::Weight
};

#[cfg(test)]
mod tests {
    use crate::Sequence;

    #[test]
    fn demo() {
        let seq = Sequence::default();
        let stable = seq.to_stable();
        
        // Now call into some other library that uses stable types in its API.
        // E.g., `other_lib::some_function(stable);`

        let unstable = Sequence::from_stable(stable);
        assert_eq!(unstable, seq);
    }
}
