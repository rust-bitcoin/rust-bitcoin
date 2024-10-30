// SPDX-License-Identifier: CC0-1.0

//! Bitcoin value.
//!
//! Provides the [`Value`] type, this is mainly for machine usage. If you are interacting with
//! humans consider using the [`Amount`] type.
//!
//! [`Amount`]: crate::Amount

use crate::{FeeRate, Weight};

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(inline)]
pub use units::value::{Value, ZERO, ONE_SAT, ONE_BTC, FIFTY_BTC};

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Value`] type.
    pub trait ValueExt impl for Value {
        /// Checked addition.
        ///
        /// Returns [`None`] if overflow occurred.
        fn checked_add(self, rhs: Value) -> Option<Value> {
            self.to_sat().checked_add(rhs.to_sat()).map(Value::from_sat)
        }

        /// Checked subtraction.
        ///
        /// Returns [`None`] if overflow occurred.
        fn checked_sub(self, rhs: Value) -> Option<Value> {
            self.to_sat().checked_sub(rhs.to_sat()).map(Value::from_sat)
        }

        /// Checked multiplication.
        ///
        /// Returns [`None`] if overflow occurred.
        fn checked_mul(self, rhs: u64) -> Option<Value> { self.to_sat().checked_mul(rhs).map(Value::from_sat) }

        /// Checked integer division.
        ///
        /// Be aware that integer division loses the remainder if no exact division
        /// can be made.
        /// Returns [`None`] if overflow occurred.
        fn checked_div(self, rhs: u64) -> Option<Value> { self.to_sat().checked_div(rhs).map(Value::from_sat) }

        /// Checked weight division.
        ///
        /// Be aware that integer division loses the remainder if no exact division
        /// can be made.  This method rounds up ensuring the transaction fee-rate is
        /// sufficient.  If you wish to round-down, use the unchecked version instead.
        ///
        /// [`None`] is returned if an overflow occurred.
        #[cfg(feature = "alloc")]
        fn checked_div_by_weight(self, rhs: Weight) -> Option<FeeRate> {
            let sats = self.to_sat().checked_mul(1000)?;
            let wu = rhs.to_wu();

            let fee_rate = sats.checked_add(wu.checked_sub(1)?)?.checked_div(wu)?;
            Some(FeeRate::from_sat_per_kwu(fee_rate))
        }

        /// Checked remainder.
        ///
        /// Returns [`None`] if overflow occurred.
        fn checked_rem(self, rhs: u64) -> Option<Value> { self.to_sat().checked_rem(rhs).map(Value::from_sat) }

        /// Unchecked addition.
        ///
        /// Computes `self + rhs`.
        ///
        /// # Panics
        ///
        /// On overflow, panics in debug mode, wraps in release mode.
        fn unchecked_add(self, rhs: Value) -> Value { Value::from_sat(self.to_sat() + rhs.to_sat()) }

        /// Unchecked subtraction.
        ///
        /// Computes `self - rhs`.
        ///
        /// # Panics
        ///
        /// On overflow, panics in debug mode, wraps in release mode.
        fn unchecked_sub(self, rhs: Value) -> Value { Value::from_sat(self.to_sat() - rhs.to_sat()) }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Value {}
}
