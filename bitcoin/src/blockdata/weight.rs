// SPDX-License-Identifier: CC0-1.0

//! Weight
//!
//! This module contains the [`Weight`] struct and related methods to operate on it
//! Block weight represents virtual size (vsize) of a transaction measured in virtual bytes (vbytes).

// ensure explicit constructor
use std::ops::{Add, Sub, AddAssign, SubAssign, Mul};

/// Represents virtual transaction size
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Weight(usize);

impl Weight {
    pub(crate) const ZERO: Weight = Weight(0);

    pub(crate) fn from_witness_data_size(size: usize) -> Self {
        Weight(size)
    }

    pub(crate) fn from_non_witness_data_size(size: usize) -> Self {
        Weight(size * 4)
    }
}

impl From<Weight> for usize {
    fn from(value: Weight) -> Self {
        value.0
    }
}

impl Add for Weight {
    type Output = Weight;

    fn add(self, rhs: Weight) -> Self::Output {
        Weight(self.0 + rhs.0)
    }
}

impl Sub for Weight {
    type Output = Weight;

    fn sub(self, rhs: Weight) -> Self::Output {
        Weight(self.0 - rhs.0)
    }
}

impl AddAssign for Weight {
    fn add_assign(&mut self, rhs: Weight) {
        self.0 += rhs.0
    }
}

impl SubAssign for Weight {
    fn sub_assign(&mut self, rhs: Weight) {
        self.0 -= rhs.0
    }
}

impl Mul<usize> for Weight {
    type Output = Weight;

    fn mul(self, rhs: usize) -> Self::Output {
        Weight(self.0 * rhs)
    }
}

pub(crate) trait ComputeWeight {
    fn weight(&self) -> Weight;
}
pub(crate) trait ComputeSize {
    fn encoded_size(&self) -> usize;
}
