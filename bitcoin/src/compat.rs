// SPDX-License-Identifier: CC0-1.0

//! Compatibility layer.
//!
//! Provides compatibility between `primitives v0.100.0` and `bitcoin v0.32`.

use crate::{CompactTarget, Opcode, Sequence};

impl Sequence {
    /// Converts `other` from a `primitives` type to a `rust-bitcoin v0.32` [`Sequence`] type.
    pub fn from_compat(other: primitives::Sequence) -> Self {
        Sequence(other.to_consensus_u32())
    }

    /// Converts `self` from a `rust-bitcoin v0.32` [`Sequence`] type to a `primitives` type.
    pub fn to_compat(self) -> primitives::Sequence {
        primitives::Sequence::from_consensus(self.to_consensus_u32())
    }
}

impl Opcode {
    /// Converts `other` from a `primitives` type to a `rust-bitcoin v0.32` [`Opcode`] type.
    // TODO: Re-export `Opcode` from primitives crate root.
    pub fn from_compat(other: primitives::opcodes::Opcode) -> Self {
        Opcode::from(other.to_u8())
    }

    /// Converts `self` from a `rust-bitcoin v0.32` [`Opcode`] type to a `primitives` type.
    pub fn to_compat(self) -> primitives::opcodes::Opcode {
        primitives::opcodes::Opcode::from(self.to_u8())
    }
}

impl CompactTarget {
    /// Converts `other` from a `primitives` type to a `rust-bitcoin v0.32` [`CompactTarget`] type.
    pub fn from_compat(other: primitives::CompactTarget) -> Self {
        CompactTarget::from_consensus(other.to_consensus())
    }

    /// Converts `self` from a `rust-bitcoin v0.32` [`CompactTarget`] type to a `primitives` type.
    pub fn to_compat(self) -> primitives::CompactTarget {
        primitives::CompactTarget::from_consensus(self.to_consensus())
    }
}
