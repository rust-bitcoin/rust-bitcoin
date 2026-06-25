// SPDX-License-Identifier: CC0-1.0

use super::{opcode_to_verify, Error};
use crate::key::{LegacyPublicKey, XOnlyPublicKey};
use crate::locktime::absolute;
use crate::opcodes::all::*;
use crate::prelude::Vec;
use crate::script::{ScriptBufExt as _, ScriptBufExtPriv as _, ScriptExtPriv as _};
use crate::{relative, Sequence};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::script::Builder;

mod sealed {
    pub trait Sealed {}
    impl<T> Sealed for super::Builder<T> {}
}

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Builder`] type.
    pub trait BuilderExt<T> impl<T> for Builder<T> {
        /// Constructs a new empty script builder with at least the specified capacity.
        #[inline]
        fn with_capacity(capacity: usize) -> Self { Self::from(Vec::with_capacity(capacity)) }

        /// Returns the length in bytes of the script.
        fn len(&self) -> usize { self.as_script().len() }

        /// Checks whether the script is the empty script.
        fn is_empty(&self) -> bool { self.as_script().is_empty() }

        /// Adds instructions to push an integer onto the stack.
        ///
        /// Integers are encoded as little-endian signed-magnitude numbers, but there are dedicated
        /// opcodes to push some small integers.
        ///
        /// # Errors
        ///
        /// Only errors if `data == i32::MIN` (CScriptNum cannot have value -2^31).
        fn push_int(self, n: i32) -> Result<Builder<T>, Error> {
            let mut script = self.into_script();
            script.push_int(n)?;
            Ok(Self::from(script.into_bytes()))
        }

        /// Adds instructions to push an unchecked integer onto the stack.
        ///
        /// Integers are encoded as little-endian signed-magnitude numbers, but there are dedicated
        /// opcodes to push some small integers.
        ///
        /// This function implements `CScript::push_int64` from Core `script.h`.
        ///
        /// > Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
        /// > The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
        /// > but results may overflow (and are valid as long as they are not used in a subsequent
        /// > numeric operation). CScriptNum enforces those semantics by storing results as
        /// > an int64 and allowing out-of-range values to be returned as a vector of bytes but
        /// > throwing an exception if arithmetic is done or the result is interpreted as an integer.
        ///
        /// Does not check whether `n` is in the range of [-2^31 +1...2^31 -1].
        fn push_int_unchecked(self, n: i64) -> Self {
            let mut script = self.into_script();
            script.push_int_unchecked(n);
            Self::from(script.into_bytes())
        }

        /// Adds an `OP_VERIFY` to the script or replaces the last opcode with VERIFY form.
        ///
        /// Some opcodes such as `OP_CHECKSIG` have a verify variant that works as if `VERIFY` was
        /// in the script right after. To save space this function appends `VERIFY` only if
        /// the most-recently-added opcode *does not* have an alternate `VERIFY` form. If it does
        /// the last opcode is replaced. E.g., `OP_CHECKSIG` will become `OP_CHECKSIGVERIFY`.
        ///
        /// Note that existing `OP_*VERIFY` opcodes do not lead to the instruction being ignored
        /// because `OP_VERIFY` consumes an item from the stack so ignoring them would change the
        /// semantics.
        fn push_verify(self) -> Self {
            // "duplicated code" because we need to update `1` field
            match opcode_to_verify(self.as_script().last_opcode()) {
                Some(opcode) => {
                    let mut script = self.into_script();
                    script.as_byte_vec().pop();
                    let result= Self::from(script.into_bytes());
                    result.push_opcode(opcode)
                }
                None => self.push_opcode(OP_VERIFY),
            }
        }

        /// Adds instructions to push a public key onto the stack.
        fn push_key(self, key: LegacyPublicKey) -> Self {
            if key.compressed() {
                self.push_slice(key.serialize_compressed())
            } else {
                self.push_slice(key.serialize_uncompressed())
            }
        }

        /// Adds instructions to push an XOnly public key onto the stack.
        fn push_x_only_key(self, x_only_key: XOnlyPublicKey) -> Self {
            self.push_slice(x_only_key.serialize().0)
        }

        /// Adds instructions to push an absolute lock time onto the stack.
        fn push_lock_time(self, lock_time: absolute::LockTime) -> Self {
            self.push_int_unchecked(lock_time.to_consensus_u32().into())
        }

        /// Adds instructions to push a relative lock time onto the stack.
        ///
        /// This is used when creating scripts that use CHECKSEQUENCEVERIFY (CSV) to enforce
        /// relative time locks.
        fn push_relative_lock_time(self, lock_time: relative::LockTime) -> Self {
            self.push_int_unchecked(lock_time.to_consensus_u32().into())
        }

        /// Adds instructions to push a sequence number onto the stack.
        ///
        /// # Deprecated
        /// This method is deprecated in favor of `push_relative_lock_time`.
        ///
        /// In Bitcoin script semantics, when using CHECKSEQUENCEVERIFY, you typically
        /// want to push a relative locktime value to be compared against the input's
        /// sequence number, not the sequence number itself.
        #[deprecated(
            since = "TBD",
            note = "Use push_relative_lock_time instead for working with timelocks in scripts"
        )]
        fn push_sequence(self, sequence: Sequence) -> Self {
            self.push_int_unchecked(sequence.to_consensus_u32().into())
        }

        /// Converts the `Builder` into script bytes
        fn into_bytes(self) -> Vec<u8> { self.into_script().into() }

        /// Returns script bytes
        fn as_bytes(&self) -> &[u8] { self.as_script().as_bytes() }
    }
}

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for [`Builder`] that should be private.
    pub(in crate::blockdata) trait BuilderExtPriv<T> impl<T> for Builder<T> {
        /// Adds instructions to push an integer onto the stack without optimization.
        ///
        /// This uses the explicit encoding regardless of the availability of dedicated opcodes.
        fn push_int_non_minimal(self, data: i64) -> Self {
            let mut script = self.into_script();
            script.push_int_non_minimal(data);
            Self::from(script.into_bytes())
        }
    }
}
