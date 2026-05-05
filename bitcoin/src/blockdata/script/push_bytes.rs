// SPDX-License-Identifier: CC0-1.0

//! Contains `PushBytes` & co

use core::fmt;

use crate::script;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::script::{PushBytes, PushBytesBuf, PushBytesErrorReport};

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`PushBytes`] type.
    pub trait PushBytesExt impl for PushBytes {
        /// Decodes an integer in script(minimal CScriptNum) format.
        ///
        /// This code is based on the
        /// [`CScriptNum` constructor in Bitcoin Core](https://github.com/bitcoin/bitcoin/blob/99a4ddf5ab1b3e514d08b90ad8565827fda7b63b/src/script/script.h#L245)
        ///
        /// # Errors
        ///
        /// * [`ScriptIntError::NumericOverflow`] if result is not in range [-2^39 +1...2^39 -1].
        /// * [`ScriptIntError::NonMinimal`] if encoding is non-minimal.
        fn read_scriptint(&self) -> Result<i32, ScriptIntError> {
            // Cast is safe, since the function already checks for byte length > 4
            let ret = read_scriptint_internal(self, 4)?;
            Ok(i32::try_from(ret).expect("4 bytes or less fits in an i32"))
        }

        /// Decodes an integer in script(minimal CScriptNum) format.
        ///
        /// This is suitable to read input values for CHECKLOCKTIMEVERIFY instructions.
        ///
        /// Notice that this fails on overflow: the result is the same as in bitcoind, that only 4-byte
        /// signed-magnitude values may be read as numbers. They can be added or subtracted (and a long
        /// time ago, multiplied and divided), and this may result in numbers which can't be written out
        /// in 4 bytes or less. This is ok! The number just can't be read as a number again. This is a
        /// bit crazy and subtle, but it makes sense: you can load 32-bit numbers and do anything with
        /// them, which back when mult/div was allowed, could result in up to a 64-bit number. We don't
        /// want overflow since that's surprising --- and we don't want numbers that don't fit in 64
        /// bits (for efficiency on modern processors). This function will return any value up to 40
        /// bits in length. This is basically a ranged type implementation.
        ///
        /// This code is based on the
        /// [`CScriptNum` constructor in Bitcoin Core](https://github.com/bitcoin/bitcoin/blob/99a4ddf5ab1b3e514d08b90ad8565827fda7b63b/src/script/script.h#L245)
        ///
        /// # Errors
        ///
        /// * [`ScriptIntError::NumericOverflow`] if result is not in range [-2^39 +1...2^39 -1].
        /// * [`ScriptIntError::NonMinimal`] if encoding is non-minimal.
        fn read_cltv_scriptint(&self) -> Result<i64, ScriptIntError> {
            read_scriptint_internal(self, 5)
        }
    }
}

/// The internal implementation for reading a script integer.
///
/// As with `read_cltv_scriptint`, this returns an i64, since that is the maximum size we might
/// need to return data. In practice, if the max_size parameter is 4 or less, this function
/// will always return a value that can fit into an i32, and can thus be safely cast.
fn read_scriptint_internal(bytes: &PushBytes, max_size: usize) -> Result<i64, ScriptIntError> {
    let last = match bytes.as_bytes().last() {
        Some(last) => last,
        None => return Ok(0),
    };
    if bytes.len() > max_size {
        return Err(ScriptIntError::NumericOverflow);
    }
    // Comment and code copied from Bitcoin Core:
    // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if (*last & 0x7f) == 0 {
        // One exception: if there's more than one byte and the most
        // significant bit of the second-most-significant-byte is set
        // it would conflict with the sign bit. An example of this case
        // is +-255, which encode to 0xff00 and 0xff80 respectively.
        // (big-endian).
        if bytes.len() <= 1 || (bytes[bytes.len() - 2] & 0x80) == 0 {
            return Err(ScriptIntError::NonMinimal);
        }
    }

    Ok(script::scriptint_parse(bytes.as_bytes()))
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::PushBytes {}
}

/// Possible errors that can arise from [`PushBytes::read_scriptint`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScriptIntError {
    /// The result is not in range [-2^31 +1...2^31 -1].
    NumericOverflow,
    /// The resulting encoding is non-minimal.
    NonMinimal,
}

#[cfg(feature = "std")]
impl std::error::Error for ScriptIntError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NumericOverflow => None,
            Self::NonMinimal => None,
        }
    }
}

impl fmt::Display for ScriptIntError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::NumericOverflow => f.write_str("script integer outside of valid range"),
            Self::NonMinimal => f.write_str("non-minimal encoded script integer"),
        }
    }
}
