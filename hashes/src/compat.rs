// SPDX-License-Identifier: CC0-1.0

//! Comparability layer
//!
//! For converting pre-1.0 types into their 1.0 (stable) equivalent.
//!
//! ## Naming convention
//!
//! We are aiming for an ergonomic API that is in line with the Rust API naming conventions. Since
//! some types here are `Copy` and some are not we have two choices:
//!
//! 1. Use `into_foo()` for non-`Copy` type coupled with `to_foo()` for `Copy` types.
//! 2. Use `to_foo()` for both with `Copy` types consuming `self` and non-`Copy` types taking borrowing `self`.
//!
//! We elected to do (2).
//!
//! ref: https://rust-lang.github.io/api-guidelines/naming.html#ad-hoc-conversions-follow-as_-to_-into_-conventions-c-conv

// Where possible we use getters and setters instead of accessing private fields.

use bitcoin_hashes_stable as stable;

mod hash160 {
    use super::stable;
    use crate::hash160::Hash;
    use crate::Hash as _;

    impl Hash {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable(self) -> stable::hash160::Hash {
            stable::hash160::Hash::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable(stable: stable::hash160::Hash) -> Self {
            Self::from_byte_array(stable.to_byte_array())
        }
    }
}

mod hmac {
    use super::stable;
    use crate::{Hmac, Hash as _};

    // (Tobin) I'm not exactly sure why we need this. Something to do with the trait bound I'd say.
    use stable::Hash as _;

    impl<T: crate::Hash> Hmac<T> {
        /// Converts pre-1.0 type to a stable type.
        ///
        /// The type parameter `S` is the stable inner hash type and must have the same byte
        /// representation as `T` (i.e. `S::Bytes = T::Bytes`).
        pub fn to_stable<S>(self) -> stable::Hmac<S>
        where
            S: stable::Hash<Bytes = T::Bytes>,
        {
            stable::Hmac::<S>::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        ///
        /// The type parameter `S` is the stable inner hash type and must have the same byte
        /// representation as `T` (i.e. `S::Bytes = T::Bytes`).
        pub fn from_stable<S>(stable_hmac: stable::Hmac<S>) -> Self
        where
            S: stable::Hash<Bytes = T::Bytes>,
        {
            Self::from_byte_array(stable_hmac.to_byte_array())
        }
    }
}

mod ripemd160 {
    use super::stable;
    use crate::ripemd160::Hash;
    use crate::Hash as _;

    impl Hash {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable(self) -> stable::ripemd160::Hash {
            stable::ripemd160::Hash::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable(stable: stable::ripemd160::Hash) -> Self {
            Self::from_byte_array(stable.to_byte_array())
        }
    }
}

mod sha1 {
    use super::stable;
    use crate::sha1::Hash;
    use crate::Hash as _;

    impl Hash {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable(self) -> stable::sha1::Hash {
            stable::sha1::Hash::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable(stable: stable::sha1::Hash) -> Self {
            Self::from_byte_array(stable.to_byte_array())
        }
    }
}

mod sha256 {
    use super::stable;
    use crate::sha256::{Hash, HashEngine, Midstate};
    use crate::Hash as _;

    impl Hash {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable(self) -> stable::sha256::Hash {
            stable::sha256::Hash::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable(stable: stable::sha256::Hash) -> Self {
            Self::from_byte_array(stable.to_byte_array())
        }
    }

    impl Midstate {
        /// Converts pre-1.0 type to a stable type.
        ///
        /// The stable [`sha256::Midstate`] includes the number of bytes hashed alongside the
        /// midstate bytes but the pre-1.0 type does not — callers must supply this value.
        pub fn to_stable(self, bytes_hashed: u64) -> stable::sha256::Midstate {
            stable::sha256::Midstate::new(self.to_byte_array(), bytes_hashed)
        }

        /// Converts a stable type to a pre-1.0 type.
        ///
        /// Note: the number of bytes hashed is discarded during this conversion.
        pub fn from_stable(stable: stable::sha256::Midstate) -> Self {
            let (bytes, _) = stable.to_parts();
            Self::from_byte_array(bytes)
        }
    }

    impl HashEngine {
        /// Converts pre-1.0 type to a stable type.
        ///
        /// Only engines where the number of bytes hashed so far is a multiple of the block size
        /// (64) can be converted, because the pre-1.0 midstate does not carry the partial block
        /// buffer. This matches the constraint already imposed by the pre-1.0
        /// [`HashEngine::from_midstate`].
        ///
        /// # Panics
        ///
        /// Panics if `self.n_bytes_hashed() % 64 != 0`.
        pub fn to_stable(self) -> stable::sha256::HashEngine {
            use crate::HashEngine as _;

            let n = self.n_bytes_hashed();
            assert!(n % 64 == 0, "cannot convert sha256::HashEngine: {n} bytes hashed is not a multiple of 64");
            let stable_midstate = self.midstate().to_stable(n as u64);
            stable::sha256::HashEngine::from_midstate(stable_midstate)
        }

        /// Converts a stable type to a pre-1.0 type.
        ///
        /// Only engines where the number of bytes hashed so far is a multiple of the block size
        /// (64) can be converted.
        ///
        /// # Panics
        ///
        /// Panics if the stable engine's bytes hashed is not a multiple of 64.
        pub fn from_stable(stable_engine: stable::sha256::HashEngine) -> Self {
            let stable_midstate = stable_engine
                .midstate()
                .expect("cannot convert sha256::HashEngine: bytes hashed is not a multiple of 64");
            let (bytes, bytes_hashed) = stable_midstate.to_parts();
            let midstate = Midstate::from_byte_array(bytes);
            Self::from_midstate(midstate, bytes_hashed as usize)
        }
    }
}

mod sha256d {
    use super::stable;
    use crate::sha256d::Hash;
    use crate::Hash as _;

    impl Hash {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable(self) -> stable::sha256d::Hash {
            stable::sha256d::Hash::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable(stable: stable::sha256d::Hash) -> Self {
            Self::from_byte_array(stable.to_byte_array())
        }
    }
}

mod sha256t {
    use super::stable;
    use crate::sha256t::{Hash, Tag};
    use crate::Hash as _;

    impl<T: Tag> Hash<T> {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable<S>(self) -> stable::sha256t::Hash<S>
        where
            S: stable::sha256t::Tag,
        {
            stable::sha256t::Hash::<S>::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable<S>(stable: stable::sha256t::Hash<S>) -> Self
        where
            S: stable::sha256t::Tag,
        {
            Self::from_byte_array(stable.to_byte_array())
        }
    }
}

mod sha384 {
    use super::stable;
    use crate::sha384::Hash;
    use crate::Hash as _;

    impl Hash {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable(self) -> stable::sha384::Hash {
            stable::sha384::Hash::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable(stable: stable::sha384::Hash) -> Self {
            Self::from_byte_array(stable.to_byte_array())
        }
    }
}

mod sha512 {
    use super::stable;
    use crate::sha512::Hash;
    use crate::Hash as _;

    impl Hash {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable(self) -> stable::sha512::Hash {
            stable::sha512::Hash::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable(stable: stable::sha512::Hash) -> Self {
            Self::from_byte_array(stable.to_byte_array())
        }
    }
}

mod sha512_256 {
    use super::stable;
    use crate::sha512_256::Hash;
    use crate::Hash as _;

    impl Hash {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable(self) -> stable::sha512_256::Hash {
            stable::sha512_256::Hash::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable(stable: stable::sha512_256::Hash) -> Self {
            Self::from_byte_array(stable.to_byte_array())
        }
    }
}

mod siphash24 {
    use super::stable;
    use crate::siphash24::Hash;
    use crate::Hash as _;

    impl Hash {
        /// Converts pre-1.0 type to a stable type.
        pub fn to_stable(self) -> stable::siphash24::Hash {
            stable::siphash24::Hash::from_byte_array(self.to_byte_array())
        }

        /// Converts a stable type to a pre-1.0 type.
        pub fn from_stable(stable: stable::siphash24::Hash) -> Self {
            Self::from_byte_array(stable.to_byte_array())
        }
    }
}
