// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Cryptography

#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "hex")]
pub extern crate hex;

pub extern crate base58;

pub extern crate network;

pub extern crate secp256k1;

pub mod ecdsa;
pub mod key;
pub mod sighash;
pub mod taproot;

#[doc(inline)]
pub use self::key::{FullPublicKey, Keypair, LegacyPublicKey, PrivateKey, XOnlyPublicKey};

include!("../include/newtype.rs"); // Explained in `REPO_DIR/include/README.md`.
#[cfg(feature = "alloc")]
include!("../include/asref_push_bytes.rs");

// Encapsulation module for the `PushBytes` code to be removed before 1.0.
#[cfg(feature = "alloc")]
mod push_bytes {
    use core::borrow::Borrow;

    use primitives::script::{PushBytes, PushBytesBuf};

    use super::key::{PubkeyHash, SerializedLegacyPublicKey, WPubkeyHash};

    impl AsRef<PushBytes> for super::ecdsa::SerializedSignature {
        #[inline]
        fn as_ref(&self) -> &PushBytes {
            <&PushBytes>::try_from(<Self as AsRef<[u8]>>::as_ref(self))
                .expect("max length 73 bytes is valid")
        }
    }

    impl AsRef<PushBytes> for super::taproot::SerializedSignature {
        #[inline]
        fn as_ref(&self) -> &PushBytes {
            <&PushBytes>::try_from(<Self as AsRef<[u8]>>::as_ref(self))
                .expect("max length 65 bytes is valid")
        }
    }

    crate::impl_asref_push_bytes!(PubkeyHash, WPubkeyHash);

    impl AsRef<PushBytes> for SerializedLegacyPublicKey {
        fn as_ref(&self) -> &PushBytes { self.borrow() }
    }

    impl Borrow<PushBytes> for SerializedLegacyPublicKey {
        fn borrow(&self) -> &PushBytes { <&PushBytes>::try_from(&**self).expect("65 <= u32::MAX") }
    }
}
