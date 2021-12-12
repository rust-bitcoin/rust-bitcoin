// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Schnorr Bitcoin keys.
//!
//! This module provides Schnorr keys used in Bitcoin, reexporting Secp256k1
//! Schnorr key types.
//!

pub use secp256k1::schnorrsig::{PublicKey, KeyPair};
use secp256k1::{Secp256k1, Verification};
use hashes::Hash;
use util::taproot::{TapBranchHash, TapTweakHash};
use core::fmt;

/// Untweaked Schnorr public key
pub type UntweakedPublicKey = PublicKey;

/// Tweaked Schnorr public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TweakedPublicKey(PublicKey);

impl fmt::LowerHex for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::Display for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A trait for tweaking Schnorr public keys
pub trait TapTweak {
    /// Tweaks an untweaked public key given an untweaked key and optional script tree merkle root.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked key
    ///  * P is the internal key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(self, secp: &Secp256k1<C>, merkle_root: Option<TapBranchHash>) -> (TweakedPublicKey, bool);

    /// Directly converts an [`UntweakedPublicKey`] to a [`TweakedPublicKey`]
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> TweakedPublicKey;
}

impl TapTweak for UntweakedPublicKey {
    fn tap_tweak<C: Verification>(self, secp: &Secp256k1<C>, merkle_root: Option<TapBranchHash>) -> (TweakedPublicKey, bool) {
        let tweak_value = TapTweakHash::from_key_and_tweak(self, merkle_root).into_inner();
        let mut output_key = self.clone();
        let parity = output_key.tweak_add_assign(&secp, &tweak_value).expect("Tap tweak failed");

        debug_assert!(self.tweak_add_check(&secp, &output_key, parity, tweak_value));
        (TweakedPublicKey(output_key), parity)
    }

    fn dangerous_assume_tweaked(self) -> TweakedPublicKey {
        TweakedPublicKey(self)
    }
}


impl TweakedPublicKey {
    /// Creates a new [`TweakedPublicKey`] from a [`PublicKey`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedPublicKey`] instead of using this constructor.
    pub fn dangerous_assume_tweaked(key: PublicKey) -> TweakedPublicKey {
        TweakedPublicKey(key)
    }

    /// Returns the underlying public key.
    pub fn into_inner(self) -> PublicKey {
        self.0
    }

    /// Returns a reference to underlying public key.
    pub fn as_inner(&self) -> &PublicKey {
        &self.0
    }

}
