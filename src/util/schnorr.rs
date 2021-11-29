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

/// Untweaked Schnorr public key
pub type UntweakedPublicKey = PublicKey;

/// Tweaked Schnorr public key
pub struct TweakedPublicKey(PublicKey);

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
    fn tap_tweak<C: Verification>(self, secp: &Secp256k1<C>, merkle_root: Option<TapBranchHash>) -> TweakedPublicKey;

    /// Directly convert an UntweakedPublicKey to a TweakedPublicKey
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> TweakedPublicKey;
}

impl TapTweak for UntweakedPublicKey {
    fn tap_tweak<C: Verification>(self, secp: &Secp256k1<C>, merkle_root: Option<TapBranchHash>) -> TweakedPublicKey {
        // Compute the tweak
        let tweak_value = TapTweakHash::from_key_and_tweak(self, merkle_root).into_inner();

        //Tweak the internal key by the tweak value
        let mut output_key = self.clone();
        let parity = output_key.tweak_add_assign(&secp, &tweak_value).expect("Tap tweak failed");
        if self.tweak_add_check(&secp, &output_key, parity, tweak_value) {
            return TweakedPublicKey(output_key);
        } else { unreachable!("Tap tweak failed") }
    }

    fn dangerous_assume_tweaked(self) -> TweakedPublicKey {
        TweakedPublicKey(self)
    }
}


impl TweakedPublicKey {
    /// Create a new [TweakedPublicKey] from a [PublicKey]. No tweak is applied.
    pub fn new(key: PublicKey) -> TweakedPublicKey {
        TweakedPublicKey(key)
    }

    /// Returns the underlying public key
    pub fn into_inner(self) -> PublicKey {
        self.0
    }

    /// Returns a reference to underlying public key
    pub fn as_inner(&self) -> &PublicKey {
        &self.0
    }

}
