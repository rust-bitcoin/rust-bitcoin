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

//! Schnorr Bitcoin Keys
//!
//! Schnorr keys used in Bitcoin, reexporting Secp256k1 Schnorr key types
//!

pub use secp256k1::schnorrsig::{PublicKey, KeyPair};

use util::taproot::{TaprootKey, TapTweakHash, TapBranchHash};
use secp256k1::{Verification, Signing, Secp256k1};

impl TaprootKey for PublicKey {
    #[inline]
    fn self_tweak<C: Verification + Signing>(&mut self, secp: &Secp256k1<C>) {
        let hash = &TapTweakHash::from(*self);
        self.tweak_add_assign(secp, hash)
            .expect("negligible probability for taproot public key self-tweaked operation");
    }

    #[inline]
    fn script_tweak<C: Verification>(&mut self, secp: &Secp256k1<C>, merkle_root: TapBranchHash) {
        self.tweak_add_assign(secp, &merkle_root)
            .expect("negligible probability for taproot public key tapscript tweak operation");
    }
}

impl TaprootKey for KeyPair {
    #[inline]
    fn self_tweak<C: Verification + Signing>(&mut self, secp: &Secp256k1<C>) {
        let hash = TapTweakHash::with(secp, self);
        self.tweak_add_assign(secp, &hash)
            .expect("negligible probability for taproot keypair self-tweaked operation");
    }

    #[inline]
    fn script_tweak<C: Verification>(&mut self, secp: &Secp256k1<C>, merkle_root: TapBranchHash) {
        self.tweak_add_assign(secp, &merkle_root)
            .expect("negligible probability for taproot keypair tapscript tweak operation");
    }
}
