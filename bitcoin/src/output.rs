// SPDX-License-Identifier: CC0-1.0

//! Bitcoin output types.
//!
//! This module serves to tie together many of this libraries other types and API's by grouping them
//! according to the output type. The output types are all just empty enums with a bunch of
//! functions that represent functionality that one would expect when creating or spending a Bitcoin
//! output.
//!
//! You will find here each of the output types currently supported by the Bitcoin network.
//!
//! - [`P2TR`]: Pay to taproot (segwit v1).
//! - [`P2WPKH`]: Pay to witness pubkey hash (native segwit v0).
//! - [`P2WSH`]: Pay to witness script hash (native segwit v0).
//! - [`P2shP2wpkh`]: Wrapped pay to witness pubkey hash (segwit v0).
//! - [`P2shP2wsh`]: Wrapped pay to witness script hash (segwit v0).
//! - [`P2pkh`]: Pay to pubkey hash (legacy).
//! - [`P2sh`]: Pay to script hash (legacy).
//! - [`P2pk`]: Pay to pubkey (legacy).

use secp256k1::{Secp256k1, Verification};

use crate::blockdata::script::{ScriptBuf, ScriptHash};
use crate::blockdata::witness::Witness;
use crate::crypto::sighash::{
    EcdsaSighashType, LegacySighash, SegwitV0Sighash, TapSighash, TapSighashType,
};
use crate::crypto::{ecdsa, taproot};
use crate::key::{PublicKey, TweakedPublicKey, UntweakedPublicKey, XOnlyPublicKey};
use crate::script;
use crate::taproot::TapNodeHash;

/// A trait describing the various Bitcoin output types.
///
/// This trait is not meant to be implemented by types outside of this crate/module. Its purpose is
/// to group together various types that exist for each Bitcoin output. Functionality is implemented
/// on the individual output types instead of as trait methods, this is because the functions are
/// conceptually similar but not similar enough to have identical function signatures.
pub trait Output {
    /// The public key type to verify signatures for this output.
    type PublicKey;
    /// The required signature to spend this output.
    type Signature;
    /// The sighash for this output.
    type Sighash;
    /// The sighash type used when creating the sighash for this output.
    type SighashType;
}

/// A P2TR output (segwit v1).
pub enum P2tr {}

impl Output for P2tr {
    type PublicKey = XOnlyPublicKey;
    type Signature = taproot::Signature;
    type Sighash = TapSighash;
    type SighashType = TapSighashType;
}

impl P2tr {
    /// Creates the script pubkey used to lock coins to a P2TR output.
    ///
    /// This output will only be spendable by way of a key spend using `internal_key`.
    ///
    /// # Examples
    ///
    /// ```
    /// // To create an output spendable by only a single key use:
    /// let script_pubkey = P2tr::script_pubkey(&secp, key, None);
    ///
    /// // To create an output spendable by ...
    // TODO: Finish these docs.
    /// ```
    pub fn script_pubkey<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> ScriptBuf {
        ScriptBuf::new_p2tr(secp, internal_key, merkle_root)
    }

    /// Creates the script pubkey used to lock coins to a P2TR output.
    ///
    /// This output will be spendable by anyone that can sign with the tweaked `output_key`.
    pub fn script_pubkey_tweaked(output_key: TweakedPublicKey) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(output_key)
    }

    /// Creates the empty script sig required to spend a P2TR output.
    pub fn script_sig() -> ScriptBuf { ScriptBuf::new() }

    /// Creates the witness used to do a key spend of a P2TR output.
    pub fn witness_key_spend(sig: taproot::Signature) -> Witness { Witness::p2tr_key_spend(&sig) }

    /// Creates the witness used to do a script path spend of a P2TR output.
    pub fn witnes_script_spend() -> Witness { todo!() }
}

/// A P2WPKH output (segwit v0).
pub enum P2wpkh {}

impl Output for P2wpkh {
    type PublicKey = secp256k1::PublicKey;
    type Signature = ecdsa::segwit_v0::Signature;
    type Sighash = SegwitV0Sighash;
    type SighashType = EcdsaSighashType;
}

impl P2wpkh {
    /// Creates the script pubkey used to lock coins to a P2WPKH output.
    pub fn script_pubkey(pubkey: secp256k1::PublicKey) -> ScriptBuf {
        let key = PublicKey::new(pubkey);
        let pubkey_hash = key.wpubkey_hash().expect("new() returns a compressed key");
        ScriptBuf::new_p2wpkh(&pubkey_hash)
    }

    /// Creates the empty script sig required to spend a P2WPKH output.
    pub fn script_sig() -> ScriptBuf { ScriptBuf::new() }

    /// Creates the witness used to spend P2WPKH output.
    pub fn witness(sig: ecdsa::segwit_v0::Signature, pk: secp256k1::PublicKey) -> Witness {
        Witness::p2wpkh(&sig, &pk)
    }
}

/// A P2WSH output (segwit v0).
pub enum P2wsh {}

impl Output for P2wsh {
    type PublicKey = secp256k1::PublicKey;
    type Signature = ecdsa::segwit_v0::Signature;
    type Sighash = SegwitV0Sighash;
    type SighashType = EcdsaSighashType;
}

impl P2wsh {
    /// Creates the script pubkey used to lock coins to a P2WSH output.
    pub fn script_pubkey(pubkey: secp256k1::PublicKey) -> ScriptBuf {
        let key = PublicKey::new(pubkey);
        let pubkey_hash = key.wpubkey_hash().expect("new() returns a compressed key");
        ScriptBuf::new_p2wpkh(&pubkey_hash)
    }

    /// Creates the empty script sig required to spend a P2WSH output.
    pub fn script_sig() -> ScriptBuf { ScriptBuf::new() }

    /// Creates the witness used to spend a P2WSH output.
    pub fn witness() -> Witness { todo!() }
}

/// A P2SH-P2WPKH output (nested segwit).
pub enum P2shP2wpkh {}

impl Output for P2shP2wpkh {
    type PublicKey = secp256k1::PublicKey;
    type Signature = ecdsa::segwit_v0::Signature;
    type Sighash = SegwitV0Sighash;
    type SighashType = EcdsaSighashType;
}

impl P2shP2wpkh {
    /// Creates the script pubkey used to lock coins to a P2SH-P2WPKH output.
    pub fn script_pubkey(pubkey: secp256k1::PublicKey) -> ScriptBuf {
        let redeem_script = Self::redeem_script(pubkey);
        let redeem_script_hash = ScriptHash::from(redeem_script);
        ScriptBuf::new_p2sh(&redeem_script_hash)
    }

    /// Creates the script sig required to spend a P2SH-P2WPKH output (the redeem script).
    pub fn script_sig(pubkey: secp256k1::PublicKey) -> ScriptBuf { Self::redeem_script(pubkey) }

    /// Creates the redeem script used to spend a P2SH-P2WPKH output.
    pub fn redeem_script(pubkey: secp256k1::PublicKey) -> ScriptBuf {
        let key = PublicKey::new(pubkey);
        let pubkey_hash = key.wpubkey_hash().expect("new() returns a compressed key");
        ScriptBuf::new_p2wpkh(&pubkey_hash)
    }

    /// Creates the witness used to spend P2SH-P2WSH output.
    pub fn witness() -> Witness { todo!() }
}

/// A P2SH-P2WSH output (nested segwit).
pub enum P2shP2wsh {}

impl Output for P2shP2wsh {
    type PublicKey = PublicKey;
    type Signature = ecdsa::segwit_v0::Signature;
    type Sighash = SegwitV0Sighash;
    type SighashType = EcdsaSighashType;
}

impl P2shP2wsh {
    /// Creates the script pubkey used to lock coins to a P2SH-P2WSH output.
    // TODO: Should this take a &Script instead?
    pub fn script_pubkey(redeem_script_hash: ScriptHash) -> ScriptBuf {
        ScriptBuf::new_p2sh(&redeem_script_hash)
    }

    /// Creates the script sig required to spend a P2SH-P2WSH output (the redeem script).
    pub fn script_sig(script_hash: ScriptHash) -> ScriptBuf { Self::redeem_script(script_hash) }

    /// Creates the redeem script used to spend a P2SH-P2WSH output.
    pub fn redeem_script(_script_hash: ScriptHash) -> ScriptBuf { todo!() }

    /// Creates the witness used to spend P2SH-P2WSH output.
    pub fn witness() -> Witness { todo!() }
}

/// A P2PKH output (legacy).
pub enum P2pkh {}

impl Output for P2pkh {
    type PublicKey = PublicKey;
    type Signature = ecdsa::legacy::Signature;
    type Sighash = LegacySighash;
    type SighashType = EcdsaSighashType;
}

impl P2pkh {
    /// Creates the script pubkey used to lock coins to a P2PKH output.
    pub fn script_pubkey(pubkey: PublicKey) -> ScriptBuf {
        let pubkey_hash = pubkey.pubkey_hash();
        ScriptBuf::new_p2pkh(&pubkey_hash)
    }

    /// Creates the script sig required to spend a P2PKH output.
    pub fn script_sig(sig: ecdsa::legacy::Signature, pubkey: PublicKey) -> ScriptBuf {
        script::Builder::new().push_slice(sig.serialize()).push_key(&pubkey).into_script()
    }
}

/// A P2SH output (legacy).
///
/// This is the original legacy P2output only, does not include nested segwit outputs.
pub struct P2sh;

impl Output for P2sh {
    type PublicKey = PublicKey;
    type Signature = ecdsa::legacy::Signature;
    type Sighash = LegacySighash;
    type SighashType = EcdsaSighashType;
}

impl P2sh {
    /// Creates the script pubkey used to lock coins to a P2SH output.
    // TODO: Should this take a &Script instead?
    pub fn script_pubkey(script_hash: ScriptHash) -> ScriptBuf { ScriptBuf::new_p2sh(&script_hash) }

    /// Creates the script sig required to spend a P2SH output.
    pub fn script_sig(_sig: ecdsa::legacy::Signature) -> ScriptBuf { todo!() }
}

/// A P2PK output (legacy).
pub struct P2pk;

impl Output for P2pk {
    type PublicKey = PublicKey;
    type Signature = ecdsa::legacy::Signature;
    type Sighash = LegacySighash;
    type SighashType = EcdsaSighashType;
}

impl P2pk {
    /// Creates the script pubkey used to lock coins to a P2PK output.
    pub fn script_pubkey(pubkey: PublicKey) -> ScriptBuf { ScriptBuf::new_p2pk(&pubkey) }

    /// Creates the script sig required to spend a P2PK output.
    pub fn script_sig(sig: ecdsa::legacy::Signature) -> ScriptBuf {
        script::Builder::new().push_slice(sig.serialize()).into_script()
    }
}
