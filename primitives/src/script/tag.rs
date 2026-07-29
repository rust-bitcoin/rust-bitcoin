// SPDX-License-Identifier: CC0-1.0

//! Script tags.
//!
//! Tags are used to differentiate the different kinds of scripts that appear
//! in Bitcoin transactions.

/// Sealed trait representing a type of script.
pub trait Tag: sealed::Sealed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::RedeemScriptTag {}
    impl Sealed for super::ScriptSigTag {}
    impl Sealed for super::ScriptPubKeyTag {}
    impl Sealed for super::SignetBlockScriptTag {}
    impl Sealed for super::TapScriptTag {}
    impl Sealed for super::WitnessScriptTag {}
}

/// A P2SH redeem script.
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum RedeemScriptTag {}
impl Tag for RedeemScriptTag {}

/// A script signature (scriptSig).
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum ScriptSigTag {}
impl Tag for ScriptSigTag {}

/// A script public key (scriptPubKey).
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum ScriptPubKeyTag {}
impl Tag for ScriptPubKeyTag {}

/// A signet block challenge script.
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum SignetBlockScriptTag {}
impl Tag for SignetBlockScriptTag {}

/// A Segwit v1 Taproot script.
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum TapScriptTag {}
impl Tag for TapScriptTag {}

/// A Segwit v0 witness script.
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum WitnessScriptTag {}
impl Tag for WitnessScriptTag {}
