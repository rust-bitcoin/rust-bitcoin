// SPDX-License-Identifier: CC0-1.0

//! Script tags.
//!
//! Tags are used to differentiate the different kinds of scripts that appear
//! in Bitcoin transactions.

/// Sealed trait representing a type of script.
pub trait Tag {}

/// Placeholder tag.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum Whatever {}

impl Tag for Whatever {}

/// A P2SH redeem script.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum RedeemScriptTag {}
impl Tag for RedeemScriptTag {}

/// A script signature (scriptSig).
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum ScriptSigTag {}
impl Tag for ScriptSigTag {}

/// A script public key (scriptPubKey).
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum ScriptPubKeyTag {}
impl Tag for ScriptPubKeyTag {}
