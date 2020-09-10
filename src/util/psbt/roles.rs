// Rust Bitcoin Library
// Written by
//   Dr Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Roles for working with partially-signed bitcoin transactions
//! according to
//! [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)

use std::fmt::{self, Display, Debug, Formatter};

use secp256k1::Signature;
use blockdata::transaction::{Transaction, TxIn};
use blockdata::script::Script;
use util::key::PublicKey;
use util::bip32::{DerivationPath, Fingerprint};
use util::psbt::{PartiallySignedTransaction, Global, Input, Output, Error};

/// PSBT-related roles according to
/// [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
/// and https://github.com/bitcoin/bitcoin/blob/master/src/psbt.h#L559
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
// Tracking PR https://github.com/bitcoin/bips/pull/989
pub enum Role {
    /// Creator role
    Creator,
    /// Updater role
    Updater,
    /// Signer role
    Signer,
    /// Combiner role
    Combiner,
    /// Input finalizer role
    Finalizer,
    /// Transaction extractor role
    Extractor,
}

impl Default for Role {
    fn default() -> Self {
        Role::Creator
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        (self as &Debug).fmt(f)
    }
}

impl Role {
    /// Initialization of the default role ([Role::Creator])
    pub fn init() -> Role {
        Role::default()
    }

    /// Next role following the current one
    pub fn next(&self) -> Option<Role> {
        match self {
            Role::Creator => Some(Role::Updater),
            Role::Updater => Some(Role::Signer),
            Role::Signer => Some(Role::Combiner),
            Role::Combiner => Some(Role::Finalizer),
            Role::Finalizer => Some(Role::Extractor),
            Role::Extractor => None
        }
    }
}

impl PartiallySignedTransaction {
    // Must be kept in accordance with
    // https://github.com/bitcoin/bitcoin/blob/master/src/node/psbt.cpp#L15
    /// Previous role detected basing on the data present in the PSBT
    pub fn prev_role(&self) -> Role {
        match self {
            me if me.has_final_info() => Role::Finalizer,
            me if me.has_all_signatures() => Role::Combiner,
            me if me.has_partial_signatures() => Role::Signer,
            me if me.has_sign_info() => Role::Updater,
            _ => Role::Creator,
        }
    }

    /// Next role detected basing on the data present in the PSBT
    pub fn next_role(&self) -> Option<Role> {
        self.prev_role().next()
    }
}


/// Implementation of [Role::Creator] role according to
/// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Creator
pub trait Creator where Self: Sized {
    /// Create a PartiallySignedTransaction from an unsigned transaction, error
    /// if not unsigned.
    ///
    /// Must match implementation from
    /// https://github.com/bitcoin/bitcoin/tree/master/src/psbt.cpp#L9
    fn from_unsigned_tx(tx: Transaction) -> Result<Self, Error>;
}

impl Creator for PartiallySignedTransaction {
    fn from_unsigned_tx(tx: Transaction) -> Result<Self, self::Error> {
        Ok(PartiallySignedTransaction {
            inputs: vec![Default::default(); tx.input.len()],
            // Tracking PR https://github.com/bitcoin/bips/pull/988
            outputs: vec![Default::default(); tx.output.len()],
            global: Global::from_unsigned_tx(tx)?,
        })
    }
}

/// Implementation of [Role::Updater] role according to
/// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Updater
pub trait Updater {
    /// Detects when all necessary information for signatures are present,
    /// so the role may transit to [Signer]
    fn has_sign_info(&self) -> bool;

    /// Adds information about transaction being spent to a given input index
    /// in a non-segwit format
    fn add_input_tx(&mut self, index: u32, tx: &Transaction) -> Result<&mut Self, Error>;

    /// Adds information about transaction being spent to a given input index
    /// in a segwit-specific format
    fn add_input_utxo(&mut self, index: u32, txin: &TxIn) -> Result<&mut Self, Error>;

    /// Adds information about full input script for the given input index
    /// (P2SH-specific)
    fn add_input_script(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error>;

    /// Adds information about full input script for the given input index
    /// (P2WSH-specific)
    fn add_input_wscript(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error>;

    /// Adds information about public key derivation for a given input index
    /// (for P2PK and P2WPK outputs)
    fn add_input_derivation(&mut self, index: u32, pubkey: &PublicKey, fingerprint: Fingerprint, path: &DerivationPath) -> Result<&mut Self, Error>;

    /// Adds P2SH script source for a given output index
    fn add_output_script(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error>;

    /// Adds P2WSH script source for a given output index
    fn add_output_wscript(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error>;

    /// Adds information about public key derivation for a given output index
    /// (for P2PK and P2WPK outputs)
    fn add_output_derivation(&mut self, index: u32, pubkey: &PublicKey, fingerprint: Fingerprint, path: &DerivationPath) -> Result<&mut Self, Error>;
}

impl Updater for PartiallySignedTransaction {
    fn has_sign_info(&self) -> bool {
        unimplemented!()
    }

    fn add_input_tx(&mut self, index: u32, tx: &Transaction) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_input_utxo(&mut self, index: u32, txin: &TxIn) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_input_script(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_input_wscript(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_input_derivation(&mut self, index: u32, pubkey: &PublicKey, fingerprint: Fingerprint, path: &DerivationPath) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_output_script(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_output_wscript(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_output_derivation(&mut self, index: u32, pubkey: &PublicKey, fingerprint: Fingerprint, path: &DerivationPath) -> Result<&mut Self, Error> {
        unimplemented!()
    }
}

/// Errors which may happen during signer verification
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SignerVerificationError {
}

impl fmt::Display for SignerVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self as &fmt::Debug).fmt(f)
    }
}

/// Implementation of [Role::Signer] role according to
/// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Signer
pub trait Signer {
    /// Detects when at least some of the signatures are present
    fn has_partial_signatures(&self) -> bool;

    /// Verifies that PSBT is ready to be signed, i.e. contains all necessary
    /// information
    fn verify(&self) -> Vec<SignerVerificationError>;

    /// Adds signature for a specific input
    fn add_signature(&mut self, input: u32, signature: Signature) -> Result<&mut Self, Error>;
}

impl Signer for PartiallySignedTransaction {
    fn has_partial_signatures(&self) -> bool {
        unimplemented!()
    }

    fn verify(&self) -> Vec<SignerVerificationError> {
        unimplemented!()
    }

    fn add_signature(&mut self, input: u32, signature: Signature) -> Result<&mut Self, Error> {
        unimplemented!()
    }
}

/// Implementation of [Role::Combiner] role according to
/// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Combiner
pub trait Combiner {
    /// Detects when all of the signatures are present, signifying completion of
    /// the [Combiner] role
    fn has_all_signatures(&self) -> bool;

    /// Attempt to merge with another `PartiallySignedTransaction`.
    fn merge(&mut self, other: Self) -> Result<(), Error>;
}

impl Combiner for PartiallySignedTransaction {
    fn has_all_signatures(&self) -> bool {
        unimplemented!()
    }

    fn merge(&mut self, other: Self) -> Result<(), Error> {
        self.global.merge(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.merge(other_input)?;
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.merge(other_output)?;
        }

        Ok(())
    }
}

impl Combiner for Global {
    fn has_all_signatures(&self) -> bool {
        unimplemented!()
    }

    fn merge(&mut self, other: Self) -> Result<(), Error> {
        if self.unsigned_tx != other.unsigned_tx {
            return Err(Error::UnexpectedUnsignedTx {
                expected: self.unsigned_tx.clone(),
                actual: other.unsigned_tx,
            });
        }

        self.unknown.extend(other.unknown);
        Ok(())
    }
}

impl Combiner for Input {
    fn has_all_signatures(&self) -> bool {
        unimplemented!()
    }

    fn merge(&mut self, other: Self) -> Result<(), Error> {
        merge!(non_witness_utxo, self, other);

        if let (&None, Some(witness_utxo)) = (&self.witness_utxo, other.witness_utxo) {
            self.witness_utxo = Some(witness_utxo);
            self.non_witness_utxo = None; // Clear out any non-witness UTXO when we set a witness one
        }

        self.partial_sigs.extend(other.partial_sigs);
        self.hd_keypaths.extend(other.hd_keypaths);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);
        merge!(final_script_sig, self, other);
        merge!(final_script_witness, self, other);

        Ok(())
    }
}

impl Combiner for Output {
    fn has_all_signatures(&self) -> bool {
        unimplemented!()
    }

    fn merge(&mut self, other: Self) -> Result<(), Error> {
        self.hd_keypaths.extend(other.hd_keypaths);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);

        Ok(())
    }
}

/// Implementation of [Role::Finalizer] role according to
/// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#input-finalizer
pub trait Finalizer {
    /// Checks that PSBT contains all necessary info for the finalization
    /// (all signatures and script information is present)
    fn has_final_info(&self) -> bool;

    /// Finalizes partially-signed bitcoin transaction according to BIP 174
    /// procedure
    fn finalize(&mut self) -> Result<&mut Self, Error>;
}

impl Finalizer for PartiallySignedTransaction {
    fn has_final_info(&self) -> bool {
        unimplemented!()
    }

    fn finalize(&mut self) -> Result<&mut Self, Error> {
        unimplemented!()
    }
}

/// Implementation of [Role::Extractor] role according to
/// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#transaction-extractor
pub trait Extractor {
    /// Extract the Transaction from a PartiallySignedTransaction by filling in
    /// the available signature information in place.
    fn extract_tx(self) -> Result<Transaction, Error>;
}

impl Extractor for PartiallySignedTransaction {
    fn extract_tx(self) -> Result<Transaction, Error> {
        if !self.has_all_signatures() {
            // TODO: Return error
        }

        let mut tx: Transaction = self.global.unsigned_tx;

        for (vin, psbtin) in tx.input.iter_mut().zip(self.inputs.into_iter()) {
            vin.script_sig = psbtin.final_script_sig.unwrap_or_else(Script::new);
            vin.witness = psbtin.final_script_witness.unwrap_or_else(Vec::new);
        }

        Ok(tx)
    }
}
