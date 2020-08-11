// Rust Bitcoin Library
// Written in 2020 by
//   The Rust Bitcoin developers
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

//! Implementation of PSBT responsibilities according to BIP-174

use std::marker::PhantomData;
use std::error::Error;
use std::fmt::{Formatter, Display};
use secp256k1::{Message, Signature};
use util::bip32::{Fingerprint, DerivationPath};
use super::PartiallySignedTransaction;

/// Trait for a generic PSBT responsibility (decorator+facade)
pub trait Responsibility where Self: Sized {
    /// Constructs responsibility decorator/facade from a given PSBT
    fn from_psbt(psbt: PartiallySignedTransaction) -> Self;

    /// Converts decorator/facade into the raw PSBT object
    fn into_psbt(self) -> PartiallySignedTransaction;

    /// Returns PSBT representation behind the decorator/facade
    fn as_psbt(&self) -> &PartiallySignedTransaction;
}

macro_rules! impl_responsibility {
    ($ident:ident) => {
        impl Responsibility for $ident {
            fn from_psbt(psbt: PartiallySignedTransaction) -> Self {
                Self { psbt }
            }

            fn into_psbt(self) -> PartiallySignedTransaction {
                self.psbt
            }

            fn as_psbt(&self) -> &PartiallySignedTransaction {
                &self.psbt
            }
        }
    };
}

/// PSBT signing verification error
#[derive(Debug)]
pub enum VerificationError {
}
impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}
impl Error for VerificationError {}

/// PSBT signing error
#[derive(Debug)]
pub enum SigningError {
    /// Can't sign because PSBT structure is invalid
    VerificationError(VerificationError)
}
impl Display for SigningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::VerificationError(err) => err.fmt(f)
        }
    }
}
impl Error for SigningError {}


impl From<VerificationError> for SigningError {
    fn from(err: VerificationError) -> Self {
        SigningError::VerificationError(err)
    }
}

/// Trait for PSBT signing responsibility
pub trait SignPsbt: Responsibility {
    /// Concrete verification error type
    type VerificationError: Error;

    /// Concrete signing error type
    type SigningError: Error + From<Self::VerificationError>;

    /// Verifies PSBT structure against BIp-174 rules
    fn verify(&self) -> Result<(), Self::VerificationError> {
        // TODO: Some default validation code
        Ok(())
    }

    /// Signs all PSBT inputs
    fn sign(self) -> Result<PartiallySignedTransaction, Self::SigningError>;
}

/// Default implementation for PSBT signing
pub struct DefaultSigner<F, E, SigningInfo = Message>
    where F: Fn(SigningInfo, Fingerprint, DerivationPath) -> Result<Option<Signature>, E>,
          E: Error
{
    psbt: PartiallySignedTransaction,
    /// External signing function
    pub sign_fn: Option<F>,
    _err: PhantomData<E>,
    _si: PhantomData<SigningInfo>,
}

impl<F, E, SigningInfo> Responsibility for DefaultSigner<F, E, SigningInfo>
    where F: Fn(SigningInfo, Fingerprint, DerivationPath) -> Result<Option<Signature>, E>,
          E: Error
{
    fn from_psbt(psbt: PartiallySignedTransaction) -> Self {
        Self { psbt, sign_fn: None, _err: Default::default(), _si: Default::default() }
    }

    fn into_psbt(self) -> PartiallySignedTransaction {
        self.psbt
    }

    fn as_psbt(&self) -> &PartiallySignedTransaction {
        &self.psbt
    }
}

impl<F, E, SigningInfo> SignPsbt for DefaultSigner<F, E, SigningInfo>
    where Self: Responsibility,
          E: Error + From<VerificationError>,
          F: Fn(SigningInfo, Fingerprint, DerivationPath) -> Result<Option<Signature>, E>
{
    type VerificationError = VerificationError;
    type SigningError = E;

    #[allow(unused_mut)]
    fn sign(mut self) -> Result<PartiallySignedTransaction, Self::SigningError> {
        // TODO: Implement
        Ok(self.into_psbt())
    }
}
