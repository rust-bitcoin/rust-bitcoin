// Rust Dash Library
// Written for Dash in 2022 by
//     The Dash Core Developers
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

//! Dash Special Transaction.
//!
//! A dash special transaction's purpose is to relay more data than just economic information.
//! They are defined in DIP2 [dip-0002](https://github.com/dashpay/dips/blob/master/dip-0002.md).
//! The list of special transactions can be found here:
//! [dip-0002-special-transactions](https://github.com/dashpay/dips/blob/master/dip-0002-special-transactions.md)
//!

use core::fmt::{Debug, Display, Formatter};
use core::convert::TryFrom;
use crate::io;
use crate::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use crate::blockdata::transaction::special_transaction::coinbase::CoinbasePayload;
use crate::blockdata::transaction::special_transaction::asset_unlock::qualified_asset_unlock::AssetUnlockPayload;
use crate::blockdata::transaction::special_transaction::provider_registration::ProviderRegistrationPayload;
use crate::blockdata::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
use crate::blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
use crate::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
use crate::blockdata::transaction::special_transaction::quorum_commitment::QuorumCommitmentPayload;
use crate::blockdata::transaction::special_transaction::TransactionPayload::{AssetLockPayloadType, AssetUnlockPayloadType, CoinbasePayloadType, ProviderRegistrationPayloadType, ProviderUpdateRegistrarPayloadType, ProviderUpdateRevocationPayloadType, ProviderUpdateServicePayloadType, QuorumCommitmentPayloadType};
use crate::blockdata::transaction::special_transaction::TransactionType::{AssetLock, Classic, Coinbase, AssetUnlock, ProviderRegistration, ProviderUpdateRegistrar, ProviderUpdateRevocation, ProviderUpdateService, QuorumCommitment};
use crate::consensus::{Decodable, Encodable, encode, encode::VarInt};
use crate::hash_types::{SpecialTransactionPayloadHash};

pub mod provider_registration;
pub mod provider_update_service;
pub mod provider_update_registrar;
pub mod provider_update_revocation;
pub mod coinbase;
pub mod quorum_commitment;
pub mod asset_lock;
pub mod asset_unlock;

/// An enum wrapper around various special transaction payloads.
/// Special transactions are defined in DIP 2.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub enum TransactionPayload {
    /// A wrapper for a Masternode Registration payload
    ProviderRegistrationPayloadType(ProviderRegistrationPayload),
    /// A wrapper for a Masternode Update Service payload
    ProviderUpdateServicePayloadType(ProviderUpdateServicePayload),
    /// A wrapper for a Masternode Update Registrar payload
    ProviderUpdateRegistrarPayloadType(ProviderUpdateRegistrarPayload),
    /// A wrapper for a Masternode Update Revocation payload
    ProviderUpdateRevocationPayloadType(ProviderUpdateRevocationPayload),
    /// A wrapper for a Coinbase payload
    CoinbasePayloadType(CoinbasePayload),
    /// A wrapper for a Quorum Commitment payload
    QuorumCommitmentPayloadType(QuorumCommitmentPayload),
    /// A wrapper for an Asset Lock payload
    AssetLockPayloadType(AssetLockPayload),
    /// A wrapper for an Asset Unlock payload
    AssetUnlockPayloadType(AssetUnlockPayload)
}

impl Encodable for TransactionPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        match self {
            ProviderRegistrationPayloadType(p) => { p.consensus_encode(w)}
            ProviderUpdateServicePayloadType(p) => { p.consensus_encode(w)}
            ProviderUpdateRegistrarPayloadType(p) => {p.consensus_encode(w)}
            ProviderUpdateRevocationPayloadType(p) => {p.consensus_encode(w)}
            CoinbasePayloadType(p) => {p.consensus_encode(w)}
            QuorumCommitmentPayloadType(p) => {p.consensus_encode(w)}
            AssetLockPayloadType(p) => {p.consensus_encode(w)}
            AssetUnlockPayloadType(p) => {p.consensus_encode(w)}
        }
    }
}

impl TransactionPayload {
    /// Gets the Transaction Type for a Special Transaction Payload
    pub fn get_type(&self) -> TransactionType {
        match self {
            ProviderRegistrationPayloadType(_) => { ProviderRegistration }
            ProviderUpdateServicePayloadType(_) => { ProviderUpdateService }
            ProviderUpdateRegistrarPayloadType(_) => { ProviderUpdateRegistrar }
            ProviderUpdateRevocationPayloadType(_) => { ProviderUpdateRevocation }
            CoinbasePayloadType(_) => { Coinbase }
            QuorumCommitmentPayloadType(_) => { QuorumCommitment }
            AssetLockPayloadType(_) => { AssetLock }
            AssetUnlockPayloadType(_) => { AssetUnlock }
        }
    }

    /// Gets the size of the special transaction payload
    pub fn len(&self) -> usize {
        // 1 byte is the size of the special transaction type
        1 + match self {
            ProviderRegistrationPayloadType(p) => { p.size()}
            ProviderUpdateServicePayloadType(p) => { p.size() }
            ProviderUpdateRegistrarPayloadType(p) => {p.size() }
            ProviderUpdateRevocationPayloadType(p) => {p.size()}
            CoinbasePayloadType(p) => {p.size()}
            QuorumCommitmentPayloadType(p) => {p.size()}
            AssetLockPayloadType(p) => {p.size()}
            AssetUnlockPayloadType(p) => {p.size()}
        }
    }

    /// Convenience method that assumes the payload to be a provider registration payload to get it
    /// easier.
    /// Errors if it is not a provider registration payload.
    pub fn to_provider_registration_payload(self) -> Result<ProviderRegistrationPayload, encode::Error> {
        if let ProviderRegistrationPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: ProviderRegistration, actual: self.get_type() })
        }
    }

    /// Convenience method that assumes the payload to be a provider update service payload to get it
    /// easier.
    /// Errors if it is not a provider update service payload.
    pub fn to_update_service_payload(self) -> Result<ProviderUpdateServicePayload, encode::Error> {
        if let ProviderUpdateServicePayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: ProviderUpdateService, actual: self.get_type() })
        }
    }

    /// Convenience method that assumes the payload to be a provider update registrar payload to get it
    /// easier.
    /// Errors if it is not a provider update registrar payload.
    pub fn to_update_registrar_payload(self) -> Result<ProviderUpdateRegistrarPayload, encode::Error> {
        if let ProviderUpdateRegistrarPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: ProviderUpdateRegistrar, actual: self.get_type() })
        }
    }

    /// Convenience method that assumes the payload to be a provider update revocation payload to get it
    /// easier.
    /// Errors if it is not a provider update revocation payload.
    pub fn to_update_revocation_payload(self) -> Result<ProviderUpdateRevocationPayload, encode::Error> {
        if let ProviderUpdateRevocationPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: ProviderUpdateRevocation, actual: self.get_type() })
        }
    }

    /// Convenience method that assumes the payload to be a coinbase payload to get it
    /// easier.
    /// Errors if it is not a coinbase payload.
    pub fn to_coinbase_payload(self) -> Result<CoinbasePayload, encode::Error> {
        if let CoinbasePayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: Coinbase, actual: self.get_type() })
        }
    }

    /// Convenience method that assumes the payload to be a quorum commitment payload to get it
    /// easier.
    /// Errors if it is not a quorum commitment payload.
    pub fn to_quorum_commitment_payload(self) -> Result<QuorumCommitmentPayload, encode::Error> {
        if let QuorumCommitmentPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: QuorumCommitment, actual: self.get_type() })
        }
    }

    /// Convenience method that assumes the payload to be an asset lock payload to get it
    /// easier.
    /// Errors if it is not an asset lock payload.
    pub fn to_asset_lock_payload(self) -> Result<AssetLockPayload, encode::Error> {
        if let AssetLockPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: AssetLock, actual: self.get_type() })
        }
    }

    /// Convenience method that assumes the payload to be a credit withdrawal payload to get it
    /// easier.
    /// Errors if it is not a credit withdrawal payload.
    pub fn to_asset_unlock_payload(self) -> Result<AssetUnlockPayload, encode::Error> {
        if let AssetUnlockPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: AssetLock, actual: self.get_type() })
        }
    }
}

/// The transaction type. Special transactions were introduced in DIP2.
/// Compared to Bitcoin the version field is split into two 16 bit integers.
/// The first part for the version and the second part for the transaction
/// type.
///
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TransactionType {
    /// A Classic transaction
    Classic = 0,
    /// A Masternode Registration Transaction
    ProviderRegistration = 1,
    /// A Masternode Update Service Transaction, used by the operator to signal changes to service
    ProviderUpdateService = 2,
    /// A Masternode Update Registrar Transaction, used by the owner to signal base changes
    ProviderUpdateRegistrar = 3,
    /// A Masternode Update Revocation Transaction, used by the operator to signal termination of service
    ProviderUpdateRevocation = 4,
    /// A Coinbase Transaction, contained as the first transaction in each block
    Coinbase = 5,
    /// A Quorum Commitment Transaction, used to save quorum information to the state
    QuorumCommitment = 6,
    /// An Asset Lock Transaction, used to transfer credits to Dash Platform, by locking them until withdrawals occur
    AssetLock = 8,
    /// An Asset Unlock Transaction, used to withdraw credits from Dash Platform, by unlocking them
    AssetUnlock = 9,
}

impl Debug for TransactionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match *self {
            Classic => write!(f, "Classic Transaction"),
            ProviderRegistration => write!(f, "Provider Registration Transaction"),
            ProviderUpdateService => write!(f, "Provider Update Service Transaction"),
            ProviderUpdateRegistrar => write!(f, "Provider Update Registrar Transaction"),
            ProviderUpdateRevocation => write!(f, "Provider Update Revocation Transaction"),
            Coinbase => write!(f, "Coinbase Transaction"),
            QuorumCommitment => write!(f, "Quorum Commitment Transaction"),
            AssetLock => write!(f, "Asset Lock Transaction"),
            AssetUnlock => write!(f, "Asset Unlock Transaction"),
        }
    }
}

impl Display for TransactionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match *self {
            Classic => write!(f, "Classic"),
            ProviderRegistration => write!(f, "Provider Registration"),
            ProviderUpdateService => write!(f, "Provider Update Service"),
            ProviderUpdateRegistrar => write!(f, "Provider Update Registrar"),
            ProviderUpdateRevocation => write!(f, "Provider Update Revocation"),
            Coinbase => write!(f, "Coinbase"),
            QuorumCommitment => write!(f, "Quorum Commitment"),
            AssetLock => write!(f, "Asset Lock"),
            AssetUnlock => write!(f, "Asset Unlock"),
        }
    }
}

impl TryFrom<u16> for TransactionType {
    type Error = encode::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Classic),
            1 => Ok(ProviderRegistration),
            2 => Ok(ProviderUpdateService),
            3 => Ok(ProviderUpdateRegistrar),
            4 => Ok(ProviderUpdateRevocation),
            5 => Ok(Coinbase),
            6 => Ok(QuorumCommitment),
            8 => Ok(AssetLock),
            9 => Ok(AssetUnlock),
            _ => Err(encode::Error::UnknownSpecialTransactionType(value))
        }
    }
}

impl Decodable for TransactionType {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let special_transaction_number = u16::consensus_decode(r)?;
        TransactionType::try_from(special_transaction_number)
    }
}

impl TransactionType {
    /// Get the transaction type from an optional payload
    /// If the payload in None then we have a Classical Transaction
    pub fn from_optional_payload(payload: &Option<TransactionPayload>) -> Self {
        match payload {
            None => { Classic}
            Some(payload) => { payload.get_type()}
        }
    }

    /// Decodes the payload based on the transaction type.
    pub fn consensus_decode<R: io::Read + ?Sized>(self, d: &mut R) -> Result<Option<TransactionPayload>, encode::Error> {
        let _len = match self {
            Classic => { VarInt(0) }
            _ => VarInt::consensus_decode(d)?
        };

        Ok(match self {
            Classic => { None }
            ProviderRegistration => { Some(ProviderRegistrationPayloadType(ProviderRegistrationPayload::consensus_decode(d)?))}
            ProviderUpdateService => { Some(ProviderUpdateServicePayloadType(ProviderUpdateServicePayload::consensus_decode(d)?))}
            ProviderUpdateRegistrar => { Some(ProviderUpdateRegistrarPayloadType(ProviderUpdateRegistrarPayload::consensus_decode(d)?))}
            ProviderUpdateRevocation => { Some(ProviderUpdateRevocationPayloadType(ProviderUpdateRevocationPayload::consensus_decode(d)?))}
            Coinbase => { Some(CoinbasePayloadType(CoinbasePayload::consensus_decode(d)?))}
            QuorumCommitment => { Some(QuorumCommitmentPayloadType(QuorumCommitmentPayload::consensus_decode(d)?))}
            AssetLock => { Some(AssetLockPayloadType(AssetLockPayload::consensus_decode(d)?))}
            AssetUnlock => { Some(AssetUnlockPayloadType(AssetUnlockPayload::consensus_decode(d)?))}
        })
    }
}

/// Data which can be encoded in a consensus-consistent way
pub trait SpecialTransactionBasePayloadEncodable {
    /// Encode the payload with a well-defined format.
    /// Returns the number of bytes written on success.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn base_payload_data_encode<W: io::Write>(&self, writer: W) -> Result<usize, io::Error>;

    /// The hash of the base payload special transaction data.
    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash;
}