//! # Partially Signed Transactions
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
//! except we define PSBTs containing non-standard SigHash types as invalid.

mod error;
pub use self::error::Error;
