// SPDX-License-Identifier: CC0-1.0

//! # Bitcoin Addresses
//!
//! Bitcoin addresses do not appear on chain; rather, they are conventions used by Bitcoin (wallet)
//! software to communicate where coins should be sent and are based on the output type e.g., P2WPKH.
//!
//! # Examples
//!
//! ### Creating a new address from a randomly-generated key pair.
//!
//! ```rust
//! #[cfg(feature = "rand")]
//! #[cfg(feature = "std")]
//! {
//! use bitcoin_crypto::secp256k1::rand;
//! use bitcoin_crypto::key::LegacyPublicKey;
//! use network::Network;
//! use bitcoin_addresses::Address;
//!
//! // Generate random key pair.
//! let (_sk, pk) = secp256k1::generate_keypair(&mut rand::rng());
//! let public_key = LegacyPublicKey::from_secp(pk); // Or `LegacyPublicKey::from(pk)`.
//!
//! // Generate a mainnet pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Bitcoin);
//! }
//! ```
//!
//! ### Using an `Address` as a struct field.
//!
//! ```rust
//! # #[cfg(feature = "serde")]
//! # #[cfg(feature = "alloc")]
//! # {
//! # use serde::{self, Deserialize, Serialize};
//! use bitcoin_addresses::{Address, NetworkValidation, NetworkValidationUnchecked};
//! #[derive(Serialize, Deserialize)]
//! struct Foo<V>
//!     where V: NetworkValidation,
//! {
//!     #[serde(bound(deserialize = "V: NetworkValidationUnchecked"))]
//!     address: Address<V>,
//! }
//! # }
//! ```
//!
//! ref: <https://sprovoost.nl/2022/11/10/what-is-a-bitcoin-address/>

#![no_std]
#![cfg(feature = "alloc")]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod witness_program;
pub mod witness_version;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bech32::{Fe32, Hrp};
use crypto::key::{FullPublicKey, LegacyPublicKey, PubkeyHash, TweakedPublicKey, XOnlyPublicKey};
use hashes::{hash160, HashEngine};
use internals::array::ArrayExt as _;
use network::{Network, NetworkKind};
use primitives::script::{
    RedeemScriptSizeError, Script, ScriptHash, ScriptHashableTag, WScriptHash, WitnessScript,
    WitnessScriptSizeError,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use witness_program::WitnessProgram;
use witness_version::WitnessVersion;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{
        Base58Error, Bech32Error, FromScriptError, InvalidBase58PayloadLengthError,
        InvalidLegacyPrefixError, LegacyAddressTooLongError, NetworkValidationError,
        ParseError, UnknownAddressTypeError, UnknownHrpError, ParseBech32Error,
};

/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 0; // 0x00
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5; // 0x05
/// Test (testnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (testnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
    /// Pay to witness pubkey hash.
    P2wpkh,
    /// Pay to witness script hash.
    P2wsh,
    /// Pay to Taproot.
    P2tr,
    /// Pay to anchor.
    P2a,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Self::P2pkh => "p2pkh",
            Self::P2sh => "p2sh",
            Self::P2wpkh => "p2wpkh",
            Self::P2wsh => "p2wsh",
            Self::P2tr => "p2tr",
            Self::P2a => "p2a",
        })
    }
}

impl FromStr for AddressType {
    type Err = UnknownAddressTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(Self::P2pkh),
            "p2sh" => Ok(Self::P2sh),
            "p2wpkh" => Ok(Self::P2wpkh),
            "p2wsh" => Ok(Self::P2wsh),
            "p2tr" => Ok(Self::P2tr),
            "p2a" => Ok(Self::P2a),
            _ => Err(UnknownAddressTypeError(s.to_owned())),
        }
    }
}

mod sealed {
    pub trait NetworkValidation {}
    impl NetworkValidation for super::NetworkChecked {}
    impl NetworkValidation for super::NetworkUnchecked {}

    pub trait NetworkValidationUnchecked {}
    impl NetworkValidationUnchecked for super::NetworkUnchecked {}
}

/// Marker of status of address's network validation. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
pub trait NetworkValidation:
    sealed::NetworkValidation + Sync + Send + Sized + Unpin + Copy
{
    /// Indicates whether this `NetworkValidation` is `NetworkChecked` or not.
    const IS_CHECKED: bool;
}

/// Marker trait for `FromStr` and `serde::Deserialize`.
///
/// This allows users to use `V: NetworkValidation` in conjunction with derives. Is only ever
/// implemented for `NetworkUnchecked`.
pub trait NetworkValidationUnchecked:
    NetworkValidation + sealed::NetworkValidationUnchecked + Sync + Send + Sized + Unpin
{
}

/// Marker that address's network has been successfully validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkChecked {}

/// Marker that address's network has not yet been validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkUnchecked {}

impl NetworkValidation for NetworkChecked {
    const IS_CHECKED: bool = true;
}
impl NetworkValidation for NetworkUnchecked {
    const IS_CHECKED: bool = false;
}

impl NetworkValidationUnchecked for NetworkUnchecked {}

/// The inner representation of an address, without the network validation tag.
///
/// This struct represents the inner representation of an address without the network validation
/// tag, which is used to ensure that addresses are used only on the appropriate network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AddressInner {
    P2pkh { hash: PubkeyHash, network: NetworkKind },
    P2sh { hash: ScriptHash, network: NetworkKind },
    Segwit { program: WitnessProgram, hrp: KnownHrp },
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for AddressInner {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use AddressInner::*;
        match self {
            P2pkh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    NetworkKind::Main => PUBKEY_ADDRESS_PREFIX_MAIN,
                    NetworkKind::Test => PUBKEY_ADDRESS_PREFIX_TEST,
                };
                prefixed[1..].copy_from_slice(hash.as_byte_array());
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            P2sh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    NetworkKind::Main => SCRIPT_ADDRESS_PREFIX_MAIN,
                    NetworkKind::Test => SCRIPT_ADDRESS_PREFIX_TEST,
                };
                prefixed[1..].copy_from_slice(hash.as_byte_array());
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Segwit { program, hrp } => {
                let hrp = hrp.to_hrp();
                let version = Fe32::try_from(program.version().to_num())
                    .expect("version nums 0-16 are valid fe32 values");
                let program = program.as_program_slice();

                if fmt.alternate() {
                    bech32::segwit::encode_upper_to_fmt_unchecked(fmt, hrp, version, program)
                } else {
                    bech32::segwit::encode_lower_to_fmt_unchecked(fmt, hrp, version, program)
                }
            }
        }
    }
}

/// Known bech32 human-readable parts.
///
/// This is the human-readable part before the separator (`1`) in a bech32 encoded address e.g.,
/// the "bc" in "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5".
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum KnownHrp {
    /// The main Bitcoin network.
    Mainnet,
    /// The test networks, testnet (testnet3), testnet4, and signet.
    Testnets,
    /// The regtest network.
    Regtest,
}

impl KnownHrp {
    /// Constructs a new [`KnownHrp`] from [`Network`].
    fn from_network(network: Network) -> Self {
        use Network::*;

        match network {
            Bitcoin => Self::Mainnet,
            Testnet(_) | Signet => Self::Testnets,
            Regtest => Self::Regtest,
        }
    }

    /// Constructs a new [`KnownHrp`] from a [`bech32::Hrp`].
    fn from_hrp(hrp: Hrp) -> Result<Self, UnknownHrpError> {
        if hrp == bech32::hrp::BC {
            Ok(Self::Mainnet)
        } else if hrp.is_valid_on_testnet() || hrp.is_valid_on_signet() {
            Ok(Self::Testnets)
        } else if hrp == bech32::hrp::BCRT {
            Ok(Self::Regtest)
        } else {
            Err(UnknownHrpError(hrp.to_lowercase()))
        }
    }

    /// Converts, infallibly a known HRP to a [`bech32::Hrp`].
    fn to_hrp(self) -> Hrp {
        match self {
            Self::Mainnet => bech32::hrp::BC,
            Self::Testnets => bech32::hrp::TB,
            Self::Regtest => bech32::hrp::BCRT,
        }
    }
}

impl From<Network> for KnownHrp {
    fn from(n: Network) -> Self { Self::from_network(n) }
}

impl From<KnownHrp> for NetworkKind {
    fn from(hrp: KnownHrp) -> Self {
        match hrp {
            KnownHrp::Mainnet => Self::Main,
            KnownHrp::Testnets => Self::Test,
            KnownHrp::Regtest => Self::Test,
        }
    }
}

/// The data encoded by an `Address`.
///
/// This is the data used to encumber an output that pays to this address i.e., it is the address
/// excluding the network information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressData {
    /// Data encoded by a P2PKH address.
    P2pkh {
        /// The pubkey hash used to encumber outputs to this address.
        pubkey_hash: PubkeyHash,
    },
    /// Data encoded by a P2SH address.
    P2sh {
        /// The script hash used to encumber outputs to this address.
        script_hash: ScriptHash,
    },
    /// Data encoded by a SegWit address.
    Segwit {
        /// The witness program used to encumber outputs to this address.
        witness_program: WitnessProgram,
    },
}

// Defined in `REPO_DIR/include/newtype.rs`.
crate::transparent_newtype! {
    /// A Bitcoin address.
    ///
    /// # Parsing addresses
    ///
    /// When parsing string as an address, one has to pay attention to the network, on which the parsed
    /// address is supposed to be valid. For the purpose of this validation, `Address` has
    /// [`is_valid_for_network`](Address<NetworkUnchecked>::is_valid_for_network) method. In order to provide more safety,
    /// enforced by compiler, `Address` also contains a special marker type, which indicates whether network of the parsed
    /// address has been checked. This marker type will prevent from calling certain functions unless the network
    /// verification has been successfully completed.
    ///
    /// The result of parsing an address is `Address<NetworkUnchecked>` suggesting that network of the parsed address
    /// has not yet been verified. To perform this verification, method [`require_network`](Address<NetworkUnchecked>::require_network)
    /// can be called, providing network on which the address is supposed to be valid. If the verification succeeds,
    /// `Address<NetworkChecked>` is returned.
    ///
    /// The types `Address` and `Address<NetworkChecked>` are synonymous, i.e. they can be used interchangeably.
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use network::Network;
    /// use bitcoin_addresses::{Address, NetworkUnchecked, NetworkChecked};
    ///
    /// // variant 1
    /// let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
    /// let _address: Address<NetworkChecked> = address.require_network(Network::Bitcoin).unwrap();
    ///
    /// // variant 2
    /// let _address: Address = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap()
    ///                .require_network(Network::Bitcoin).unwrap();
    ///
    /// // variant 3
    /// let _address: Address<NetworkChecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse::<Address<_>>()
    ///                .unwrap().require_network(Network::Bitcoin).unwrap();
    /// ```
    ///
    /// ### Formatting addresses
    ///
    /// To format address into its textual representation, both `Debug` (for usage in programmer-facing,
    /// debugging context) and `Display` (for user-facing output) can be used, with the following caveats:
    ///
    /// 1. `Display` is implemented only for `Address<NetworkChecked>`:
    ///
    /// ```
    /// # use bitcoin_addresses::{Address, NetworkChecked};
    /// let address: Address<NetworkChecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap().assume_checked();
    /// assert_eq!(address.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
    /// ```
    ///
    /// ```ignore
    /// # use bitcoin_addresses::{Address, NetworkChecked};
    /// let address: Address<NetworkUnchecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap();
    /// let s = address.to_string(); // does not compile
    /// ```
    ///
    /// 2. `Debug` on `Address<NetworkUnchecked>` does not produce clean address but address wrapped by
    ///    an indicator that its network has not been checked. This is to encourage programmer to properly
    ///    check the network and use `Display` in user-facing context.
    ///
    /// ```
    /// # use bitcoin_addresses::{Address, NetworkUnchecked};
    /// let address: Address<NetworkUnchecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap();
    /// assert_eq!(format!("{:?}", address), "Address<NetworkUnchecked>(132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM)");
    /// ```
    ///
    /// ```
    /// # use bitcoin_addresses::{Address, NetworkChecked};
    /// let address: Address<NetworkChecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap().assume_checked();
    /// assert_eq!(format!("{:?}", address), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
    /// ```
    ///
    /// # Relevant BIPs
    ///
    /// * [BIP-0013 - Address Format for pay-to-script-hash](https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki)
    /// * [BIP-0016 - Pay to Script Hash](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)
    /// * [BIP-0141 - Segregated Witness (Consensus layer)](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    /// * [BIP-0142 - Address Format for Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki)
    /// * [BIP-0341 - Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
    /// * [BIP-0350 - Bech32m format for v1+ witness addresses](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    // The `#[repr(transparent)]` attribute is used to guarantee the layout of the `Address` struct. It
    // is an implementation detail and users should not rely on it in their code.
    pub struct Address<V = NetworkChecked>(PhantomData<V>, AddressInner)
    where
        V: NetworkValidation;

    impl<V> Address<V> {
        fn from_inner_ref(inner: &_) -> &Self;
    }
}

#[cfg(feature = "serde")]
struct DisplayUnchecked<'a, N: NetworkValidation>(&'a Address<N>);

#[cfg(feature = "serde")]
impl<N: NetworkValidation> fmt::Display for DisplayUnchecked<'_, N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0.inner(), fmt)
    }
}

#[cfg(feature = "serde")]
impl<'de, U: NetworkValidationUnchecked> serde::Deserialize<'de> for Address<U> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use core::fmt::Formatter;

        struct Visitor<U>(PhantomData<U>);
        impl<U> serde::de::Visitor<'_> for Visitor<U>
        where
            U: NetworkValidationUnchecked + NetworkValidation,
            Address<U>: FromStr,
        {
            type Value = Address<U>;

            fn expecting(&self, f: &mut Formatter) -> core::fmt::Result {
                f.write_str("A Bitcoin address")
            }

            fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // We know that `U` is only ever `NetworkUnchecked` but the compiler does not.
                let address = v.parse::<Address<NetworkUnchecked>>().map_err(E::custom)?;
                Ok(Address::from_inner(address.to_inner()))
            }
        }

        deserializer.deserialize_str(Visitor(PhantomData::<U>))
    }
}

#[cfg(feature = "serde")]
impl<V: NetworkValidation> serde::Serialize for Address<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&DisplayUnchecked(self))
    }
}

/// Methods on [`Address`] that can be called on both `Address<NetworkChecked>` and
/// `Address<NetworkUnchecked>`.
impl<V: NetworkValidation> Address<V> {
    fn from_inner(inner: AddressInner) -> Self { Self(PhantomData, inner) }

    fn to_inner(self) -> AddressInner { self.1 }

    fn inner(&self) -> &AddressInner { &self.1 }

    /// Returns a reference to the address as if it was unchecked.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        Address::from_inner_ref(self.inner())
    }

    /// Marks the network of this address as unchecked.
    pub fn to_unchecked(self) -> Address<NetworkUnchecked> { Address::from_inner(self.to_inner()) }

    /// Marks the network of this address as unchecked.
    #[deprecated(since = "0.33.0", note = "use to_unchecked instead")]
    pub fn into_unchecked(self) -> Address<NetworkUnchecked> {
        Address::from_inner(self.to_inner())
    }

    /// Returns the [`NetworkKind`] of this address.
    pub fn network_kind(&self) -> NetworkKind {
        use AddressInner::*;
        match *self.inner() {
            P2pkh { hash: _, ref network } => *network,
            P2sh { hash: _, ref network } => *network,
            Segwit { program: _, ref hrp } => NetworkKind::from(*hrp),
        }
    }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Constructs a new pay-to-public-key-hash (P2PKH) [`Address`] from a public key.
    ///
    /// This is the preferred non-witness type address.
    #[inline]
    pub fn p2pkh(pk: impl Into<PubkeyHash>, network: impl Into<NetworkKind>) -> Self {
        let hash = pk.into();
        Self::from_inner(AddressInner::P2pkh { hash, network: network.into() })
    }

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] from a script.
    ///
    /// This address type was introduced with BIP-0016 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh<T: ScriptHashableTag>(
        redeem_script: &Script<T>,
        network: impl Into<NetworkKind>,
    ) -> Result<Self, RedeemScriptSizeError> {
        let hash = ScriptHash::from_script(redeem_script)?;
        Ok(Self::p2sh_from_hash(hash, network))
    }

    /// Constructs a new pay-to-script-hash (P2SH) [`Address`] from a script hash.
    ///
    /// # Warning
    ///
    /// The `hash` pre-image (redeem script) must not exceed 520 bytes in length
    /// otherwise outputs created from the returned address will be un-spendable.
    pub fn p2sh_from_hash(hash: ScriptHash, network: impl Into<NetworkKind>) -> Self {
        Self::from_inner(AddressInner::P2sh { hash, network: network.into() })
    }

    /// Constructs a new pay-to-witness-public-key-hash (P2WPKH) [`Address`] from a public key.
    ///
    /// This is the native SegWit address type for an output redeemable with a single signature.
    pub fn p2wpkh(pk: FullPublicKey, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wpkh(pk);
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-witness-script-hash (P2WSH) [`Address`] from a witness script.
    pub fn p2wsh(
        witness_script: &WitnessScript,
        hrp: impl Into<KnownHrp>,
    ) -> Result<Self, WitnessScriptSizeError> {
        let program = WitnessProgram::p2wsh(witness_script)?;
        Ok(Self::from_witness_program(program, hrp))
    }

    /// Constructs a new pay-to-witness-script-hash (P2WSH) [`Address`] from a witness script hash.
    pub fn p2wsh_from_hash(hash: WScriptHash, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wsh_from_hash(hash);
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-Taproot (P2TR) [`Address`] from a tweaked output key.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2tr_tweaked(output_key);
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-anchor (P2A) [`Address`].
    pub fn p2a(hrp: impl Into<KnownHrp>) -> Self {
        Self::from_witness_program(WitnessProgram::p2a(), hrp)
    }

    /// Constructs a new [`Address`] from an arbitrary [`WitnessProgram`].
    ///
    /// This only exists to support future witness versions. If you are doing normal mainnet things
    /// then you likely do not need this constructor.
    pub fn from_witness_program(program: WitnessProgram, hrp: impl Into<KnownHrp>) -> Self {
        let inner = AddressInner::Segwit { program, hrp: hrp.into() };
        Self::from_inner(inner)
    }

    /// Gets the address type of the [`Address`].
    ///
    /// # Returns
    ///
    /// None if unknown, non-standard or related to the future witness version.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> {
        match *self.inner() {
            AddressInner::P2pkh { .. } => Some(AddressType::P2pkh),
            AddressInner::P2sh { .. } => Some(AddressType::P2sh),
            AddressInner::Segwit { ref program, hrp: _ } =>
                if program.is_p2wpkh() {
                    Some(AddressType::P2wpkh)
                } else if program.is_p2wsh() {
                    Some(AddressType::P2wsh)
                } else if program.is_p2tr() {
                    Some(AddressType::P2tr)
                } else if program.is_p2a() {
                    Some(AddressType::P2a)
                } else {
                    None
                },
        }
    }

    /// Gets the address data from this address.
    pub fn to_address_data(self) -> AddressData {
        use AddressData::*;

        match *self.inner() {
            AddressInner::P2pkh { hash, network: _ } => P2pkh { pubkey_hash: hash },
            AddressInner::P2sh { hash, network: _ } => P2sh { script_hash: hash },
            AddressInner::Segwit { program, hrp: _ } => Segwit { witness_program: program },
        }
    }

    /// Gets the pubkey hash for this address if this is a P2PKH address.
    pub fn pubkey_hash(&self) -> Option<PubkeyHash> {
        use AddressInner::*;

        match *self.inner() {
            P2pkh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the script hash for this address if this is a P2SH address.
    pub fn script_hash(&self) -> Option<ScriptHash> {
        use AddressInner::*;

        match *self.inner() {
            P2sh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the witness program for this address if this is a SegWit address.
    pub fn witness_program(&self) -> Option<WitnessProgram> {
        use AddressInner::*;

        match *self.inner() {
            Segwit { ref program, hrp: _ } => Some(*program),
            _ => None,
        }
    }

    /// Checks whether or not the address is following Bitcoin standardness rules when
    /// *spending* from this address. *NOT* to be called by senders.
    ///
    /// <details>
    /// <summary>Spending Standardness</summary>
    ///
    /// For forward compatibility, the senders must send to any [`Address`]. Receivers
    /// can use this method to check whether or not they can spend from this address.
    ///
    /// SegWit addresses with unassigned witness versions or non-standard program sizes are
    /// considered non-standard.
    /// </details>
    ///
    pub fn is_spend_standard(&self) -> bool { self.address_type().is_some() }

    /// Constructs a new URI string *bitcoin:address* optimized to be encoded in QR codes.
    ///
    /// If the address is bech32, the address becomes uppercase.
    /// If the address is base58, the address is left mixed case.
    ///
    /// Quoting BIP 173 "inside QR codes uppercase SHOULD be used, as those permit the use of
    /// alphanumeric mode, which is 45% more compact than the normal byte mode."
    ///
    /// Note however that despite BIP-0021 explicitly stating that the `bitcoin:` prefix should be
    /// parsed as case-insensitive many wallets got this wrong and don't parse correctly.
    /// [See compatibility table.](https://github.com/btcpayserver/btcpayserver/issues/2110)
    ///
    /// If you want to avoid allocation you can use alternate display instead:
    /// ```
    /// # use core::fmt::Write;
    /// # const ADDRESS: &str = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
    /// # let address = ADDRESS.parse::<bitcoin_addresses::Address<_>>().unwrap().assume_checked();
    /// # let mut writer = String::new();
    /// # // magic trick to make error handling look better
    /// # (|| -> core::fmt::Result {
    ///
    /// write!(writer, "{:#}", address)?;
    ///
    /// # Ok(())
    /// # })().unwrap();
    /// # assert_eq!(writer, ADDRESS);
    /// ```
    pub fn to_qr_uri(self) -> String { format!("bitcoin:{:#}", self) }

    /// Returns true if the given pubkey is directly related to the address payload.
    ///
    /// This is determined by directly comparing the address payload with either the
    /// hash of the given public key or the SegWit redeem hash generated from the
    /// given key. For Taproot addresses, the supplied key is assumed to be tweaked
    pub fn is_related_to_pubkey(&self, pubkey: LegacyPublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload_as_bytes();
        let xonly_pubkey = XOnlyPublicKey::from(pubkey);

        (*pubkey_hash.as_byte_array() == *payload)
            || (xonly_pubkey.serialize().0 == *payload)
            || (*segwit_redeem_hash(pubkey_hash).as_byte_array() == *payload)
    }

    /// Returns true if the supplied xonly public key can be used to derive the address.
    ///
    /// This will only work for Taproot addresses. The Public Key is
    /// assumed to have already been tweaked.
    pub fn is_related_to_xonly_pubkey(&self, xonly_pubkey: XOnlyPublicKey) -> bool {
        xonly_pubkey.serialize().0 == *self.payload_as_bytes()
    }

    /// Returns the "payload" for this address.
    ///
    /// The "payload" is the useful stuff excluding serialization prefix, the exact payload is
    /// dependent on the inner address:
    ///
    /// - For p2sh, the payload is the script hash.
    /// - For p2pkh, the payload is the pubkey hash.
    /// - For SegWit addresses, the payload is the witness program.
    fn payload_as_bytes(&self) -> &[u8] {
        use AddressInner::*;
        match *self.inner() {
            P2sh { ref hash, network: _ } => hash.as_ref(),
            P2pkh { ref hash, network: _ } => hash.as_ref(),
            Segwit { ref program, hrp: _ } => program.as_program_slice(),
        }
    }
}

/// Methods that can be called only on `Address<NetworkUnchecked>`.
impl Address<NetworkUnchecked> {
    /// Returns a reference to the checked address.
    ///
    /// This function is dangerous in case the address is not a valid checked address.
    pub fn assume_checked_ref(&self) -> &Address { Address::from_inner_ref(self.inner()) }

    /// Parsed addresses do not always have *one* network. The problem is that legacy testnet,
    /// regtest and signet addresses use the same prefix instead of multiple different ones. When
    /// parsing, such addresses are always assumed to be testnet addresses (the same is true for
    /// bech32 signet addresses). So if one wants to check if an address belongs to a certain
    /// network a simple comparison is not enough anymore. Instead this function can be used.
    ///
    /// ```rust
    /// use network::{Network, TestnetVersion};
    /// use bitcoin_addresses::{Address, NetworkUnchecked};
    ///
    /// let address: Address<NetworkUnchecked> = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Testnet(TestnetVersion::V3)));
    /// assert!(address.is_valid_for_network(Network::Regtest));
    /// assert!(address.is_valid_for_network(Network::Signet));
    ///
    /// assert_eq!(address.is_valid_for_network(Network::Bitcoin), false);
    ///
    /// let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Bitcoin));
    /// assert_eq!(address.is_valid_for_network(Network::Testnet(TestnetVersion::V4)), false);
    /// ```
    pub fn is_valid_for_network(&self, n: Network) -> bool {
        use AddressInner::*;
        match *self.inner() {
            P2pkh { hash: _, ref network } => *network == NetworkKind::from(n),
            P2sh { hash: _, ref network } => *network == NetworkKind::from(n),
            Segwit { program: _, ref hrp } => *hrp == KnownHrp::from_network(n),
        }
    }

    /// Checks whether network of this address is as required.
    ///
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    ///
    /// # Errors
    ///
    /// This function only ever returns the [`ParseError::NetworkValidation`] variant of
    /// `ParseError`. This is not how we normally implement errors in this library but
    /// `require_network` is not a typical function, it is conceptually part of string parsing.
    ///
    ///  # Examples
    ///
    /// ```
    /// use bitcoin_addresses::{Address, NetworkChecked, NetworkUnchecked, ParseError};
    /// use network::Network;
    ///
    /// const ADDR: &str = "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs";
    ///
    /// fn parse_and_validate_address(network: Network) -> Result<Address, ParseError> {
    ///     let address = ADDR.parse::<Address<_>>()?
    ///                       .require_network(network)?;
    ///     Ok(address)
    /// }
    ///
    /// fn parse_and_validate_address_combinator(network: Network) -> Result<Address, ParseError> {
    ///     let address = ADDR.parse::<Address<_>>()
    ///                       .and_then(|a| a.require_network(network))?;
    ///     Ok(address)
    /// }
    ///
    /// fn parse_and_validate_address_show_types(network: Network) -> Result<Address, ParseError> {
    ///     let address: Address<NetworkChecked> = ADDR.parse::<Address<NetworkUnchecked>>()?
    ///                                                .require_network(network)?;
    ///     Ok(address)
    /// }
    ///
    /// let network = Network::Bitcoin;  // Don't hard code network in applications.
    /// let _ = parse_and_validate_address(network).unwrap();
    /// let _ = parse_and_validate_address_combinator(network).unwrap();
    /// let _ = parse_and_validate_address_show_types(network).unwrap();
    /// ```
    #[inline]
    pub fn require_network(self, required: Network) -> Result<Address, ParseError> {
        if self.is_valid_for_network(required) {
            Ok(self.assume_checked())
        } else {
            Err(NetworkValidationError { required, address: self }.into())
        }
    }

    /// Marks, without any additional checks, network of this address as checked.
    ///
    /// Improper use of this method may lead to loss of funds. Reader will most likely prefer
    /// [`require_network`](Address<NetworkUnchecked>::require_network) as a safe variant.
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn assume_checked(self) -> Address { Address::from_inner(self.to_inner()) }

    /// Parses a bech32 Address string
    pub fn from_bech32_str(s: &str) -> Result<Self, Bech32Error> {
        let (hrp, witness_version, data) =
            bech32::segwit::decode(s).map_err(|e| Bech32Error::ParseBech32(ParseBech32Error(e)))?;
        let version = WitnessVersion::try_from(witness_version.to_u8())?;
        let program = WitnessProgram::new(version, &data)
            .expect("bech32 guarantees valid program length for witness");

        let hrp = KnownHrp::from_hrp(hrp)?;
        let inner = AddressInner::Segwit { program, hrp };
        Ok(Self::from_inner(inner))
    }

    /// Parses a base58 Address string
    pub fn from_base58_str(s: &str) -> Result<Self, Base58Error> {
        if s.len() > 50 {
            return Err(LegacyAddressTooLongError { length: s.len() }.into());
        }
        let data = base58::decode_check(s)?;
        let data: &[u8; 21] = (&*data)
            .try_into()
            .map_err(|_| InvalidBase58PayloadLengthError { length: data.len() })?;

        let (prefix, &data) = data.split_first();

        let inner = match *prefix {
            PUBKEY_ADDRESS_PREFIX_MAIN => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: NetworkKind::Main }
            }
            PUBKEY_ADDRESS_PREFIX_TEST => {
                let hash = PubkeyHash::from_byte_array(data);
                AddressInner::P2pkh { hash, network: NetworkKind::Test }
            }
            SCRIPT_ADDRESS_PREFIX_MAIN => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Main }
            }
            SCRIPT_ADDRESS_PREFIX_TEST => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Test }
            }
            invalid => return Err(InvalidLegacyPrefixError { invalid }.into()),
        };

        Ok(Self::from_inner(inner))
    }
}

// Alternate formatting `{:#}` is used to return an uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.inner(), fmt) }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            fmt::Display::fmt(&self.inner(), f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            fmt::Display::fmt(&self.inner(), f)?;
            write!(f, ")")
        }
    }
}

/// Address can be parsed only with `NetworkUnchecked`.
///
/// Only SegWit bech32 addresses prefixed with `bc`, `bcrt` or `tb` and legacy base58 addresses
/// prefixed with `1`, `2`, `3`, `m` or `n` are supported.
///
/// # Errors
///
/// - [`ParseError::Bech32`] if the SegWit address begins with a `bc`, `bcrt` or `tb` and is not a
///   valid bech32 address.
///
/// - [`ParseError::Base58`] if the legacy address begins with a `1`, `2`, `3`, `m` or `n` and is
///   not a valid base58 address.
///
/// - [`UnknownHrpError`] if the address does not begin with one of the above SegWit or
///   legacy prefixes.
impl<U: NetworkValidationUnchecked> FromStr for Address<U> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        if ["bc1", "bcrt1", "tb1"].iter().any(|&prefix| s.to_lowercase().starts_with(prefix)) {
            let address = Address::from_bech32_str(s)?;
            // We know that `U` is only ever `NetworkUnchecked` but the compiler does not.
            Ok(Self::from_inner(address.to_inner()))
        } else if ["1", "2", "3", "m", "n"].iter().any(|&prefix| s.starts_with(prefix)) {
            let address = Address::from_base58_str(s)?;
            Ok(Self::from_inner(address.to_inner()))
        } else {
            let hrp = match s.rfind('1') {
                Some(pos) => &s[..pos],
                None => s,
            };
            Err(UnknownHrpError(hrp.to_owned()).into())
        }
    }
}

/// Convert a byte array of a pubkey hash into a SegWit redeem hash
fn segwit_redeem_hash(pubkey_hash: PubkeyHash) -> hash160::Hash {
    let mut sha_engine = hash160::Hash::engine();
    sha_engine.input(&[0, 20]);
    sha_engine.input(pubkey_hash.as_ref());
    hash160::Hash::from_engine(sha_engine)
}

include!("../include/newtype.rs"); // Explained in `REPO_DIR/docs/README.md`.

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use network::TestnetVersion;

    use super::*;

    #[test]
    fn address_debug() {
        // This is not really testing output of Debug but the ability and proper functioning
        // of Debug derivation on structs generic in NetworkValidation.
        #[derive(Debug)]
        #[allow(unused)]
        struct Test<V: NetworkValidation> {
            address: Address<V>,
        }

        let addr_str = "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k";
        let unchecked = addr_str.parse::<Address<_>>().unwrap();

        assert_eq!(
            format!("{:?}", Test { address: unchecked }),
            format!("Test {{ address: Address<NetworkUnchecked>({}) }}", addr_str)
        );

        assert_eq!(
            format!("{:?}", Test { address: unchecked.assume_checked() }),
            format!("Test {{ address: {} }}", addr_str)
        );
    }

    #[test]
    fn address_type() {
        let addresses = [
            ("1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY", Some(AddressType::P2pkh)),
            ("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k", Some(AddressType::P2sh)),
            ("bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw", Some(AddressType::P2wpkh)),
            (
                "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
                Some(AddressType::P2wsh),
            ),
            (
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                Some(AddressType::P2tr),
            ),
            // Related to future extensions, addresses are valid but have no type
            // SegWit v1 and len != 32
            ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", None),
            // SegWit v2
            ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", None),
        ];
        for (address, expected_type) in &addresses {
            let addr = address
                .parse::<Address<_>>()
                .unwrap()
                .require_network(Network::Bitcoin)
                .expect("mainnet");
            assert_eq!(&addr.address_type(), expected_type);
        }
    }

    #[test]
    fn qr_string() {
        for el in
            ["132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM", "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k"].iter()
        {
            let addr = el
                .parse::<Address<_>>()
                .unwrap()
                .require_network(Network::Bitcoin)
                .expect("mainnet");
            assert_eq!(addr.to_qr_uri(), format!("bitcoin:{}", el));
        }

        for el in [
            "bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl",
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
        ]
        .iter()
        {
            let addr = el.parse::<Address<_>>().unwrap().assume_checked();
            assert_eq!(addr.to_qr_uri(), format!("bitcoin:{}", el.to_ascii_uppercase()));
        }
    }

    #[test]
    fn is_related_to_pubkey_p2wpkh() {
        let address_string = "bc1qhvd6suvqzjcu9pxjhrwhtrlj85ny3n2mqql5w4";
        let address = address_string
            .parse::<Address<_>>()
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<LegacyPublicKey>().expect("pubkey");

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<LegacyPublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey))
    }

    #[test]
    fn is_related_to_pubkey_p2shwpkh() {
        let address_string = "3EZQk4F8GURH5sqVMLTFisD17yNeKa7Dfs";
        let address = address_string
            .parse::<Address<_>>()
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<LegacyPublicKey>().expect("pubkey");

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<LegacyPublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey))
    }

    #[test]
    fn is_related_to_pubkey_p2pkh() {
        let address_string = "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx";
        let address = address_string
            .parse::<Address<_>>()
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<LegacyPublicKey>().expect("pubkey");

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<LegacyPublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey))
    }

    #[test]
    fn is_related_to_pubkey_p2pkh_uncompressed_key() {
        let address_string = "msvS7KzhReCDpQEJaV2hmGNvuQqVUDuC6p";
        let address = address_string
            .parse::<Address<_>>()
            .expect("address")
            .require_network(Network::Testnet(TestnetVersion::V3))
            .expect("testnet");

        let pubkey_string = "04e96e22004e3db93530de27ccddfdf1463975d2138ac018fc3e7ba1a2e5e0aad8e424d0b55e2436eb1d0dcd5cb2b8bcc6d53412c22f358de57803a6a655fbbd04";
        let pubkey = pubkey_string.parse::<LegacyPublicKey>().expect("pubkey");

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<LegacyPublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey))
    }

    #[test]
    fn is_related_to_pubkey_p2tr() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<LegacyPublicKey>().expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

        assert_eq!(
            address,
            "bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e"
                .parse::<Address<_>>()
                .expect("address")
                .require_network(Network::Bitcoin)
                .expect("mainnet")
        );

        let result = address.is_related_to_pubkey(pubkey);
        assert!(result);

        let unused_pubkey = "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c"
            .parse::<LegacyPublicKey>()
            .expect("pubkey");
        assert!(!address.is_related_to_pubkey(unused_pubkey));
    }

    #[test]
    fn is_related_to_xonly_pubkey() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<LegacyPublicKey>().expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

        assert_eq!(
            address,
            "bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e"
                .parse::<Address<_>>()
                .expect("address")
                .require_network(Network::Bitcoin)
                .expect("mainnet")
        );

        let result = address.is_related_to_xonly_pubkey(xonly_pubkey);
        assert!(result);
    }

    #[test]
    fn valid_address_parses_correctly() {
        let addr = "p2tr".parse::<AddressType>().expect("false negative while parsing address");
        assert_eq!(addr, AddressType::P2tr);
    }

    #[test]
    fn invalid_address_parses_error() {
        let got = "invalid".parse::<AddressType>();
        let want = Err(UnknownAddressTypeError("invalid".to_string()));
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_address_usage_in_struct() {
        use serde::{self, Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct Foo<V>
        where
            V: NetworkValidation,
        {
            #[serde(bound(deserialize = "V: NetworkValidationUnchecked"))]
            address: Address<V>,
        }

        let addr_str = "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k";
        let unchecked = addr_str.parse::<Address<_>>().unwrap();

        // Serialize with an unchecked address.
        let foo_unchecked = Foo { address: unchecked };
        let ser = serde_json::to_string(&foo_unchecked).expect("failed to serialize");
        let roundtrip: Foo<NetworkUnchecked> =
            serde_json::from_str(&ser).expect("failed to deserialize");
        assert_eq!(roundtrip, foo_unchecked);

        // Serialize with a checked address.
        let foo_checked = Foo { address: unchecked.assume_checked() };
        let ser = serde_json::to_string(&foo_checked).expect("failed to serialize");
        let roundtrip: Foo<NetworkUnchecked> =
            serde_json::from_str(&ser).expect("failed to deserialize");
        assert_eq!(&roundtrip.address, foo_checked.address.as_unchecked());
        assert_eq!(roundtrip, foo_unchecked);
    }
}
