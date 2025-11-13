// SPDX-License-Identifier: CC0-1.0

//! Bitcoin addresses.
//!
//! Support for segwit and legacy addresses (bech32 and base58 respectively).
//!
//! # Examples
//!
//! ### Creating a new address from a randomly-generated key pair.
//!
//! ```rust
//! #[cfg(all(feature = "rand", feature = "std"))] {
//! use bitcoin::secp256k1::rand;
//! use bitcoin::{Address, Network, PublicKey};
//!
//! // Generate random key pair.
//! let (_sk, pk) = secp256k1::generate_keypair(&mut rand::rng());
//! let public_key = PublicKey::new(pk); // Or `PublicKey::from(pk)`.
//!
//! // Generate a mainnet pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Bitcoin);
//! }
//! ```
//!
//! ### Using an `Address` as a struct field.
//!
//! ```rust
//! # #[cfg(feature = "serde")] {
//! # use serde::{self, Deserialize, Serialize};
//! use bitcoin::address::{Address, NetworkValidation, NetworkValidationUnchecked};
//! #[derive(Serialize, Deserialize)]
//! struct Foo<V>
//!     where V: NetworkValidation,
//! {
//!     #[serde(bound(deserialize = "V: NetworkValidationUnchecked"))]
//!     address: Address<V>,
//! }
//! # }
//! ```

pub mod error;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bech32::primitives::gf32::Fe32;
use bech32::primitives::hrp::Hrp;
use crypto::key::{
    CompressedPublicKey, PubkeyHash, PublicKey, TweakedPublicKey, UntweakedPublicKey,
    XOnlyPublicKey,
};
use crypto::WitnessProgramExt as _;
use hashes::{hash160, HashEngine};
use internals::array::ArrayExt;
use network::{Network, NetworkKind};
use primitives::script::witness_program::WitnessProgram;
use primitives::script::witness_version::WitnessVersion;
use primitives::script::ScriptHash;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use taproot_primitives::TapNodeHash;

use crate::constants::{
    PUBKEY_ADDRESS_PREFIX_MAIN, PUBKEY_ADDRESS_PREFIX_TEST, SCRIPT_ADDRESS_PREFIX_MAIN,
    SCRIPT_ADDRESS_PREFIX_TEST,
};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::error::{
        Base58Error, Bech32Error, FromScriptError, InvalidBase58PayloadLengthError,
        InvalidLegacyPrefixError, LegacyAddressTooLongError, NetworkValidationError,
        ParseError, UnknownAddressTypeError, UnknownHrpError, ParseBech32Error,
};

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
                let program = program.program();

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

internals::transparent_newtype! {
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
    /// use bitcoin::{Address, Network};
    /// use bitcoin::address::{NetworkUnchecked, NetworkChecked};
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
    /// # use bitcoin::address::{Address, NetworkChecked};
    /// let address: Address<NetworkChecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap().assume_checked();
    /// assert_eq!(address.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
    /// ```
    ///
    /// ```ignore
    /// # use bitcoin::address::{Address, NetworkChecked};
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
    /// # use bitcoin::address::{Address, NetworkUnchecked};
    /// let address: Address<NetworkUnchecked> = "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".parse::<Address<_>>()
    ///                .unwrap();
    /// assert_eq!(format!("{:?}", address), "Address<NetworkUnchecked>(132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM)");
    /// ```
    ///
    /// ```
    /// # use bitcoin::address::{Address, NetworkChecked};
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
    pub fn p2wpkh(pk: CompressedPublicKey, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wpkh(pk);
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-Taproot (P2TR) [`Address`] from an untweaked key.
    pub fn p2tr<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
        hrp: impl Into<KnownHrp>,
    ) -> Self {
        let internal_key = internal_key.into();
        let program = WitnessProgram::p2tr(internal_key, merkle_root);
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-Taproot (P2TR) [`Address`] from a pre-tweaked output key.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2tr_tweaked(output_key);
        Self::from_witness_program(program, hrp)
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
    /// # let address = ADDRESS.parse::<bitcoin::Address<_>>().unwrap().assume_checked();
    /// # let mut writer = String::new();
    /// # // magic trick to make error handling look better
    /// # (|| -> Result<(), core::fmt::Error> {
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
    pub fn is_related_to_pubkey(&self, pubkey: PublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload_as_bytes();
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);

        (*pubkey_hash.as_byte_array() == *payload)
            || (xonly_pubkey.serialize() == *payload)
            || (*segwit_redeem_hash(pubkey_hash).as_byte_array() == *payload)
    }

    /// Returns true if the supplied xonly public key can be used to derive the address.
    ///
    /// This will only work for Taproot addresses. The Public Key is
    /// assumed to have already been tweaked.
    pub fn is_related_to_xonly_pubkey(&self, xonly_pubkey: XOnlyPublicKey) -> bool {
        xonly_pubkey.serialize() == *self.payload_as_bytes()
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
            Segwit { ref program, hrp: _ } => program.program(),
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
    /// use bitcoin::{Address, Network, TestnetVersion};
    /// use bitcoin::address::NetworkUnchecked;
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
    /// use bitcoin::address::{NetworkChecked, NetworkUnchecked, ParseError};
    /// use bitcoin::{Address, Network};
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
