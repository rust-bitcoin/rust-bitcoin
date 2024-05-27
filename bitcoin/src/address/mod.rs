// SPDX-License-Identifier: CC0-1.0

//! Bitcoin addresses.
//!
//! Support for ordinary base58 Bitcoin addresses and private keys.
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//! # #[cfg(feature = "rand-std")] {
//! use bitcoin::{Address, PublicKey, Network};
//! use bitcoin::secp256k1::{rand, Secp256k1};
//!
//! // Generate random key pair.
//! let s = Secp256k1::new();
//! let public_key = PublicKey::new(s.generate_keypair(&mut rand::thread_rng()).1);
//!
//! // Generate pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Bitcoin);
//! # }
//! ```
//!
//! # Note: creating a new address requires the rand-std feature flag
//!
//! ```toml
//! bitcoin = { version = "...", features = ["rand-std"] }
//! ```

pub mod error;

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bech32::primitives::hrp::Hrp;
use hashes::{sha256, Hash, HashEngine};
use secp256k1::{Secp256k1, Verification, XOnlyPublicKey};

use crate::blockdata::constants::{
    MAX_SCRIPT_ELEMENT_SIZE, PUBKEY_ADDRESS_PREFIX_MAIN, PUBKEY_ADDRESS_PREFIX_TEST,
    SCRIPT_ADDRESS_PREFIX_MAIN, SCRIPT_ADDRESS_PREFIX_TEST,
};
use crate::blockdata::script::witness_program::WitnessProgram;
use crate::blockdata::script::witness_version::WitnessVersion;
use crate::blockdata::script::{self, Script, ScriptBuf, ScriptHash};
use crate::consensus::Params;
use crate::crypto::key::{
    CompressedPublicKey, PubkeyHash, PublicKey, TweakedPublicKey, UntweakedPublicKey,
};
use crate::network::{Network, NetworkKind};
use crate::prelude::*;
use crate::taproot::TapNodeHash;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    error::{
        FromScriptError, InvalidBase58PayloadLengthError, InvalidLegacyPrefixError, LegacyAddressTooLongError,
        NetworkValidationError, ParseError, P2shError, UnknownAddressTypeError, UnknownHrpError
    },
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
    /// Pay to taproot.
    P2tr,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            AddressType::P2pkh => "p2pkh",
            AddressType::P2sh => "p2sh",
            AddressType::P2wpkh => "p2wpkh",
            AddressType::P2wsh => "p2wsh",
            AddressType::P2tr => "p2tr",
        })
    }
}

impl FromStr for AddressType {
    type Err = UnknownAddressTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(AddressType::P2pkh),
            "p2sh" => Ok(AddressType::P2sh),
            "p2wpkh" => Ok(AddressType::P2wpkh),
            "p2wsh" => Ok(AddressType::P2wsh),
            "p2tr" => Ok(AddressType::P2tr),
            _ => Err(UnknownAddressTypeError(s.to_owned())),
        }
    }
}

mod sealed {
    pub trait NetworkValidation {}
    impl NetworkValidation for super::NetworkChecked {}
    impl NetworkValidation for super::NetworkUnchecked {}
}

/// Marker of status of address's network validation. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
pub trait NetworkValidation: sealed::NetworkValidation + Sync + Send + Sized + Unpin {
    /// Indicates whether this `NetworkValidation` is `NetworkChecked` or not.
    const IS_CHECKED: bool;
}

/// Marker that address's network has been successfully validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkChecked {}

/// Marker that address's network has not yet been validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkUnchecked {}

impl NetworkValidation for NetworkChecked {
    const IS_CHECKED: bool = true;
}
impl NetworkValidation for NetworkUnchecked {
    const IS_CHECKED: bool = false;
}

/// The inner representation of an address, without the network validation tag.
///
/// This struct represents the inner representation of an address without the network validation
/// tag, which is used to ensure that addresses are used only on the appropriate network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            P2sh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    NetworkKind::Main => SCRIPT_ADDRESS_PREFIX_MAIN,
                    NetworkKind::Test => SCRIPT_ADDRESS_PREFIX_TEST,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Segwit { program, hrp } => {
                let hrp = hrp.to_hrp();
                let version = program.version().to_fe();
                let program = program.program().as_ref();

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
    /// The test networks, testnet and signet.
    Testnets,
    /// The regtest network.
    Regtest,
}

impl KnownHrp {
    /// Creates a `KnownHrp` from `network`.
    fn from_network(network: Network) -> Self {
        use Network::*;

        match network {
            Bitcoin => Self::Mainnet,
            Testnet | Signet => Self::Testnets,
            Regtest => Self::Regtest,
        }
    }

    /// Creates a `KnownHrp` from a [`bech32::Hrp`].
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
        pubkey_hash: PubkeyHash
    },
    /// Data encoded by a P2SH address.
    P2sh {
        /// The script hash used to encumber outputs to this address.
        script_hash: ScriptHash
    },
    /// Data encoded by a Segwit address.
    Segwit {
        /// The witness program used to encumber outputs to this address.
        witness_program: WitnessProgram
    },
}

/// A Bitcoin address.
///
/// ### Parsing addresses
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
/// The types `Address` and `Address<NetworkChecked>` are synonymous, i. e. they can be used interchangeably.
///
/// ```rust
/// use std::str::FromStr;
/// use bitcoin::{Address, Network};
/// use bitcoin::address::{NetworkUnchecked, NetworkChecked};
///
/// // variant 1
/// let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
/// let address: Address<NetworkChecked> = address.require_network(Network::Bitcoin).unwrap();
///
/// // variant 2
/// let address: Address = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap()
///                .require_network(Network::Bitcoin).unwrap();
///
/// // variant 3
/// let address: Address<NetworkChecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse::<Address<_>>()
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
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap().assume_checked();
/// assert_eq!(address.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
/// ```
///
/// ```ignore
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap();
/// let s = address.to_string(); // does not compile
/// ```
///
/// 2. `Debug` on `Address<NetworkUnchecked>` does not produce clean address but address wrapped by
/// an indicator that its network has not been checked. This is to encourage programmer to properly
/// check the network and use `Display` in user-facing context.
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkUnchecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap();
/// assert_eq!(format!("{:?}", address), "Address<NetworkUnchecked>(132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM)");
/// ```
///
/// ```
/// # use std::str::FromStr;
/// # use bitcoin::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
///                .unwrap().assume_checked();
/// assert_eq!(format!("{:?}", address), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
/// ```
///
/// ### Relevant BIPs
///
/// * [BIP13 - Address Format for pay-to-script-hash](https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki)
/// * [BIP16 - Pay to Script Hash](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)
/// * [BIP141 - Segregated Witness (Consensus layer)](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
/// * [BIP142 - Address Format for Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0142.mediawiki)
/// * [BIP341 - Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
/// * [BIP350 - Bech32m format for v1+ witness addresses](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// The `#[repr(transparent)]` attribute is used to guarantee the layout of the `Address` struct. It
// is an implementation detail and users should not rely on it in their code.
#[repr(transparent)]
pub struct Address<V = NetworkChecked>(AddressInner, PhantomData<V>)
where
    V: NetworkValidation;

#[cfg(feature = "serde")]
struct DisplayUnchecked<'a, N: NetworkValidation>(&'a Address<N>);

#[cfg(feature = "serde")]
impl<N: NetworkValidation> fmt::Display for DisplayUnchecked<'_, N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0 .0, fmt) }
}

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_deserialize_impl!(Address<NetworkUnchecked>, "a Bitcoin address");

#[cfg(feature = "serde")]
impl<N: NetworkValidation> serde::Serialize for Address<N> {
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
    /// Returns a reference to the address as if it was unchecked.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        unsafe { &*(self as *const Address<V> as *const Address<NetworkUnchecked>) }
    }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key.
    ///
    /// This is the preferred non-witness type address.
    #[inline]
    pub fn p2pkh(pk: impl Into<PubkeyHash>, network: impl Into<NetworkKind>) -> Address {
        let hash = pk.into();
        Self(AddressInner::P2pkh { hash, network: network.into() }, PhantomData)
    }

    /// Creates a pay to script hash P2SH address from a script.
    ///
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh(script: &Script, network: impl Into<NetworkKind>) -> Result<Address, P2shError> {
        if script.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(P2shError::ExcessiveScriptSize);
        }
        let hash = script.script_hash();
        Ok(Address::p2sh_from_hash(hash, network))
    }

    /// Creates a pay to script hash P2SH address from a script hash.
    ///
    /// # Warning
    ///
    /// The `hash` pre-image (redeem script) must not exceed 520 bytes in length
    /// otherwise outputs created from the returned address will be un-spendable.
    pub fn p2sh_from_hash(hash: ScriptHash, network: impl Into<NetworkKind>) -> Address {
        Self(AddressInner::P2sh { hash, network: network.into() }, PhantomData)
    }

    /// Creates a witness pay to public key address from a public key.
    ///
    /// This is the native segwit address type for an output redeemable with a single signature.
    pub fn p2wpkh(pk: &CompressedPublicKey, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wpkh(pk);
        Address::from_witness_program(program, hrp)
    }

    /// Creates a pay to script address that embeds a witness pay to public key.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwpkh(pk: &CompressedPublicKey, network: impl Into<NetworkKind>) -> Address {
        let builder = script::Builder::new().push_int(0).push_slice(pk.wpubkey_hash());
        let script_hash = builder.as_script().script_hash();
        Address::p2sh_from_hash(script_hash, network)
    }

    /// Creates a witness pay to script hash address.
    pub fn p2wsh(script: &Script, hrp: impl Into<KnownHrp>) -> Address {
        let program = WitnessProgram::p2wsh(script);
        Address::from_witness_program(program, hrp)
    }

    /// Creates a pay to script address that embeds a witness pay to script hash address.
    ///
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients.
    pub fn p2shwsh(script: &Script, network: impl Into<NetworkKind>) -> Address {
        let builder = script::Builder::new().push_int(0).push_slice(script.wscript_hash());
        let script_hash = builder.as_script().script_hash();
        Address::p2sh_from_hash(script_hash, network)
    }

    /// Creates a pay to taproot address from an untweaked key.
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
        hrp: impl Into<KnownHrp>,
    ) -> Address {
        let program = WitnessProgram::p2tr(secp, internal_key, merkle_root);
        Address::from_witness_program(program, hrp)
    }

    /// Creates a pay to taproot address from a pre-tweaked output key.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey, hrp: impl Into<KnownHrp>) -> Address {
        let program = WitnessProgram::p2tr_tweaked(output_key);
        Address::from_witness_program(program, hrp)
    }

    /// Creates an address from an arbitrary witness program.
    ///
    /// This only exists to support future witness versions. If you are doing normal mainnet things
    /// then you likely do not need this constructor.
    pub fn from_witness_program(program: WitnessProgram, hrp: impl Into<KnownHrp>) -> Address {
        let inner = AddressInner::Segwit { program, hrp: hrp.into() };
        Address(inner, PhantomData)
    }

    /// Gets the address type of the address.
    ///
    /// # Returns
    ///
    /// None if unknown, non-standard or related to the future witness version.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> {
        match self.0 {
            AddressInner::P2pkh { .. } => Some(AddressType::P2pkh),
            AddressInner::P2sh { .. } => Some(AddressType::P2sh),
            AddressInner::Segwit { ref program, hrp: _ } =>
                if program.is_p2wpkh() {
                    Some(AddressType::P2wpkh)
                } else if program.is_p2wsh() {
                    Some(AddressType::P2wsh)
                } else if program.is_p2tr() {
                    Some(AddressType::P2tr)
                } else {
                    None
                },
        }
    }

    /// Gets the address data from this address.
    pub fn to_address_data(&self) -> AddressData {
        use AddressData::*;

        match self.0 {
            AddressInner::P2pkh { hash, network: _ } => P2pkh { pubkey_hash: hash },
            AddressInner::P2sh { hash, network: _ } => P2sh { script_hash: hash },
            AddressInner::Segwit { program, hrp: _ } => Segwit { witness_program: program },
        }
    }

    /// Gets the pubkey hash for this address if this is a P2PKH address.
    pub fn pubkey_hash(&self) -> Option<PubkeyHash> {
        use AddressInner::*;

        match self.0 {
            P2pkh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the script hash for this address if this is a P2SH address.
    pub fn script_hash(&self) -> Option<ScriptHash> {
        use AddressInner::*;

        match self.0 {
            P2sh { ref hash, network: _ } => Some(*hash),
            _ => None,
        }
    }

    /// Gets the witness program for this address if this is a segwit address.
    pub fn witness_program(&self) -> Option<WitnessProgram> {
        use AddressInner::*;

        match self.0 {
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

    /// Constructs an [`Address`] from an output script (`scriptPubkey`).
    pub fn from_script(script: &Script, params: impl AsRef<Params>) -> Result<Address, FromScriptError> {
        let network = params.as_ref().network;
        if script.is_p2pkh() {
            let bytes = script.as_bytes()[3..23].try_into().expect("statically 20B long");
            let hash = PubkeyHash::from_byte_array(bytes);
            Ok(Address::p2pkh(hash, network))
        } else if script.is_p2sh() {
            let bytes = script.as_bytes()[2..22].try_into().expect("statically 20B long");
            let hash = ScriptHash::from_byte_array(bytes);
            Ok(Address::p2sh_from_hash(hash, network))
        } else if script.is_witness_program() {
            let opcode = script.first_opcode().expect("is_witness_program guarantees len > 4");

            let version = WitnessVersion::try_from(opcode)?;
            let program = WitnessProgram::new(version, &script.as_bytes()[2..])?;
            Ok(Address::from_witness_program(program, network))
        } else {
            Err(FromScriptError::UnrecognizedScript)
        }
    }

    /// Generates a script pubkey spending to this address.
    pub fn script_pubkey(&self) -> ScriptBuf {
        use AddressInner::*;
        match self.0 {
            P2pkh { ref hash, network: _ } => ScriptBuf::new_p2pkh(hash),
            P2sh { ref hash, network: _ } => ScriptBuf::new_p2sh(hash),
            Segwit { ref program, hrp: _ } => {
                let prog = program.program();
                let version = program.version();
                ScriptBuf::new_witness_program_unchecked(version, prog)
            }
        }
    }

    /// Creates a URI string *bitcoin:address* optimized to be encoded in QR codes.
    ///
    /// If the address is bech32, the address becomes uppercase.
    /// If the address is base58, the address is left mixed case.
    ///
    /// Quoting BIP 173 "inside QR codes uppercase SHOULD be used, as those permit the use of
    /// alphanumeric mode, which is 45% more compact than the normal byte mode."
    ///
    /// Note however that despite BIP21 explicitly stating that the `bitcoin:` prefix should be
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
    pub fn to_qr_uri(&self) -> String { format!("bitcoin:{:#}", self) }

    /// Returns true if the given pubkey is directly related to the address payload.
    ///
    /// This is determined by directly comparing the address payload with either the
    /// hash of the given public key or the segwit redeem hash generated from the
    /// given key. For taproot addresses, the supplied key is assumed to be tweaked
    pub fn is_related_to_pubkey(&self, pubkey: &PublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload_as_bytes();
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);

        (*pubkey_hash.as_byte_array() == *payload)
            || (xonly_pubkey.serialize() == *payload)
            || (*segwit_redeem_hash(&pubkey_hash).as_byte_array() == *payload)
    }

    /// Returns true if the supplied xonly public key can be used to derive the address.
    ///
    /// This will only work for Taproot addresses. The Public Key is
    /// assumed to have already been tweaked.
    pub fn is_related_to_xonly_pubkey(&self, xonly_pubkey: &XOnlyPublicKey) -> bool {
        xonly_pubkey.serialize() == *self.payload_as_bytes()
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script: &Script) -> bool {
        use AddressInner::*;
        match self.0 {
            P2pkh { ref hash, network: _ } if script.is_p2pkh() =>
                &script.as_bytes()[3..23] == <PubkeyHash as AsRef<[u8; 20]>>::as_ref(hash),
            P2sh { ref hash, network: _ } if script.is_p2sh() =>
                &script.as_bytes()[2..22] == <ScriptHash as AsRef<[u8; 20]>>::as_ref(hash),
            Segwit { ref program, hrp: _ } if script.is_witness_program() =>
                &script.as_bytes()[2..] == program.program().as_bytes(),
            P2pkh { .. } | P2sh { .. } | Segwit { .. } => false,
        }
    }

    /// Returns the "payload" for this address.
    ///
    /// The "payload" is the useful stuff excluding serialization prefix, the exact payload is
    /// dependent on the inner address:
    ///
    /// - For p2sh, the payload is the script hash.
    /// - For p2pkh, the payload is the pubkey hash.
    /// - For segwit addresses, the payload is the witness program.
    fn payload_as_bytes(&self) -> &[u8] {
        use AddressInner::*;
        match self.0 {
            P2sh { ref hash, network: _ } => hash.as_ref(),
            P2pkh { ref hash, network: _ } => hash.as_ref(),
            Segwit { ref program, hrp: _ } => program.program().as_bytes(),
        }
    }
}

/// Methods that can be called only on `Address<NetworkUnchecked>`.
impl Address<NetworkUnchecked> {
    /// Returns a reference to the checked address.
    ///
    /// This function is dangerous in case the address is not a valid checked address.
    pub fn assume_checked_ref(&self) -> &Address {
        unsafe { &*(self as *const Address<NetworkUnchecked> as *const Address) }
    }

    /// Parsed addresses do not always have *one* network. The problem is that legacy testnet,
    /// regtest and signet addresse use the same prefix instead of multiple different ones. When
    /// parsing, such addresses are always assumed to be testnet addresses (the same is true for
    /// bech32 signet addresses). So if one wants to check if an address belongs to a certain
    /// network a simple comparison is not enough anymore. Instead this function can be used.
    ///
    /// ```rust
    /// use bitcoin::{Address, Network};
    /// use bitcoin::address::NetworkUnchecked;
    ///
    /// let address: Address<NetworkUnchecked> = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Testnet));
    /// assert!(address.is_valid_for_network(Network::Regtest));
    /// assert!(address.is_valid_for_network(Network::Signet));
    ///
    /// assert_eq!(address.is_valid_for_network(Network::Bitcoin), false);
    ///
    /// let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Bitcoin));
    /// assert_eq!(address.is_valid_for_network(Network::Testnet), false);
    /// ```
    pub fn is_valid_for_network(&self, n: Network) -> bool {
        use AddressInner::*;
        match self.0 {
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
    pub fn assume_checked(self) -> Address {
        use AddressInner::*;

        let inner = match self.0 {
            P2pkh { hash, network } => P2pkh { hash, network },
            P2sh { hash, network } => P2sh { hash, network },
            Segwit { program, hrp } => Segwit { program, hrp },
        };
        Address(inner, PhantomData)
    }
}

impl From<Address> for script::ScriptBuf {
    fn from(a: Address) -> Self { a.script_pubkey() }
}

// Alternate formatting `{:#}` is used to return uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, fmt) }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            fmt::Display::fmt(&self.0, f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            fmt::Display::fmt(&self.0, f)?;
            write!(f, ")")
        }
    }
}

/// Address can be parsed only with `NetworkUnchecked`.
impl FromStr for Address<NetworkUnchecked> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Address<NetworkUnchecked>, ParseError> {
        if let Ok((hrp, witness_version, data)) = bech32::segwit::decode(s) {
            let version = WitnessVersion::try_from(witness_version)?;
            let program = WitnessProgram::new(version, &data)
                .expect("bech32 guarantees valid program length for witness");

            let hrp = KnownHrp::from_hrp(hrp)?;
            let inner = AddressInner::Segwit { program, hrp };
            return Ok(Address(inner, PhantomData));
        }

        // If segwit decoding fails, assume its a legacy address.

        if s.len() > 50 {
            return Err(LegacyAddressTooLongError { length: s.len() }.into());
        }
        let data = base58::decode_check(s)?;
        if data.len() != 21 {
            return Err(InvalidBase58PayloadLengthError { length: s.len() }.into());
        }

        let (prefix, data) = data.split_first().expect("length checked above");
        let data: [u8; 20] = data.try_into().expect("length checked above");

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

        Ok(Address(inner, PhantomData))
    }
}

/// Convert a byte array of a pubkey hash into a segwit redeem hash
fn segwit_redeem_hash(pubkey_hash: &PubkeyHash) -> crate::hashes::hash160::Hash {
    let mut sha_engine = sha256::Hash::engine();
    sha_engine.input(&[0, 20]);
    sha_engine.input(pubkey_hash.as_ref());
    crate::hashes::hash160::Hash::from_engine(sha_engine)
}

#[cfg(test)]
mod tests {
    use hex_lit::hex;

    use super::*;
    use crate::consensus::params;
    use crate::network::Network::{Bitcoin, Testnet};

    fn roundtrips(addr: &Address, network: Network) {
        assert_eq!(
            Address::from_str(&addr.to_string()).unwrap().assume_checked(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), network)
                .expect("failed to create inner address from script_pubkey"),
            *addr,
            "script round-trip failed for {}",
            addr,
        );

        #[cfg(feature = "serde")]
        {
            let ser = serde_json::to_string(addr).expect("failed to serialize address");
            let back: Address<NetworkUnchecked> =
                serde_json::from_str(&ser).expect("failed to deserialize address");
            assert_eq!(back.assume_checked(), *addr, "serde round-trip failed for {}", addr)
        }
    }

    #[test]
    fn test_p2pkh_address_58() {
        let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<PubkeyHash>().unwrap();
        let addr = Address::p2pkh(hash, NetworkKind::Main);

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac").unwrap()
        );
        assert_eq!(&addr.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2pkh_from_key() {
        let key = "048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183".parse::<PublicKey>().unwrap();
        let addr = Address::p2pkh(key, NetworkKind::Main);
        assert_eq!(&addr.to_string(), "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY");

        let key = "03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f"
            .parse::<PublicKey>()
            .unwrap();
        let addr = Address::p2pkh(key, NetworkKind::Test);
        assert_eq!(&addr.to_string(), "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr, Testnet);
    }

    #[test]
    fn test_p2sh_address_58() {
        let hash = "162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse::<ScriptHash>().unwrap();
        let addr = Address::p2sh_from_hash(hash, NetworkKind::Main);

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087").unwrap(),
        );
        assert_eq!(&addr.to_string(), "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2sh_parse() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae").unwrap();
        let addr = Address::p2sh(&script, NetworkKind::Test).unwrap();
        assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Testnet);
    }

    #[test]
    fn test_p2sh_parse_for_large_script() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123").unwrap();
        assert_eq!(Address::p2sh(&script, NetworkKind::Test), Err(P2shError::ExcessiveScriptSize));
    }

    #[test]
    fn test_p2wpkh() {
        // stolen from Bitcoin transaction: b3c8c2b6cfc335abbcb2c7823a8453f55d64b2b5125a9a61e8737230cdb8ce20
        let key = "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let addr = Address::p2wpkh(&key, KnownHrp::Mainnet);
        assert_eq!(&addr.to_string(), "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw");
        assert_eq!(addr.address_type(), Some(AddressType::P2wpkh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2wsh() {
        // stolen from Bitcoin transaction 5df912fda4becb1c29e928bec8d64d93e9ba8efa9b5b405bd683c86fd2c65667
        let script = ScriptBuf::from_hex("52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae").unwrap();
        let addr = Address::p2wsh(&script, KnownHrp::Mainnet);
        assert_eq!(
            &addr.to_string(),
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
        );
        assert_eq!(addr.address_type(), Some(AddressType::P2wsh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2shwpkh() {
        // stolen from Bitcoin transaction: ad3fd9c6b52e752ba21425435ff3dd361d6ac271531fc1d2144843a9f550ad01
        let key = "026c468be64d22761c30cd2f12cbc7de255d592d7904b1bab07236897cc4c2e766"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let addr = Address::p2shwpkh(&key, NetworkKind::Main);
        assert_eq!(&addr.to_string(), "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_p2shwsh() {
        // stolen from Bitcoin transaction f9ee2be4df05041d0e0a35d7caa3157495ca4f93b233234c9967b6901dacf7a9
        let script = ScriptBuf::from_hex("522103e5529d8eaa3d559903adb2e881eb06c86ac2574ffa503c45f4e942e2a693b33e2102e5f10fcdcdbab211e0af6a481f5532536ec61a5fdbf7183770cf8680fe729d8152ae").unwrap();
        let addr = Address::p2shwsh(&script, NetworkKind::Main);
        assert_eq!(&addr.to_string(), "36EqgNnsWW94SreZgBWc1ANC6wpFZwirHr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_non_existent_segwit_version() {
        // 40-byte program
        let program = hex!(
            "654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4"
        );
        let program = WitnessProgram::new(WitnessVersion::V13, &program).expect("valid program");

        let addr = Address::from_witness_program(program, KnownHrp::Mainnet);
        roundtrips(&addr, Bitcoin);
    }

    #[test]
    fn test_address_debug() {
        // This is not really testing output of Debug but the ability and proper functioning
        // of Debug derivation on structs generic in NetworkValidation.
        #[derive(Debug)]
        #[allow(unused)]
        struct Test<V: NetworkValidation> {
            address: Address<V>,
        }

        let addr_str = "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k";
        let unchecked = Address::from_str(addr_str).unwrap();

        assert_eq!(
            format!("{:?}", Test { address: unchecked.clone() }),
            format!("Test {{ address: Address<NetworkUnchecked>({}) }}", addr_str)
        );

        assert_eq!(
            format!("{:?}", Test { address: unchecked.assume_checked() }),
            format!("Test {{ address: {} }}", addr_str)
        );
    }

    #[test]
    fn test_address_type() {
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
            // segwit v1 and len != 32
            ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", None),
            // segwit v2
            ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", None),
        ];
        for (address, expected_type) in &addresses {
            let addr = Address::from_str(address)
                .unwrap()
                .require_network(Network::Bitcoin)
                .expect("mainnet");
            assert_eq!(&addr.address_type(), expected_type);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_json_serialize() {
        use serde_json;

        let addr =
            Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac").unwrap()
        );

        let addr =
            Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087").unwrap()
        );

        let addr: Address<NetworkUnchecked> =
            Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
                .unwrap();
        let json = serde_json::to_value(addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
            )
        );

        let addr =
            Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
                .unwrap()
                .assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
            )
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex(
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
            )
            .unwrap()
        );

        let addr = Address::from_str("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl")
            .unwrap()
            .assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("001454d26dddb59c7073c6a197946ea1841951fa7a74").unwrap()
        );
    }

    #[test]
    fn test_qr_string() {
        for el in
            ["132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM", "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k"].iter()
        {
            let addr =
                Address::from_str(el).unwrap().require_network(Network::Bitcoin).expect("mainnet");
            assert_eq!(addr.to_qr_uri(), format!("bitcoin:{}", el));
        }

        for el in [
            "bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl",
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
        ]
        .iter()
        {
            let addr = Address::from_str(el).unwrap().assume_checked();
            assert_eq!(addr.to_qr_uri(), format!("bitcoin:{}", el.to_ascii_uppercase()));
        }
    }

    #[test]
    fn p2tr_from_untweaked() {
        //Test case from BIP-086
        let internal_key = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        let secp = Secp256k1::verification_only();
        let address = Address::p2tr(&secp, internal_key, None, KnownHrp::Mainnet);
        assert_eq!(
            address.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(address.address_type(), Some(AddressType::P2tr));
        roundtrips(&address, Bitcoin);
    }

    #[test]
    fn test_is_related_to_pubkey_p2wpkh() {
        let address_string = "bc1qhvd6suvqzjcu9pxjhrwhtrlj85ny3n2mqql5w4";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2shwpkh() {
        let address_string = "3EZQk4F8GURH5sqVMLTFisD17yNeKa7Dfs";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh() {
        let address_string = "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Bitcoin)
            .expect("mainnet");

        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh_uncompressed_key() {
        let address_string = "msvS7KzhReCDpQEJaV2hmGNvuQqVUDuC6p";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Testnet)
            .expect("testnet");

        let pubkey_string = "04e96e22004e3db93530de27ccddfdf1463975d2138ac018fc3e7ba1a2e5e0aad8e424d0b55e2436eb1d0dcd5cb2b8bcc6d53412c22f358de57803a6a655fbbd04";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2tr() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

        assert_eq!(
            address,
            Address::from_str("bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e")
                .expect("address")
                .require_network(Network::Bitcoin)
                .expect("mainnet")
        );

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey));
    }

    #[test]
    fn test_is_related_to_xonly_pubkey() {
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
        let address = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Mainnet);

        assert_eq!(
            address,
            Address::from_str("bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e")
                .expect("address")
                .require_network(Network::Bitcoin)
                .expect("mainnet")
        );

        let result = address.is_related_to_xonly_pubkey(&xonly_pubkey);
        assert!(result);
    }

    #[test]
    fn test_fail_address_from_script() {
        use crate::witness_program;

        let bad_p2wpkh = ScriptBuf::from_hex("0014dbc5b0a8f9d4353b4b54c3db48846bb15abfec").unwrap();
        let bad_p2wsh = ScriptBuf::from_hex(
            "00202d4fa2eb233d008cc83206fa2f4f2e60199000f5b857a835e3172323385623",
        )
        .unwrap();
        let invalid_segwitv0_script =
            ScriptBuf::from_hex("001161458e330389cd0437ee9fe3641d70cc18").unwrap();
        let expected = Err(FromScriptError::UnrecognizedScript);

        assert_eq!(Address::from_script(&bad_p2wpkh, Network::Bitcoin), expected);
        assert_eq!(Address::from_script(&bad_p2wsh, Network::Bitcoin), expected);
        assert_eq!(
            Address::from_script(&invalid_segwitv0_script, &params::MAINNET),
            Err(FromScriptError::WitnessProgram(witness_program::Error::InvalidSegwitV0Length(17)))
        );
    }

    #[test]
    fn valid_address_parses_correctly() {
        let addr = AddressType::from_str("p2tr").expect("false negative while parsing address");
        assert_eq!(addr, AddressType::P2tr);
    }

    #[test]
    fn invalid_address_parses_error() {
        let got = AddressType::from_str("invalid");
        let want = Err(UnknownAddressTypeError("invalid".to_string()));
        assert_eq!(got, want);
    }

    #[test]
    fn test_matches_script_pubkey() {
        let addresses = [
            "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY",
            "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx",
            "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k",
            "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE",
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw",
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            "bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e",
        ];
        for addr in &addresses {
            let addr = Address::from_str(addr).unwrap().require_network(Network::Bitcoin).unwrap();
            for another in &addresses {
                let another =
                    Address::from_str(another).unwrap().require_network(Network::Bitcoin).unwrap();
                assert_eq!(addr.matches_script_pubkey(&another.script_pubkey()), addr == another);
            }
        }
    }
}
