//! Implements an example PSBT workflow.
//!
//! The workflow we simulate is that of a setup using a watch-only online wallet (contains only
//! public keys) and a cold-storage signing wallet (contains the private keys).
//!
//! You can verify the workflow using `bitcoind` and `bitcoin-cli`.
//!
//! ## Example Setup
//!
//! 1. Start Bitcoin Core in Regtest mode, for example:
//!
//!    `bitcoind -regtest -server -daemon -fallbackfee=0.0002 -rpcuser=admin -rpcpassword=pass -rpcallowip=127.0.0.1/0 -rpcbind=127.0.0.1 -blockfilterindex=1 -peerblockfilters=1`
//!
//! 2. Define a shell alias to `bitcoin-cli`, for example:
//!
//!    `alias bt=bitcoin-cli -rpcuser=admin -rpcpassword=pass -rpcport=18443`
//!
//! 3. Create (or load) a default wallet, for example:
//!
//!    `bt createwallet <wallet-name>`
//!
//! 4. Mine some blocks, for example:
//!
//!    `bt generatetoaddress 110 $(bt getnewaddress)`
//!
//! 5. Get the details for a UTXO to fund the PSBT with:
//!
//!    `bt listunspent`
//!

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use bitcoin::consensus::encode;
use bitcoin::hashes::hex::{self, FromHex};
use bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use bitcoin::util::address;
use bitcoin::util::amount::ParseAmountError;
use bitcoin::util::bip32::{
    self, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint,
    IntoDerivationPath,
};
use bitcoin::util::psbt::{self, Input, Psbt, PsbtSighashType};
use bitcoin::{
    Address, Amount, Network, OutPoint, PackedLockTime, PrivateKey, PublicKey, Script, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};

use self::psbt_sign::*;

type Result<T> = std::result::Result<T, Error>;

// Get this from the output of `bt dumpwallet <file>`.
const EXTENDED_MASTER_PRIVATE_KEY: &str = "tprv8ZgxMBicQKsPeSHZFZWT8zxie2dXWcwemnTkf4grVzMvP2UABUxqbPTCHzZ4ztwhBghpfFw27sJqEgW6y1ZTZcfvCUdtXE1L6qMF7TBdbqQ";

// Set these with valid data from output of step 5 above. Please note, input utxo must be a p2wpkh.
const INPUT_UTXO_TXID: &str = "295f06639cde6039bf0c3dbf4827f0e3f2b2c2b476408e2f9af731a8d7a9c7fb";
const INPUT_UTXO_VOUT: u32 = 0;
const INPUT_UTXO_SCRIPT_PUBKEY: &str = "00149891eeb8891b3e80a2a1ade180f143add23bf5de";
const INPUT_UTXO_VALUE: &str = "50 BTC";
// Get this from the desciptor,
// "wpkh([97f17dca/0'/0'/0']02749483607dafb30c66bd93ece4474be65745ce538c2d70e8e246f17e7a4e0c0c)#m9n56cx0".
const INPUT_UTXO_DERIVATION_PATH: &str = "m/0h/0h/0h";

// Grab an address to receive on: `bt generatenewaddress` (obviously contrived but works as an example).
const RECEIVE_ADDRESS: &str = "bcrt1qcmnpjjjw78yhyjrxtql6lk7pzpujs3h244p7ae"; // The address to receive the coins we send.

// These should be correct if the UTXO above should is for 50 BTC.
const OUTPUT_AMOUNT_BTC: &str = "1 BTC";
const CHANGE_AMOUNT_BTC: &str = "48.99999 BTC"; // 1000 sat transaction fee.

const NETWORK: Network = Network::Regtest;

fn main() -> Result<()> {
    let secp = Secp256k1::new();

    let (offline, fingerprint, account_0_xpub, input_xpub) =
        ColdStorage::new(&secp, EXTENDED_MASTER_PRIVATE_KEY)?;

    let online = WatchOnly::new(account_0_xpub, input_xpub, fingerprint);

    let created = online.create_psbt(&secp)?;
    let updated = online.update_psbt(created)?;

    let signed = offline.sign_psbt(&secp, updated)?;

    let finalized = online.finalize_psbt(signed)?;

    // You can use `bt sendrawtransaction` to broadcast the extracted transaction.
    let tx = finalized.extract_tx();
    tx.verify(|_| Some(previous_output())).expect("failed to verify transaction");

    let hex = encode::serialize_hex(&tx);
    println!("You should now be able to broadcast the following transaction: \n\n{}", hex);

    Ok(())
}

// We cache the pubkeys for convenience because it requires a scep context to convert the private key.
/// An example of an offline signer i.e., a cold-storage device.
struct ColdStorage {
    /// The master extended private key.
    master_xpriv: ExtendedPrivKey,
    /// The master extended public key.
    master_xpub: ExtendedPubKey,
}

/// The data exported from an offline wallet to enable creation of a watch-only online wallet.
/// (wallet, fingerprint, account_0_xpub, input_utxo_xpub)
type ExportData = (ColdStorage, Fingerprint, ExtendedPubKey, ExtendedPubKey);

impl ColdStorage {
    /// Constructs a new `ColdStorage` signer.
    ///
    /// # Returns
    ///
    /// The newly created signer along with the data needed to configure a watch-only wallet.
    fn new<C: Signing>(secp: &Secp256k1<C>, xpriv: &str) -> Result<ExportData> {
        let master_xpriv = ExtendedPrivKey::from_str(xpriv)?;
        let master_xpub = ExtendedPubKey::from_priv(secp, &master_xpriv);

        // Hardened children require secret data to derive.

        let path = "m/84h/0h/0h".into_derivation_path()?;
        let account_0_xpriv = master_xpriv.derive_priv(secp, &path)?;
        let account_0_xpub = ExtendedPubKey::from_priv(secp, &account_0_xpriv);

        let path = INPUT_UTXO_DERIVATION_PATH.into_derivation_path()?;
        let input_xpriv = master_xpriv.derive_priv(secp, &path)?;
        let input_xpub = ExtendedPubKey::from_priv(secp, &input_xpriv);

        let wallet = ColdStorage { master_xpriv, master_xpub };
        let fingerprint = wallet.master_fingerprint();

        Ok((wallet, fingerprint, account_0_xpub, input_xpub))
    }

    /// Returns the fingerprint for the master extended public key.
    fn master_fingerprint(&self) -> Fingerprint { self.master_xpub.fingerprint() }

    /// Signs `psbt` with this signer.
    fn sign_psbt<C: Signing>(&self, secp: &Secp256k1<C>, mut psbt: Psbt) -> Result<Psbt> {
        let sk = self.private_key_to_sign(secp, &psbt.inputs[0])?;
        psbt_sign::sign(&mut psbt, &sk, 0, secp)?;

        Ok(psbt)
    }

    /// Returns the private key required to sign `input` if we have it.
    fn private_key_to_sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        input: &Input,
    ) -> Result<PrivateKey> {
        match input.bip32_derivation.iter().next() {
            Some((pk, (fingerprint, path))) => {
                if *fingerprint != self.master_fingerprint() {
                    return Err(Error::WrongFingerprint);
                }

                let sk = self.master_xpriv.derive_priv(secp, &path)?.to_priv();
                if *pk != sk.public_key(secp).inner {
                    return Err(Error::WrongPubkey);
                }

                Ok(sk)
            }
            None => Err(Error::MissingBip32Derivation),
        }
    }
}

/// An example of an watch-only online wallet.
struct WatchOnly {
    /// The xpub for account 0 derived from derivation path "m/84h/0h/0h".
    account_0_xpub: ExtendedPubKey,
    /// The xpub derived from `INPUT_UTXO_DERIVATION_PATH`.
    input_xpub: ExtendedPubKey,
    /// The master extended pubkey fingerprint.
    master_fingerprint: Fingerprint,
}

impl WatchOnly {
    /// Constructs a new watch-only wallet.
    ///
    /// A watch-only wallet would typically be online and connected to the Bitcoin network. We
    /// 'import' into the wallet the `account_0_xpub` and `master_fingerprint`.
    ///
    /// The reason for importing the `input_xpub` is so one can use bitcoind to grab a valid input
    /// to verify the workflow presented in this file.
    fn new(
        account_0_xpub: ExtendedPubKey,
        input_xpub: ExtendedPubKey,
        master_fingerprint: Fingerprint,
    ) -> Self {
        WatchOnly { account_0_xpub, input_xpub, master_fingerprint }
    }

    /// Creates the PSBT, in BIP174 parlance this is the 'Creater'.
    fn create_psbt<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<Psbt> {
        let to_address = Address::from_str(RECEIVE_ADDRESS)?;
        let to_amount = Amount::from_str(OUTPUT_AMOUNT_BTC)?;

        let (_, change_address, _) = self.change_address(secp)?;
        let change_amount = Amount::from_str(CHANGE_AMOUNT_BTC)?;

        let tx = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_hex(INPUT_UTXO_TXID)?,
                    vout: INPUT_UTXO_VOUT,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX, // Disable LockTime and RBF.
                witness: Witness::default(),
            }],
            output: vec![
                TxOut { value: to_amount.to_sat(), script_pubkey: to_address.script_pubkey() },
                TxOut {
                    value: change_amount.to_sat(),
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
        };

        let psbt = Psbt::from_unsigned_tx(tx)?;

        Ok(psbt)
    }

    /// Updates the PSBT, in BIP174 parlance this is the 'Updater'.
    fn update_psbt(&self, mut psbt: Psbt) -> Result<Psbt> {
        let mut input = Input { witness_utxo: Some(previous_output()), ..Default::default() };

        let pk = self.input_xpub.to_pub();
        let wpkh = pk.wpubkey_hash().expect("a compressed pubkey");

        let redeem_script = Script::new_v0_p2wpkh(&wpkh);
        input.redeem_script = Some(redeem_script);

        let fingerprint = self.master_fingerprint;
        let path = input_derivation_path()?;
        let mut map = BTreeMap::new();
        map.insert(pk.inner, (fingerprint, path));
        input.bip32_derivation = map;

        let ty = PsbtSighashType::from_str("SIGHASH_ALL").map_err(|_| Error::SighashTypeParse)?;
        input.sighash_type = Some(ty);

        psbt.inputs = vec![input];

        Ok(psbt)
    }

    /// Finalizes the PSBT, in BIP174 parlance this is the 'Finalizer'.
    fn finalize_psbt(&self, mut psbt: Psbt) -> Result<Psbt> {
        use bitcoin::util::psbt::serialize::Serialize;

        if psbt.inputs.is_empty() {
            return Err(Error::InputsEmpty);
        }

        let sigs: Vec<_> = psbt.inputs[0].partial_sigs.values().collect();

        let mut script_witness: Witness = Witness::new();
        script_witness.push(&sigs[0].serialize());
        script_witness.push(self.input_xpub.to_pub().serialize());

        psbt.inputs[0].final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        psbt.inputs[0].partial_sigs = BTreeMap::new();
        psbt.inputs[0].sighash_type = None;
        psbt.inputs[0].redeem_script = None;
        psbt.inputs[0].witness_script = None;
        psbt.inputs[0].bip32_derivation = BTreeMap::new();

        Ok(psbt)
    }

    /// Returns data for the first change address (standard BIP84 derivation path
    /// "m/84h/0h/0h/1/0"). A real wallet would have access to the chain so could determine if an
    /// address has been used or not. We ignore this detail and just re-use the first change address
    /// without loss of generality.
    fn change_address<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<(PublicKey, Address, DerivationPath)> {
        let path = vec![ChildNumber::from_normal_idx(1)?, ChildNumber::from_normal_idx(0)?];
        let derived = self.account_0_xpub.derive_pub(secp, &path)?;

        let pk = derived.to_pub();
        let addr = Address::p2wpkh(&pk, NETWORK)?;
        let path = path.into_derivation_path()?;

        Ok((pk, addr, path))
    }
}

fn input_derivation_path() -> Result<DerivationPath> {
    let path = INPUT_UTXO_DERIVATION_PATH.into_derivation_path()?;
    Ok(path)
}

fn previous_output() -> TxOut {
    let script_pubkey = Script::from_hex(INPUT_UTXO_SCRIPT_PUBKEY)
        .expect("failed to parse input utxo scriptPubkey");
    let amount = Amount::from_str(INPUT_UTXO_VALUE).expect("failed to parse input utxo value");

    TxOut { value: amount.to_sat(), script_pubkey }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Error {
    /// Bip32 error.
    Bip32(bip32::Error),
    /// PSBT error.
    Psbt(psbt::Error),
    /// PSBT sighash error.
    PsbtSighash(SighashError),
    /// Bitcoin_hashes hex error.
    Hex(hex::Error),
    /// Address error.
    Address(address::Error),
    /// Parse amount error.
    ParseAmount(ParseAmountError),
    /// Parsing sighash type string failed.
    SighashTypeParse,
    /// PSBT inputs field is empty.
    InputsEmpty,
    /// BIP32 data missing.
    MissingBip32Derivation,
    /// Fingerprint does not match that in input.
    WrongFingerprint,
    /// Pubkey for derivation path does not match that in input.
    WrongPubkey,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self) }
}

impl From<bip32::Error> for Error {
    fn from(e: bip32::Error) -> Error { Error::Bip32(e) }
}

impl From<psbt::Error> for Error {
    fn from(e: psbt::Error) -> Error { Error::Psbt(e) }
}

impl From<SighashError> for Error {
    fn from(e: SighashError) -> Error { Error::PsbtSighash(e) }
}

impl From<hex::Error> for Error {
    fn from(e: hex::Error) -> Error { Error::Hex(e) }
}

impl From<address::Error> for Error {
    fn from(e: address::Error) -> Error { Error::Address(e) }
}

impl From<ParseAmountError> for Error {
    fn from(e: ParseAmountError) -> Error { Error::ParseAmount(e) }
}

/// This module implements signing a PSBT. It is based on code in `rust-miniscript` with a bit of a
/// look at `bdk` as well. Since this example only uses ECDSA signatures the signing code is
/// sufficient however before we can merge this into the main `rust-bitcoin` crate we need to handle
/// taproot as well. See PR: https://github.com/rust-bitcoin/rust-bitcoin/pull/957
///
/// All functions that take a `psbt` argument should be implemented on `Psbt` and use `self` instead.
mod psbt_sign {
    use std::fmt;
    use std::ops::Deref;

    use bitcoin::psbt::{Input, Prevouts, Psbt, PsbtSighashType};
    use bitcoin::util::sighash::{self, SighashCache};
    use bitcoin::util::taproot::TapLeafHash;
    use bitcoin::{
        EcdsaSig, EcdsaSigError, EcdsaSighashType, PrivateKey, SchnorrSighashType, Script,
        Transaction, TxOut,
    };
    use secp256k1::{Message, Secp256k1, Signing};

    /// Signs the input at `input_index` with private key `sk`.
    pub fn sign<C: Signing>(
        psbt: &mut Psbt,
        sk: &PrivateKey,
        input_index: usize,
        secp: &Secp256k1<C>,
    ) -> Result<(), SighashError> {
        check_index_is_within_bounds(psbt, input_index)?;

        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let (msg, sighash_ty) = sighash(psbt, input_index, &mut cache, None)?;

        let sig = secp.sign_ecdsa(&msg, &sk.inner);

        let mut final_signature = Vec::with_capacity(75);
        final_signature.extend_from_slice(&sig.serialize_der());
        final_signature.push(sighash_ty.to_u32() as u8);

        let pk = sk.public_key(secp);
        psbt.inputs[input_index].partial_sigs.insert(pk, EcdsaSig::from_slice(&final_signature)?);

        Ok(())
    }

    /// Returns the sighash message to sign along with the sighash type.
    fn sighash<T: Deref<Target = Transaction>>(
        psbt: &Psbt,
        input_index: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>,
    ) -> Result<(Message, PsbtSighashType), SighashError> {
        check_index_is_within_bounds(psbt, input_index)?;

        let input = &psbt.inputs[input_index];
        let prevouts = prevouts(psbt)?;

        let utxo = spend_utxo(psbt, input_index)?;
        let script = utxo.script_pubkey.clone(); // scriptPubkey for input spend utxo.

        if script.is_v1_p2tr() {
            return taproot_sighash(input, prevouts, input_index, cache, tapleaf_hash);
        }

        let hash_ty = input
            .sighash_type
            .map(|ty| ty.ecdsa_hash_ty())
            .unwrap_or(Ok(EcdsaSighashType::All))
            .map_err(|_| SighashError::InvalidSighashType)?; // Only support standard sighash types.

        let is_wpkh = script.is_v0_p2wpkh();
        let is_wsh = script.is_v0_p2wsh();

        let is_nested_wpkh = script.is_p2sh()
            && input.redeem_script.as_ref().map(|s| s.is_v0_p2wpkh()).unwrap_or(false);

        let is_nested_wsh = script.is_p2sh()
            && input.redeem_script.as_ref().map(|x| x.is_v0_p2wsh()).unwrap_or(false);

        let is_segwit = is_wpkh || is_wsh || is_nested_wpkh || is_nested_wsh;

        let sighash = if is_segwit {
            if is_wpkh || is_nested_wpkh {
                let script_code = if is_wpkh {
                    Script::p2wpkh_script_code(&script).ok_or(SighashError::NotWpkh)?
                } else {
                    Script::p2wpkh_script_code(input.redeem_script.as_ref().expect("checked above"))
                        .ok_or(SighashError::NotWpkh)?
                };
                cache.segwit_signature_hash(input_index, &script_code, utxo.value, hash_ty)?
            } else {
                let script_code =
                    input.witness_script.as_ref().ok_or(SighashError::MissingWitnessScript)?;
                cache.segwit_signature_hash(input_index, script_code, utxo.value, hash_ty)?
            }
        } else {
            let script_code = if script.is_p2sh() {
                input.redeem_script.as_ref().ok_or(SighashError::MissingRedeemScript)?
            } else {
                &script
            };
            cache.legacy_signature_hash(input_index, script_code, hash_ty.to_u32())?
        };

        Ok((Message::from_slice(&sighash).expect("sighashes are 32 bytes"), hash_ty.into()))
    }

    /// Returns the prevouts for this PSBT.
    fn prevouts(psbt: &Psbt) -> Result<Vec<&TxOut>, SighashError> {
        let len = psbt.inputs.len();
        let mut utxos = Vec::with_capacity(len);

        for i in 0..len {
            utxos.push(spend_utxo(psbt, i)?);
        }

        Ok(utxos)
    }

    /// Returns the spending utxo for this PSBT's input at `input_index`.
    fn spend_utxo(psbt: &Psbt, input_index: usize) -> Result<&TxOut, SighashError> {
        check_index_is_within_bounds(psbt, input_index)?;

        let input = &psbt.inputs[input_index];
        let utxo = if let Some(witness_utxo) = &input.witness_utxo {
            witness_utxo
        } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
            let vout = psbt.unsigned_tx.input[input_index].previous_output.vout;
            &non_witness_utxo.output[vout as usize]
        } else {
            return Err(SighashError::MissingSpendUtxo);
        };
        Ok(utxo)
    }

    /// Checks `input_index` is within bounds for the PSBT `inputs` array and
    /// for the PSBT `unsigned_tx` `input` array.
    fn check_index_is_within_bounds(psbt: &Psbt, input_index: usize) -> Result<(), SighashError> {
        if input_index >= psbt.inputs.len() {
            return Err(SighashError::IndexOutOfBounds(input_index, psbt.inputs.len()));
        }

        if input_index >= psbt.unsigned_tx.input.len() {
            return Err(SighashError::IndexOutOfBounds(input_index, psbt.unsigned_tx.input.len()));
        }

        Ok(())
    }

    /// Returns the sighash message and sighash type for this `input`.
    fn taproot_sighash<T: Deref<Target = Transaction>>(
        input: &Input,
        prevouts: Vec<&TxOut>,
        input_index: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>,
    ) -> Result<(Message, PsbtSighashType), SighashError> {
        // Note that as per PSBT spec we should have access to spent utxos for the transaction. Even
        // if the transaction does not require SIGHASH_ALL, we create `Prevouts::All` for simplicity.
        let prevouts = Prevouts::All(&prevouts);

        let hash_ty = input
            .sighash_type
            .map(|ty| ty.schnorr_hash_ty())
            .unwrap_or(Ok(SchnorrSighashType::Default))
            .map_err(|_e| SighashError::InvalidSighashType)?;

        let sighash = match tapleaf_hash {
            Some(leaf_hash) => cache.taproot_script_spend_signature_hash(
                input_index,
                &prevouts,
                leaf_hash,
                hash_ty,
            )?,
            None => cache.taproot_key_spend_signature_hash(input_index, &prevouts, hash_ty)?,
        };
        let msg = Message::from_slice(&sighash).expect("sighashes are 32 bytes");
        Ok((msg, hash_ty.into()))
    }

    /// Errors encountered while calculating the sighash message.
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
    pub enum SighashError {
        /// Input index out of bounds (actual index, maximum index allowed).
        IndexOutOfBounds(usize, usize),
        /// Missing spending utxo.
        MissingSpendUtxo,
        /// Missing witness script.
        MissingWitnessScript,
        /// Missing Redeem script.
        MissingRedeemScript,
        /// Invalid Sighash type.
        InvalidSighashType,
        /// The `scriptPubkey` is not a P2WPKH script.
        NotWpkh,
        /// Sighash computation error.
        SighashComputation(sighash::Error),
        /// An ECDSA key-related error occurred.
        EcdsaSig(EcdsaSigError),
    }

    impl fmt::Display for SighashError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                SighashError::IndexOutOfBounds(ind, len) => {
                    write!(f, "index {}, psbt input len: {}", ind, len)
                }
                SighashError::MissingSpendUtxo => write!(f, "missing spend utxon in PSBT"),
                SighashError::MissingWitnessScript => write!(f, "missing witness script"),
                SighashError::MissingRedeemScript => write!(f, "missing redeem script"),
                SighashError::InvalidSighashType => write!(f, "invalid sighash type"),
                SighashError::NotWpkh => write!(f, "the scriptPubkey is not a P2WPKH script"),
                // If merged into rust-bitcoin these two should use `write_err!`.
                SighashError::SighashComputation(e) => write!(f, "sighash: {}", e),
                SighashError::EcdsaSig(e) => write!(f, "ecdsa: {}", e),
            }
        }
    }

    impl From<sighash::Error> for SighashError {
        fn from(e: sighash::Error) -> Self { SighashError::SighashComputation(e) }
    }

    impl From<EcdsaSigError> for SighashError {
        fn from(e: EcdsaSigError) -> Self { SighashError::EcdsaSig(e) }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for SighashError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use self::SighashError::*;

            match self {
                IndexOutOfBounds(_, _)
                | MissingSpendUtxo
                | MissingWitnessScript
                | MissingRedeemScript
                | InvalidSighashType
                | NotWpkh => None,
                SighashComputation(e) => Some(e),
                EcdsaSig(e) => Some(e),
            }
        }
    }
}
