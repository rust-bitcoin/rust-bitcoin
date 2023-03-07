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

use std::boxed::Box;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use bitcoin::bip32::{
    ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint, IntoDerivationPath,
};
use bitcoin::consensus::encode;
use bitcoin::locktime::absolute;
use bitcoin::psbt::{self, Input, Psbt, PsbtSighashType};
use bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

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
        match psbt.sign(&self.master_xpriv, secp) {
            Ok(keys) => assert_eq!(keys.len(), 1),
            Err((_, e)) => {
                let e = e.get(&0).expect("at least one error");
                return Err(e.clone().into());
            }
        };
        Ok(psbt)
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
        let to_address = Address::from_str(RECEIVE_ADDRESS)?.require_network(Network::Regtest)?;
        let to_amount = Amount::from_str(OUTPUT_AMOUNT_BTC)?;

        let (_, change_address, _) = self.change_address(secp)?;
        let change_amount = Amount::from_str(CHANGE_AMOUNT_BTC)?;

        let tx = Transaction {
            version: 2,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: INPUT_UTXO_TXID.parse()?, vout: INPUT_UTXO_VOUT },
                script_sig: ScriptBuf::new(),
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

        let redeem_script = ScriptBuf::new_v0_p2wpkh(&wpkh);
        input.redeem_script = Some(redeem_script);

        let fingerprint = self.master_fingerprint;
        let path = input_derivation_path()?;
        let mut map = BTreeMap::new();
        map.insert(pk.inner, (fingerprint, path));
        input.bip32_derivation = map;

        let ty = PsbtSighashType::from_str("SIGHASH_ALL")?;
        input.sighash_type = Some(ty);

        psbt.inputs = vec![input];

        Ok(psbt)
    }

    /// Finalizes the PSBT, in BIP174 parlance this is the 'Finalizer'.
    /// This is just an example. For a production-ready PSBT Finalizer, use [rust-miniscript](https://docs.rs/miniscript/latest/miniscript/psbt/trait.PsbtExt.html#tymethod.finalize)
    fn finalize_psbt(&self, mut psbt: Psbt) -> Result<Psbt> {
        if psbt.inputs.is_empty() {
            return Err(psbt::SignError::MissingInputUtxo.into());
        }

        let sigs: Vec<_> = psbt.inputs[0].partial_sigs.values().collect();
        let mut script_witness: Witness = Witness::new();
        script_witness.push(&sigs[0].to_vec());
        script_witness.push(self.input_xpub.to_pub().to_bytes());

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
        let path = [ChildNumber::from_normal_idx(1)?, ChildNumber::from_normal_idx(0)?];
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
    let script_pubkey = ScriptBuf::from_hex(INPUT_UTXO_SCRIPT_PUBKEY)
        .expect("failed to parse input utxo scriptPubkey");
    let amount = Amount::from_str(INPUT_UTXO_VALUE).expect("failed to parse input utxo value");

    TxOut { value: amount.to_sat(), script_pubkey }
}

struct Error(Box<dyn std::error::Error>);

impl<T: std::error::Error + 'static> From<T> for Error {
    fn from(e: T) -> Self { Error(Box::new(e)) }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Debug::fmt(&self.0, f) }
}
