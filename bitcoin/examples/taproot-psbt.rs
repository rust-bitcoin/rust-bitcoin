//! Example of Taproot PSBT workflow

// We use the alias `alias bt='bitcoin-cli -regtest'` for brevity.

// Step 0 - Wipe the `regtest` data directory to start from a clean slate.

// Step 1 - Run `bitcoind -regtest -daemon` to start the daemon. Bitcoin Core 23.0+ is required.

// Step 2 -
//          2.1) Run `bt -named createwallet wallet_name=benefactor blank=true` to create a blank wallet with the name "benefactor"
//          2.2) Run `bt -named createwallet wallet_name=beneficiary blank=true` to create a blank wallet with the name "beneficiary"
//          2.3) Create the two aliases:
//                  alias bt-benefactor='bitcoin-cli -regtest -rpcwallet=benefactor'
//                  alias bt-beneficiary='bitcoin-cli -regtest -rpcwallet=beneficiary'
//
//          2.4) Import the example descriptors:
//                  bt-benefactor importdescriptors '[
//                     { "desc": "tr(tprv8ZgxMBicQKsPd4arFr7sKjSnKFDVMR2JHw9Y8L9nXN4kiok4u28LpHijEudH3mMYoL4pM5UL9Bgdz2M4Cy8EzfErmU9m86ZTw6hCzvFeTg7/86\'/1\'/0\'/1/*)#jzyeered", "active": true, "timestamp": "now", "internal": true },
//                     { "desc": "tr(tprv8ZgxMBicQKsPd4arFr7sKjSnKFDVMR2JHw9Y8L9nXN4kiok4u28LpHijEudH3mMYoL4pM5UL9Bgdz2M4Cy8EzfErmU9m86ZTw6hCzvFeTg7/86\'/1\'/0\'/0/*)#rkpcykf4", "active": true, "timestamp": "now" }
//                  ]'
//                  bt-beneficiary importdescriptors '[
//                     { "desc": "tr(tprv8ZgxMBicQKsPe72C5c3cugP8b7AzEuNjP4NSC17Dkpqk5kaAmsL6FHwPsVxPpURVqbNwdLAbNqi8Cvdq6nycDwYdKHDjDRYcsMzfshimAUq/86\'/1\'/0\'/1/*)#w4ehwx46", "active": true, "timestamp": "now", "internal": true },
//                     { "desc": "tr(tprv8ZgxMBicQKsPe72C5c3cugP8b7AzEuNjP4NSC17Dkpqk5kaAmsL6FHwPsVxPpURVqbNwdLAbNqi8Cvdq6nycDwYdKHDjDRYcsMzfshimAUq/86\'/1\'/0\'/0/*)#lpuknn9z", "active": true, "timestamp": "now" }
//                  ]'
//
// The xpriv and derivation path from the imported descriptors
const BENEFACTOR_XPRIV_STR: &str = "tprv8ZgxMBicQKsPd4arFr7sKjSnKFDVMR2JHw9Y8L9nXN4kiok4u28LpHijEudH3mMYoL4pM5UL9Bgdz2M4Cy8EzfErmU9m86ZTw6hCzvFeTg7";
const BENEFICIARY_XPRIV_STR: &str = "tprv8ZgxMBicQKsPe72C5c3cugP8b7AzEuNjP4NSC17Dkpqk5kaAmsL6FHwPsVxPpURVqbNwdLAbNqi8Cvdq6nycDwYdKHDjDRYcsMzfshimAUq";
const BIP86_DERIVATION_PATH: &str = "m/86'/1'/0'/0/0";

// Step 3 -
//          Run `bt generatetoaddress 103 $(bt-benefactor getnewaddress '' bech32m)` to generate 103 new blocks
//          with block reward being sent to a newly created P2TR address in the `benefactor` wallet.
//          This will leave us with 3 mature UTXOs that can be spent. Each will be used in a different example below.

// Step 4 - Run `bt-benefactor listunspent` to display our three spendable UTXOs. Check that everything is the same as below
//        - otherwise modify it. The txids should be deterministic on regtest:

const UTXO_SCRIPT_PUBKEY: &str =
    "5120be27fa8b1f5278faf82cab8da23e8761f8f9bd5d5ebebbb37e0e12a70d92dd16";
const UTXO_PUBKEY: &str = "a6ac32163539c16b6b5dbbca01b725b8e8acaa5f821ba42c80e7940062140d19";
const UTXO_MASTER_FINGERPRINT: &str = "e61b318f";
const ABSOLUTE_FEES: Amount = Amount::from_sat_u32(1_000);

// UTXO_1 will be used for spending example 1
const UTXO_1: P2trUtxo = P2trUtxo {
    txid: "a85d89b4666fed622281d3589474aa1f87971b54bd5d9c1899ed2e8e0447cc06",
    vout: 0,
    script_pubkey: UTXO_SCRIPT_PUBKEY,
    pubkey: UTXO_PUBKEY,
    master_fingerprint: UTXO_MASTER_FINGERPRINT,
    amount: Amount::FIFTY_BTC,
    derivation_path: BIP86_DERIVATION_PATH,
};

// UTXO_2 will be used for spending example 2
const UTXO_2: P2trUtxo = P2trUtxo {
    txid: "6f1c1df5862a67f4b6d1cde9a87e3c441b483ba6a140fbec2815f03aa3a5309d",
    vout: 0,
    script_pubkey: UTXO_SCRIPT_PUBKEY,
    pubkey: UTXO_PUBKEY,
    master_fingerprint: UTXO_MASTER_FINGERPRINT,
    amount: Amount::FIFTY_BTC,
    derivation_path: BIP86_DERIVATION_PATH,
};

// UTXO_3 will be used for spending example 3
const UTXO_3: P2trUtxo = P2trUtxo {
    txid: "9795fed5aedca219244a396dfd7bce55c851274418383c3ab43530e3f74e5dcc",
    vout: 0,
    script_pubkey: UTXO_SCRIPT_PUBKEY,
    pubkey: UTXO_PUBKEY,
    master_fingerprint: UTXO_MASTER_FINGERPRINT,
    amount: Amount::FIFTY_BTC,
    derivation_path: BIP86_DERIVATION_PATH,
};

use std::collections::BTreeMap;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::consensus::encode;
use bitcoin::ext::*;
use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_DROP};
use bitcoin::psbt::{self, Input, Output, Psbt, PsbtSighashType};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::{self, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    absolute, script, transaction, Address, Amount, Network, OutPoint, ScriptPubKeyBuf,
    ScriptSigBuf, TapScriptBuf, Transaction, TxIn, TxOut, Witness,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n----------------");
    println!("\nSTART EXAMPLE 1 - P2TR with a BIP-0086 commitment, signed with internal key\n");

    // Just some addresses for outputs from our wallets. Not really important.
    let to_address = "bcrt1p0p3rvwww0v9znrclp00uneq8ytre9kj922v8fxhnezm3mgsmn9usdxaefc"
        .parse::<Address<_>>()?
        .require_network(Network::Regtest)?;
    let change_address = "bcrt1pz449kexzydh2kaypatup5ultru3ej284t6eguhnkn6wkhswt0l7q3a7j76"
        .parse::<Address<_>>()?
        .require_network(Network::Regtest)?;
    let amount_to_send = Amount::ONE_BTC;
    let change_amount = UTXO_1
        .amount
        .checked_sub(amount_to_send)
        .and_then(|x| x.checked_sub(ABSOLUTE_FEES))
        .ok_or("fees more than input amount!")?;

    let tx_hex_string = encode::serialize_hex(&generate_bip86_key_spend_tx(
        // The master extended private key from the descriptor in step 4
        BENEFACTOR_XPRIV_STR.parse::<Xpriv>()?,
        // Set these fields with valid data for the UTXO from step 5 above
        UTXO_1,
        vec![
            TxOut { amount: amount_to_send, script_pubkey: to_address.script_pubkey() },
            TxOut { amount: change_amount, script_pubkey: change_address.script_pubkey() },
        ],
    )?);
    println!(
        "\nYou should now be able to broadcast the following transaction: \n\n{tx_hex_string}"
    );

    println!("\nEND EXAMPLE 1\n");
    println!("----------------\n");

    println!("START EXAMPLE 2 - Script path spending of inheritance UTXO\n");

    {
        let beneficiary = BeneficiaryWallet::new(BENEFICIARY_XPRIV_STR.parse::<Xpriv>()?)?;

        let mut benefactor = BenefactorWallet::new(
            BENEFACTOR_XPRIV_STR.parse::<Xpriv>()?,
            beneficiary.master_xpub(),
        )?;
        let (tx, psbt) = benefactor.create_inheritance_funding_tx(
            absolute::LockTime::from_height(1000).unwrap(),
            UTXO_2,
        )?;
        let tx_hex = encode::serialize_hex(&tx);

        println!("Inheritance funding tx hex:\n\n{tx_hex}");
        // You can now broadcast the transaction hex:
        // bt sendrawtransaction ...
        //
        // And mine a block to confirm the transaction:
        // bt generatetoaddress 1 $(bt-benefactor getnewaddress '' 'bech32m')

        let spending_tx = beneficiary.spend_inheritance(
            psbt,
            absolute::LockTime::from_height(1000).unwrap(),
            to_address,
        )?;
        let spending_tx_hex = encode::serialize_hex(&spending_tx);
        println!("\nInheritance spending tx hex:\n\n{spending_tx_hex}");
        // If you try to broadcast now, the transaction will be rejected as it is timelocked.
        // First mine 900 blocks so we're sure we are over the 1000 block locktime:
        // bt generatetoaddress 900 $(bt-benefactor getnewaddress '' 'bech32m')
        // Then broadcast the transaction with `bt sendrawtransaction ...`
    }

    println!("\nEND EXAMPLE 2\n");
    println!("----------------\n");

    println!("START EXAMPLE 3 - Key path spending of inheritance UTXO\n");

    {
        let beneficiary = BeneficiaryWallet::new(BENEFICIARY_XPRIV_STR.parse::<Xpriv>()?)?;

        let mut benefactor = BenefactorWallet::new(
            BENEFACTOR_XPRIV_STR.parse::<Xpriv>()?,
            beneficiary.master_xpub(),
        )?;
        let (tx, _) = benefactor.create_inheritance_funding_tx(
            absolute::LockTime::from_height(2000).unwrap(),
            UTXO_3,
        )?;
        let tx_hex = encode::serialize_hex(&tx);

        println!("Inheritance funding tx hex:\n\n{tx_hex}");
        // You can now broadcast the transaction hex:
        // bt sendrawtransaction ...
        //
        // And mine a block to confirm the transaction:
        // bt generatetoaddress 1 $(bt-benefactor getnewaddress '' 'bech32m')

        // At some point we may want to extend the locktime further into the future for the beneficiary.
        // We can do this by "refreshing" the inheritance transaction as the benefactor. This effectively
        // spends the inheritance transaction via the key path of the Taproot output, and is not encumbered
        // by the timelock so we can spend it immediately. We set up a new output similar to the first with
        // a locktime that is 'locktime_delta' blocks greater.
        let (tx, _) = benefactor.refresh_tx(1000)?;
        let tx_hex = encode::serialize_hex(&tx);

        println!("\nRefreshed inheritance tx hex:\n\n{tx_hex}\n");

        println!("\nEND EXAMPLE 3\n");
        println!("----------------\n");
    }

    Ok(())
}

struct P2trUtxo<'a> {
    txid: &'a str,
    vout: u32,
    script_pubkey: &'a str,
    pubkey: &'a str,
    master_fingerprint: &'a str,
    amount: Amount,
    derivation_path: &'a str,
}

#[allow(clippy::single_element_loop)]
fn generate_bip86_key_spend_tx(
    master_xpriv: Xpriv,
    input_utxo: P2trUtxo,
    outputs: Vec<TxOut>,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let from_amount = input_utxo.amount;
    let input_pubkey = input_utxo.pubkey.parse::<XOnlyPublicKey>()?;

    // CREATOR + UPDATER
    let tx1 = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: input_utxo.txid.parse()?, vout: input_utxo.vout },
            script_sig: ScriptSigBuf::new(),
            sequence: bitcoin::Sequence(0xFFFFFFFF), // Ignore nSequence.
            witness: Witness::default(),
        }],
        outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx1)?;

    let mut origins = BTreeMap::new();
    origins.insert(
        input_pubkey,
        (
            vec![],
            (
                input_utxo.master_fingerprint.parse::<Fingerprint>()?,
                input_utxo.derivation_path.parse::<DerivationPath>()?,
            ),
        ),
    );

    let mut input = Input {
        witness_utxo: {
            let script_pubkey =
                ScriptPubKeyBuf::from_hex_no_length_prefix(input_utxo.script_pubkey)
                    .expect("failed to parse input utxo scriptPubkey");
            Some(TxOut { amount: from_amount, script_pubkey })
        },
        tap_key_origins: origins,
        ..Default::default()
    };
    let ty = "SIGHASH_ALL".parse::<PsbtSighashType>()?;
    input.sighash_type = Some(ty);
    input.tap_internal_key = Some(input_pubkey);
    psbt.inputs = vec![input];

    // The `Prevouts::All` array is used to create the sighash to sign for each input in the
    // `psbt.inputs` array, as such it must be the same length and in the same order as the inputs.
    let mut input_txouts = Vec::<TxOut>::new();
    for input in [&input_utxo].iter() {
        input_txouts.push(TxOut {
            amount: input.amount,
            script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix(input.script_pubkey)?,
        });
    }

    // SIGNER
    let unsigned_tx = psbt.unsigned_tx.clone();
    psbt.inputs.iter_mut().enumerate().try_for_each::<_, Result<(), Box<dyn std::error::Error>>>(
        |(vout, input)| {
            let sighash_type = input
                .sighash_type
                .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
                .unwrap_or(TapSighashType::All);
            let hash = SighashCache::new(&unsigned_tx).taproot_key_spend_signature_hash(
                vout,
                &sighash::Prevouts::All(input_txouts.as_slice()),
                sighash_type,
            )?;

            let (_, (_, derivation_path)) = input
                .tap_key_origins
                .get(&input.tap_internal_key.ok_or("internal key missing in PSBT")?)
                .ok_or("missing Taproot key origin")?;

            let secret_key = master_xpriv.derive_xpriv(derivation_path)?.to_private_key().inner;
            sign_psbt_taproot(
                secret_key,
                input.tap_internal_key.unwrap(),
                None,
                input,
                hash,
                sighash_type,
            );

            Ok(())
        },
    )?;

    // FINALIZER
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        input.final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });

    // EXTRACTOR
    let tx = psbt.extract_tx_unchecked_fee_rate();
    tx.verify(|_| {
        Some(TxOut {
            amount: from_amount,
            script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix(input_utxo.script_pubkey)
                .unwrap(),
        })
    })
    .expect("failed to verify transaction");

    Ok(tx)
}

/// A wallet that allows creating and spending from an inheritance directly via the key path for purposes
/// of refreshing the inheritance timelock or changing other spending conditions.
struct BenefactorWallet {
    master_xpriv: Xpriv,
    beneficiary_xpub: Xpub,
    current_spend_info: Option<TaprootSpendInfo>,
    next_psbt: Option<Psbt>,
    next: ChildNumber,
}

impl BenefactorWallet {
    fn new(
        master_xpriv: Xpriv,
        beneficiary_xpub: Xpub,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            master_xpriv,
            beneficiary_xpub,
            current_spend_info: None,
            next_psbt: None,
            next: ChildNumber::ZERO_NORMAL,
        })
    }

    fn time_lock_script(
        locktime: absolute::LockTime,
        beneficiary_key: XOnlyPublicKey,
    ) -> TapScriptBuf {
        script::Builder::new()
            .push_lock_time(locktime)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_x_only_key(beneficiary_key)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn create_inheritance_funding_tx(
        &mut self,
        lock_time: absolute::LockTime,
        input_utxo: P2trUtxo,
    ) -> Result<(Transaction, Psbt), Box<dyn std::error::Error>> {
        if let ChildNumber::Normal { index } = self.next {
            if index > 0 && self.current_spend_info.is_some() {
                return Err(
                    "transaction already exists, use refresh_tx to refresh the timelock".into()
                );
            }
        }
        // We use some other derivation path in this example for our inheritance protocol. The important thing is to ensure
        // that we use an unhardened path so we can make use of xpubs.
        let derivation_path = format!("101/1/0/0/{}", self.next).parse::<DerivationPath>()?;
        let internal_keypair = self
            .master_xpriv
            .derive_xpriv(&derivation_path)
            .expect("derivation path is short")
            .to_keypair();
        let beneficiary_key =
            self.beneficiary_xpub.derive_xpub(&derivation_path)?.to_x_only_public_key();

        // Build up the leaf script and combine with internal key into a Taproot commitment
        let script = Self::time_lock_script(lock_time, beneficiary_key);
        let leaf_hash = script.tapscript_leaf_hash();

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(internal_keypair.x_only_public_key().0)
            .expect("should be finalizable");
        self.current_spend_info = Some(taproot_spend_info.clone());
        let script_pubkey = ScriptPubKeyBuf::new_p2tr(
            taproot_spend_info.internal_key(),
            taproot_spend_info.merkle_root(),
        );
        let amount = (input_utxo.amount - ABSOLUTE_FEES)
            .expect("ABSOLUTE_FEES must be set below input amount");

        // Spend a normal BIP-0086-like output as an input in our inheritance funding transaction
        let tx = generate_bip86_key_spend_tx(
            self.master_xpriv,
            input_utxo,
            vec![TxOut { script_pubkey: script_pubkey.clone(), amount }],
        )?;

        // CREATOR + UPDATER
        let next_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: tx.compute_txid(), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: bitcoin::Sequence(0xFFFFFFFD), // enable locktime and opt-in RBF
                witness: Witness::default(),
            }],
            outputs: vec![],
        };
        let mut next_psbt = Psbt::from_unsigned_tx(next_tx)?;
        let mut origins = BTreeMap::new();
        origins.insert(
            beneficiary_key,
            (vec![leaf_hash], (self.beneficiary_xpub.fingerprint(), derivation_path.clone())),
        );
        origins.insert(
            internal_keypair.x_only_public_key().0.into(),
            (vec![], (self.master_xpriv.fingerprint(), derivation_path)),
        );
        let ty = "SIGHASH_ALL".parse::<PsbtSighashType>()?;
        let mut tap_scripts = BTreeMap::new();
        tap_scripts.insert(
            taproot_spend_info.control_block(&(script.clone(), LeafVersion::TapScript)).unwrap(),
            (script, LeafVersion::TapScript),
        );

        let input = Input {
            witness_utxo: { Some(TxOut { amount, script_pubkey }) },
            tap_key_origins: origins,
            tap_merkle_root: taproot_spend_info.merkle_root(),
            sighash_type: Some(ty),
            tap_internal_key: Some(internal_keypair.x_only_public_key().0.into()),
            tap_scripts,
            ..Default::default()
        };

        next_psbt.inputs = vec![input];
        self.next_psbt = Some(next_psbt.clone());

        self.next.increment()?;
        Ok((tx, next_psbt))
    }

    fn refresh_tx(
        &mut self,
        lock_time_delta: u32,
    ) -> Result<(Transaction, Psbt), Box<dyn std::error::Error>> {
        if let Some(ref spend_info) = self.current_spend_info.clone() {
            let mut psbt = self.next_psbt.clone().expect("should have next_psbt");
            let input = &mut psbt.inputs[0];
            let input_amount = input.witness_utxo.as_ref().unwrap().amount;
            let output_amount = (input_amount - ABSOLUTE_FEES).into_result()?;

            // We use some other derivation path in this example for our inheritance protocol. The important thing is to ensure
            // that we use an unhardened path so we can make use of xpubs.
            let new_derivation_path =
                format!("101/1/0/0/{}", self.next).parse::<DerivationPath>()?;
            let new_internal_keypair = self
                .master_xpriv
                .derive_xpriv(&new_derivation_path)
                .expect("derivation path is short")
                .to_keypair();
            let beneficiary_key =
                self.beneficiary_xpub.derive_xpub(&new_derivation_path)?.to_x_only_public_key();

            // Build up the leaf script and combine with internal key into a Taproot commitment
            let lock_time = absolute::LockTime::from_height(
                psbt.unsigned_tx.lock_time.to_consensus_u32() + lock_time_delta,
            )
            .unwrap();
            let script = Self::time_lock_script(lock_time, beneficiary_key);
            let leaf_hash = script.tapscript_leaf_hash();

            let taproot_spend_info = TaprootBuilder::new()
                .add_leaf(0, script.clone())?
                .finalize(new_internal_keypair.x_only_public_key().0)
                .expect("should be finalizable");
            self.current_spend_info = Some(taproot_spend_info.clone());
            let prevout_script_pubkey = input.witness_utxo.as_ref().unwrap().script_pubkey.clone();
            let output_script_pubkey = ScriptPubKeyBuf::new_p2tr(
                taproot_spend_info.internal_key(),
                taproot_spend_info.merkle_root(),
            );

            psbt.unsigned_tx.outputs =
                vec![TxOut { script_pubkey: output_script_pubkey.clone(), amount: output_amount }];
            psbt.outputs = vec![Output::default()];
            psbt.unsigned_tx.lock_time = absolute::LockTime::ZERO;

            let sighash_type = input
                .sighash_type
                .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
                .unwrap_or(TapSighashType::All);
            let hash = SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
                0,
                &sighash::Prevouts::All(&[TxOut {
                    amount: input_amount,
                    script_pubkey: prevout_script_pubkey,
                }]),
                sighash_type,
            )?;

            {
                let (_, (_, derivation_path)) = input
                    .tap_key_origins
                    .get(&input.tap_internal_key.ok_or("internal key missing in PSBT")?)
                    .ok_or("missing Taproot key origin")?;
                let secret_key = self
                    .master_xpriv
                    .derive_xpriv(derivation_path)
                    .expect("derivation path is short")
                    .to_private_key()
                    .inner;
                sign_psbt_taproot(
                    secret_key,
                    spend_info.internal_key(),
                    None,
                    input,
                    hash,
                    sighash_type,
                );
            }

            // FINALIZER
            psbt.inputs.iter_mut().for_each(|input| {
                let mut script_witness: Witness = Witness::new();
                script_witness.push(input.tap_key_sig.unwrap().to_vec());
                input.final_script_witness = Some(script_witness);

                // Clear all the data fields as per the spec.
                input.partial_sigs = BTreeMap::new();
                input.sighash_type = None;
                input.redeem_script = None;
                input.witness_script = None;
                input.bip32_derivation = BTreeMap::new();
            });

            // EXTRACTOR
            let tx = psbt.extract_tx_unchecked_fee_rate();
            tx.verify(|_| {
                Some(TxOut { amount: input_amount, script_pubkey: output_script_pubkey.clone() })
            })
            .expect("failed to verify transaction");

            let next_tx = Transaction {
                version: transaction::Version::TWO,
                lock_time,
                inputs: vec![TxIn {
                    previous_output: OutPoint { txid: tx.compute_txid(), vout: 0 },
                    script_sig: ScriptSigBuf::new(),
                    sequence: bitcoin::Sequence(0xFFFFFFFD), // enable locktime and opt-in RBF
                    witness: Witness::default(),
                }],
                outputs: vec![],
            };
            let mut next_psbt = Psbt::from_unsigned_tx(next_tx)?;
            let mut origins = BTreeMap::new();
            origins.insert(
                beneficiary_key,
                (vec![leaf_hash], (self.beneficiary_xpub.fingerprint(), new_derivation_path)),
            );
            let ty = "SIGHASH_ALL".parse::<PsbtSighashType>()?;
            let mut tap_scripts = BTreeMap::new();
            tap_scripts.insert(
                taproot_spend_info
                    .control_block(&(script.clone(), LeafVersion::TapScript))
                    .unwrap(),
                (script, LeafVersion::TapScript),
            );

            let input = Input {
                witness_utxo: {
                    let script_pubkey = output_script_pubkey;
                    let amount = output_amount;

                    Some(TxOut { amount, script_pubkey })
                },
                tap_key_origins: origins,
                tap_merkle_root: taproot_spend_info.merkle_root(),
                sighash_type: Some(ty),
                tap_internal_key: Some(new_internal_keypair.x_only_public_key().0.into()),
                tap_scripts,
                ..Default::default()
            };

            next_psbt.inputs = vec![input];
            self.next_psbt = Some(next_psbt.clone());

            self.next.increment()?;
            Ok((tx, next_psbt))
        } else {
            Err("no current_spend_info available. Create an inheritance tx first.".into())
        }
    }
}

/// A wallet that allows spending from an inheritance locked to a P2TR UTXO via a script path
/// after some expiry using CLTV.
struct BeneficiaryWallet {
    master_xpriv: Xpriv,
}

impl BeneficiaryWallet {
    fn new(master_xpriv: Xpriv) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self { master_xpriv })
    }

    fn master_xpub(&self) -> Xpub { Xpub::from_xpriv(&self.master_xpriv) }

    fn spend_inheritance(
        &self,
        mut psbt: Psbt,
        lock_time: absolute::LockTime,
        to_address: Address,
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
        let input_amount = psbt.inputs[0].witness_utxo.as_ref().unwrap().amount;
        let input_script_pubkey =
            psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey.clone();
        psbt.unsigned_tx.lock_time = lock_time;
        psbt.unsigned_tx.outputs = vec![TxOut {
            script_pubkey: to_address.script_pubkey(),
            amount: (input_amount - ABSOLUTE_FEES)
                .expect("ABSOLUTE_FEES must be set below input amount"),
        }];
        psbt.outputs = vec![Output::default()];
        let unsigned_tx = psbt.unsigned_tx.clone();

        // SIGNER
        for (x_only_pubkey, (leaf_hashes, (_, derivation_path))) in
            &psbt.inputs[0].tap_key_origins.clone()
        {
            let secret_key =
                self.master_xpriv.derive_xpriv(derivation_path)?.to_private_key().inner;
            for lh in leaf_hashes {
                let sighash_type = TapSighashType::All;
                let hash = SighashCache::new(&unsigned_tx).taproot_script_spend_signature_hash(
                    0,
                    &sighash::Prevouts::All(&[TxOut {
                        amount: input_amount,
                        script_pubkey: input_script_pubkey.clone(),
                    }]),
                    *lh,
                    sighash_type,
                )?;
                sign_psbt_taproot(
                    secret_key,
                    *x_only_pubkey,
                    Some(*lh),
                    &mut psbt.inputs[0],
                    hash,
                    sighash_type,
                );
            }
        }

        // FINALIZER
        psbt.inputs.iter_mut().for_each(|input| {
            let mut script_witness: Witness = Witness::new();
            for (_, signature) in input.tap_script_sigs.iter() {
                script_witness.push(signature.to_vec());
            }
            for (control_block, (script, _)) in input.tap_scripts.iter() {
                script_witness.push(script.to_vec());
                script_witness.push(control_block.serialize());
            }
            input.final_script_witness = Some(script_witness);

            // Clear all the data fields as per the spec.
            input.partial_sigs = BTreeMap::new();
            input.sighash_type = None;
            input.redeem_script = None;
            input.witness_script = None;
            input.bip32_derivation = BTreeMap::new();
            input.tap_script_sigs = BTreeMap::new();
            input.tap_scripts = BTreeMap::new();
            input.tap_key_sig = None;
        });

        // EXTRACTOR
        let tx = psbt.extract_tx_unchecked_fee_rate();
        tx.verify(|_| {
            Some(TxOut { amount: input_amount, script_pubkey: input_script_pubkey.clone() })
        })
        .expect("failed to verify transaction");

        Ok(tx)
    }
}

// Lifted and modified from BDK at https://github.com/bitcoindevkit/bdk/blob/8fbe40a9181cc9e22cabfc04d57dac5d459da87d/src/wallet/signer.rs#L469-L503

// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

// Calling this with `leaf_hash` = `None` will sign for key-spend
fn sign_psbt_taproot(
    secret_key: secp256k1::SecretKey,
    pubkey: XOnlyPublicKey,
    leaf_hash: Option<TapLeafHash>,
    psbt_input: &mut psbt::Input,
    hash: TapSighash,
    sighash_type: TapSighashType,
) {
    let keypair = secp256k1::Keypair::from_seckey_byte_array(secret_key.to_secret_bytes()).unwrap();
    let keypair = match leaf_hash {
        None => keypair.tap_tweak(psbt_input.tap_merkle_root).to_keypair(),
        Some(_) => keypair, // no tweak for script spend
    };

    let signature = secp256k1::schnorr::sign(&hash.to_byte_array(), &keypair);

    let final_signature = taproot::Signature { signature, sighash_type };

    if let Some(lh) = leaf_hash {
        psbt_input.tap_script_sigs.insert((pubkey, lh), final_signature);
    } else {
        psbt_input.tap_key_sig = Some(final_signature);
    }
}
