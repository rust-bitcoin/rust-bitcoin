use std::str::FromStr;

use serde::Serialize;

use bitcoin::bip32::Xpriv;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::script::{PushBytesBuf, Script, ScriptBuf};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, Signature, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, PublicKey, Sequence, TapNodeHash, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};

fn main() {
    let secp = Secp256k1::new();
    // This is xpriv descriptor for signet test
    let xpriv_desc = "tprv8ku1y3SPM9kB9aM3RHQ9io5nzHTTWPGXEkgZPL4UC43nJWPrVUJnFBGKGa3pLLZC7W9ZrxJKU7E7Vk62KPFZ4gcQALkZXD8HHso2usVeGNA";
    let tprv = Xpriv::from_str(xpriv_desc).unwrap();
    let sk = tprv.private_key;

    let txid = "9c7236ecc2dc45c8ba7e1e7bf8198b07e7a0b95b9fe972177e79835149f7f9e4";
    let unspent_value = 701871;
    let unspent = Unspent::new(txid, unspent_value);

    let ticker = "sats".to_owned();
    let value = "10".to_owned();
    let ins = Brc20::transfer(sk.public_key(&secp).into(), ticker, value).unwrap();

    // for testnet and signet, 1 sat/vB feerate is enough
    let feerate = 1;

    // Commit transaction ID: a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388
    // https://mempool.space/signet/tx/a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388
    let commit_tx = build_commit_tx(&secp, &sk, unspent, &ins, feerate);

    assert_eq!(
        commit_tx.txid(),
        Txid::from_str("a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388").unwrap()
    );

    println!("\nCommit Transaction:\n");
    println!("Transaction ID: {}", commit_tx.txid());

    println!("Raw Transaction: {}", serialize(&commit_tx).to_lower_hex_string());
    println!("{}", "-".repeat(80));

    // Reveal transaction ID: 0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0
    // https://mempool.space/signet/tx/0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0
    let reveal_tx = build_reveal_tx(&secp, &sk, &commit_tx, &ins);

    assert_eq!(
        reveal_tx.txid(),
        Txid::from_str("0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0").unwrap()
    );

    println!("\nReveal Transaction:\n");
    println!("Transaction ID: {}", reveal_tx.txid());
    println!("Raw Transaction: {}", serialize(&reveal_tx).to_lower_hex_string());
    println!("{}", "-".repeat(80));

    // Connection to a signet node to broadcast transactions via bitcoincore-rpc
    // use bitcoincore_rpc::{Auth, Client, RpcApi};
    // let auth = Auth::UserPass("alice".to_owned(), "alice".to_owned());
    // let client = Client::new("http://localhost:38332", auth).unwrap();
    // client.send_raw_transaction(&commit_tx).expect("commit transaction broadcast failed");
    // client.send_raw_transaction(&reveal_tx).expect("reveal transaction broadcast");
}

const REVEAL_TX_SIZE: u64 = 141;
const DUST_AMOUNT: u64 = 546;

pub struct Unspent {
    pub txid: Txid,
    pub value: Amount,
}

impl Unspent {
    pub fn new(txid: &str, value: u64) -> Self {
        let txid = Txid::from_str(txid).unwrap();
        let value = Amount::from_sat(value);
        Unspent { txid, value }
    }
}

pub fn build_commit_tx<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    unspent: Unspent,
    inscription: &OrdinalsInscription,
    feerate: u64,
) -> Transaction {
    let pubkey = sk.public_key(secp);

    // TODO: need to ajust with the vout for other txs
    let txid = unspent.txid;
    let outpoint = OutPoint { txid, vout: 1 };

    let input = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    let spend_amount = DUST_AMOUNT + feerate * REVEAL_TX_SIZE;
    let spend_amount = Amount::from_sat(spend_amount);
    let merkle_root = inscription.spend_info().merkle_root().unwrap();
    let spend = TxOut {
        value: spend_amount,
        script_pubkey: ScriptBuf::new_p2tr(secp, XOnlyPublicKey::from(pubkey), Some(merkle_root)),
    };

    let mut change = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), None),
    };

    let unspent_value = unspent.value;
    let prevout = TxOut {
        value: unspent_value,
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), None),
    };

    let tmp_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input.clone()],
        output: vec![spend.clone(), change.clone()],
    };

    let txfee = Amount::from_sat(tmp_tx.vsize() as u64 * feerate);
    change.value = unspent_value.checked_sub(spend_amount.checked_add(txfee).unwrap()).unwrap();

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend, change],
    };

    taproot_key_path_sign(secp, sk, &[prevout], &mut unsigned_tx)
}

pub fn build_reveal_tx<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    commit_tx: &Transaction,
    inscription: &OrdinalsInscription,
) -> Transaction {
    let pubkey = sk.public_key(secp);
    let txid = commit_tx.txid();

    let merkle_root = inscription.spend_info().merkle_root().unwrap();

    let preoutpoint = OutPoint { txid, vout: 0 };
    let input = TxIn {
        previous_output: preoutpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };
    let spend = TxOut {
        value: Amount::from_sat(DUST_AMOUNT),
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), None),
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend],
    };

    let prevout = TxOut {
        value: Amount::from_sat(DUST_AMOUNT),
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), Some(merkle_root)),
    };

    taproot_script_path_sign(secp, sk, &[prevout], &mut unsigned_tx, inscription)
}

// TODO: merge two taproot sign function to one
pub fn taproot_key_path_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    prevouts: &[TxOut],
    tx: &mut Transaction,
) -> Transaction {
    let keypair = Keypair::from_secret_key(secp, sk);
    let sighash_type = TapSighashType::Default;
    let prevouts = Prevouts::All(prevouts);

    let input_index = 0;
    let mut sighasher = SighashCache::new(tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed  to construct sighash");

    let tweaked = keypair.tap_tweak(secp, None);

    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr(&msg, &tweaked.to_inner());

    let signature = Signature { signature: sig, sighash_type };
    *sighasher.witness_mut(input_index).unwrap() = Witness::from_slice(&[&signature.to_vec()]);

    sighasher.into_transaction().to_owned()
}

pub fn taproot_script_path_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    prevouts: &[TxOut],
    tx: &mut Transaction,
    inscription: &OrdinalsInscription,
) -> Transaction {
    let keypair = Keypair::from_secret_key(secp, sk);
    let sighash_type = TapSighashType::Default;
    let prevouts = Prevouts::All(prevouts);
    let script = inscription.taproot_program().to_owned();
    let control_block = inscription
        .spend_info()
        .control_block(&(script.to_owned(), LeafVersion::TapScript))
        .unwrap();

    let input_index = 0;
    let mut sighasher = SighashCache::new(tx);
    let sighash = sighasher
        .taproot_script_spend_signature_hash(
            input_index,
            &prevouts,
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            sighash_type,
        )
        .expect("failed to construct sighash");
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr(&msg, &keypair);
    let signature = Signature { signature: sig, sighash_type };

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());

    *sighasher.witness_mut(input_index).unwrap() = witness;

    sighasher.into_transaction().to_owned()
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Brc20Ticker(String);

impl Brc20Ticker {
    pub fn new(string: String) -> Result<Self, Box<dyn std::error::Error>> {
        if string.len() != 4 {
            return Err("Invalid brc20 ticker".into());
        }

        Ok(Brc20Ticker(string))
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Brc20 {
    #[serde(rename = "p", default = "brc20")]
    protocol: String,
    #[serde(rename = "op")]
    operation: String,
    #[serde(rename = "tick")]
    ticker: Brc20Ticker,
    #[serde(rename = "amt")]
    amount: String,
}

impl Brc20 {
    const MIME: &'static [u8] = b"text/plain;charset=utf-8";

    pub fn new(op: String, ticker: String, value: String) -> Self {
        Brc20 {
            operation: op,
            ticker: Brc20Ticker::new(ticker).unwrap(),
            amount: value,
            ..Default::default()
        }
    }

    pub fn inscription(
        recipient: PublicKey,
        ticker: String,
        op: String,
        value: String,
    ) -> Result<OrdinalsInscription, Box<dyn std::error::Error>> {
        let data = Self::new(op, ticker, value);

        OrdinalsInscription::new(
            Self::MIME,
            &serde_json::to_vec(&data).expect("badly constructed Brc20 payload"),
            recipient,
        )
    }

    pub fn transfer(
        recipient: PublicKey,
        ticker: String,
        value: String,
    ) -> Result<OrdinalsInscription, Box<dyn std::error::Error>> {
        Self::inscription(recipient, ticker, "transfer".to_owned(), value)
    }

    pub fn mint(
        recipient: PublicKey,
        ticker: String,
        value: String,
    ) -> Result<OrdinalsInscription, Box<dyn std::error::Error>> {
        Self::inscription(recipient, ticker, "mint".to_owned(), value)
    }
}

struct TaprootProgram {
    pub script: ScriptBuf,
    pub spend_info: TaprootSpendInfo,
}

struct TaprootScript {
    pub pubkey: PublicKey,
    pub merkle_root: TapNodeHash,
}
struct OrdinalsInscription {
    envelope: TaprootProgram,
}

impl OrdinalsInscription {
    pub fn new(
        mime: &[u8],
        data: &[u8],
        recipient: PublicKey,
    ) -> Result<OrdinalsInscription, Box<dyn std::error::Error>> {
        let envelope = create_envelope(mime, data, recipient)?;
        Ok(OrdinalsInscription { envelope })
    }
    pub fn taproot_program(&self) -> &Script {
        self.envelope.script.as_script()
    }
    pub fn spend_info(&self) -> &TaprootSpendInfo {
        &self.envelope.spend_info
    }
}

/// Creates an [Ordinals Inscription](https://docs.ordinals.com/inscriptions.html).
/// This function is used for two purposes:
///
/// 1. It creates the spending condition for the given `internal_key`. This
///    associates the public key of the recipient with the Merkle root of the
///    Inscription on-chain, but it does not actually reveal the script to
///    anyone ("commit stage").
/// 2. The same function can then be used by the spender/claimer to actually
///    transfer the Inscripion by sending a transaction with the Inscription
///    script in the Witness ("reveal stage").
///
/// Do note that the `internal_key` can be different for each stage, but it
/// could also be the same entity. Stage one, the `internal_key` is the
/// recipient. Stage two, the `internal_key` is the claimer of the transaction
/// (where the Inscription script is available in the Witness).
fn create_envelope(
    mime: &[u8],
    data: &[u8],
    internal_key: PublicKey,
) -> Result<TaprootProgram, Box<dyn std::error::Error>> {
    use bitcoin::opcodes::all::*;
    use bitcoin::opcodes::*;

    let mut mime_buf = PushBytesBuf::new();
    mime_buf.extend_from_slice(mime).unwrap();

    let mut builder = ScriptBuf::builder()
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"ord")
        // Separator.
        .push_opcode(OP_PUSHBYTES_1)
        // MIME types require this addtional push. It seems that the original
        // creator inadvertently used `push_slice(&[1])`, which leads to
        // `<1><1>`, which denotes a length prefix followed by the value. On the
        // other hand, for the data, `push_slice(&[])` is used, producing `<0>`.
        // This denotes a length prefix followed by no data, as opposed to
        // '<1><0>', which would be a reasonable assumption. While this appears
        // inconsistent, it's the current requirement.
        .push_opcode(OP_PUSHBYTES_1)
        // MIME type identifying the data
        .push_slice(mime_buf.as_push_bytes())
        // Separator
        .push_opcode(OP_PUSHBYTES_0);

    // Push the actual data in chunks.
    for chunk in data.chunks(520) {
        // Create data buffer.
        let mut data_buf = PushBytesBuf::new();
        data_buf.extend_from_slice(chunk).unwrap();

        // Push buffer
        builder = builder.push_slice(data_buf);
    }

    // Finalize scripts.
    let script = builder.push_opcode(OP_ENDIF).into_script();

    // Generate the necessary spending information. As mentioned in the
    // documentation of this function at the top, this serves two purposes;
    // setting the spending condition and actually claiming the spending
    // condition.
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("Ordinals Inscription spending info must always build")
        .finalize(&Secp256k1::new(), XOnlyPublicKey::from(internal_key.inner))
        .expect("Ordinals Inscription spending info must always build");

    Ok(TaprootProgram { script, spend_info })
}
