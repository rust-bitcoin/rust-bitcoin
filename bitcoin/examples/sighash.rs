use bitcoin::hashes::Hash;
use bitcoin::{
    consensus, ecdsa, sighash, Amount, CompressedPublicKey, Script, ScriptBuf, Transaction,
};
use hex_lit::hex;

//These are real blockchain transactions examples of computing sighash for:
// - P2WPKH
// - P2MS 2of3
// - P2SH 2of2 multisig
// - P2WSH 2of2 multisig

//run with: cargo run --example sighash

//TODO add P2TR examples, ideally for both key-path and script-path spending

/// Computes segwit sighash for a transaction input that spends a p2wpkh output with "witness_v0_keyhash" scriptPubKey.type
///
/// # Arguments
///
/// * `raw_tx` - spending tx hex
/// * `inp_idx` - spending tx input index
/// * `value` - ref tx output value in sats
fn compute_sighash_p2wpkh(raw_tx: &[u8], inp_idx: usize, value: u64) {
    let tx: Transaction = consensus::deserialize(raw_tx).unwrap();
    let inp = &tx.input[inp_idx];
    let witness = &inp.witness;
    println!("Witness: {:?}", witness);

    // BIP-141: The witness must consist of exactly 2 items (≤ 520 bytes each). The first one a
    // signature, and the second one a public key.
    assert_eq!(witness.len(), 2);
    let sig_bytes = witness.nth(0).unwrap();
    let pk_bytes = witness.nth(1).unwrap();

    let sig = ecdsa::Signature::from_slice(sig_bytes).expect("failed to parse sig");

    //BIP-143: "The item 5 : For P2WPKH witness program, the scriptCode is 0x1976a914{20-byte-pubkey-hash}88ac"
    //this is nothing but a standard P2PKH script OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG:
    let pk = CompressedPublicKey::from_slice(pk_bytes).expect("failed to parse pubkey");
    let wpkh = pk.wpubkey_hash();
    println!("Script pubkey hash: {:x}", wpkh);
    let spk = ScriptBuf::new_p2wpkh(&wpkh);

    let mut cache = sighash::SighashCache::new(&tx);
    let sighash = cache
        .p2wpkh_signature_hash(inp_idx, &spk, Amount::from_sat(value), sig.hash_ty)
        .expect("failed to compute sighash");
    println!("Segwit p2wpkh sighash: {:x}", sighash);
    let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
    println!("Message is {:x}", msg);
    let secp = secp256k1::Secp256k1::verification_only();
    pk.verify(&secp, &msg, &sig).unwrap()
}

/// Computes sighash for a legacy multisig transaction input that spends either a p2sh or a p2ms output.
///
/// # Arguments
///
/// * `raw_tx` - spending tx hex
/// * `inp_idx` - spending tx input inde
/// * `script_pubkey_bytes_opt` - Option with scriptPubKey bytes. If None, it's p2sh case, i.e., reftx output's scriptPubKey.type is "scripthash". In this case scriptPubkey is extracted from the spending transaction's scriptSig. If Some(), it's p2ms case, i.e., reftx output's scriptPubKey.type is "multisig", and the scriptPubkey is supplied from the referenced output.
fn compute_sighash_legacy(raw_tx: &[u8], inp_idx: usize, script_pubkey_bytes_opt: Option<&[u8]>) {
    let tx: Transaction = consensus::deserialize(raw_tx).unwrap();
    let inp = &tx.input[inp_idx];
    let script_sig = &inp.script_sig;
    println!("scriptSig is: {}", script_sig);
    let cache = sighash::SighashCache::new(&tx);
    //In the P2SH case we get scriptPubKey from scriptSig of the spending input.
    //The scriptSig that corresponds to an M of N multisig should be: PUSHBYTES_0 PUSHBYTES_K0 <sig0><sighashflag0> ... PUSHBYTES_Km <sigM><sighashflagM> PUSHBYTES_X <scriptPubKey>
    //Here we assume that we have an M of N multisig scriptPubKey.
    let mut instructions: Vec<_> = script_sig.instructions().collect();
    let script_pubkey_p2sh;
    let script_pubkey_bytes = match script_pubkey_bytes_opt {
        //In the P2MS case, the scriptPubKey is in the referenced output, passed into this function
        Some(bytes) => bytes,
        //In the P2SH case, the scriptPubKey is the last scriptSig PushBytes instruction
        None => {
            script_pubkey_p2sh = instructions.pop().unwrap().unwrap();
            script_pubkey_p2sh.push_bytes().unwrap().as_bytes()
        }
    };
    let script_code = Script::from_bytes(script_pubkey_bytes);
    let pushbytes_0 = instructions.remove(0).unwrap();
    assert!(
        pushbytes_0.push_bytes().unwrap().as_bytes().is_empty(),
        "first in ScriptSig must be PUSHBYTES_0 got {:?}",
        pushbytes_0
    );

    //All other scriptSig instructions  must be signatures
    for instr in instructions {
        let sig = ecdsa::Signature::from_slice(instr.unwrap().push_bytes().unwrap().as_bytes())
            .expect("failed to parse sig");
        let sighash = cache
            .legacy_signature_hash(inp_idx, script_code, sig.hash_ty.to_u32())
            .expect("failed to compute sighash");
        println!("Legacy sighash: {:x} (sighash flag {})", sighash, sig.hash_ty);
    }
}

/// Computes sighash for a segwit multisig transaction input that spends a p2wsh output with "witness_v0_scripthash" scriptPubKey.type
///
/// # Arguments
///
/// * `raw_tx` - spending tx hex
/// * `inp_idx` - spending tx input index
/// * `value` - ref tx output value in sats
fn compute_sighash_p2wsh(raw_tx: &[u8], inp_idx: usize, value: u64) {
    let tx: Transaction = consensus::deserialize(raw_tx).unwrap();
    let inp = &tx.input[inp_idx];
    let witness = &inp.witness;
    println!("witness {:?}", witness);

    //last element is called witnessScript according to BIP141. It supersedes scriptPubKey.
    let witness_script_bytes: &[u8] = witness.last().expect("Out of Bounds");
    let witness_script = Script::from_bytes(witness_script_bytes);
    let mut cache = sighash::SighashCache::new(&tx);

    //in an M of N multisig, the witness elements from 1 (0-based) to M-2 are signatures (with sighash flags as the last byte)
    for n in 1..=witness.len() - 2 {
        let sig_bytes = witness.nth(n).expect("Out of Bounds");
        let sig = ecdsa::Signature::from_slice(sig_bytes).expect("failed to parse sig");
        let sig_len = sig_bytes.len() - 1; //last byte is EcdsaSighashType sighash flag
                                           //ECDSA signature in DER format lengths are between 70 and 72 bytes
        assert!((70..=72).contains(&sig_len), "signature length {} out of bounds", sig_len);
        //here we assume that all sighash_flags are the same. Can they be different?
        let sighash = cache
            .p2wsh_signature_hash(inp_idx, witness_script, Amount::from_sat(value), sig.hash_ty)
            .expect("failed to compute sighash");
        println!("Segwit p2wsh sighash: {:x} ({})", sighash, sig.hash_ty);
    }
}

fn main() {
    sighash_p2wpkh();
    sighash_p2ms_multisig_2x3();
    sighash_p2sh_multisig_2x2();
    sighash_p2wsh_multisig_2x2();
}

/// Example showing how to verify the signature for spending a p2wpkh transaction.
fn sighash_p2wpkh() {
    //Spending transaction:
    //bitcoin-cli getrawtransaction 663becacc6368150a46725e404ccdfa34d1fffbececa784c31f0a7849b4dad08  3
    let raw_tx = hex!("020000000001015ce1d4ffc716022f83cc0d557e6dad0500eeff9e9623bde014bdc09c5b672d750000000000fdffffff025fb7460b000000001600142cf4c1dc0352e0658971ca62a7457a1cd8c3389c4ce3a2000000000016001433f57fe374c6ceab61c8639128c038ac2a8c8db60247304402203cb50efb5c4a9aa7fd369ab6f4b226db99f44f9c610b5b50bc42f343a6aa401302201af791542eee6c1b11705e8895cc5adc36458910dc91aadcafb76a6478a29b9f01210242e811e66fd17e9a6e4ef772766c668d6e0595ca1d7f0583148bc460b575fbfdf0df0b00");

    //vin:0
    let inp_idx = 0;
    //output value from the referenced vout:0 from the referenced tx:
    //bitcoin-cli getrawtransaction 752d675b9cc0bd14e0bd23969effee0005ad6d7e550dcc832f0216c7ffd4e15c  3
    let ref_out_value = 200000000;

    println!("\nsighash_p2wpkh:");
    compute_sighash_p2wpkh(&raw_tx, inp_idx, ref_out_value);
}

fn sighash_p2sh_multisig_2x2() {
    //Spending transactoin:
    //bitcoin-cli getrawtransaction 214646c4b563cd8c788754ec94468ab71602f5ed07d5e976a2b0e41a413bcc0e  3
    //after decoding ScriptSig from the input:0, its last ASM element is the scriptpubkey:
    //bitcoin-cli decodescript 5221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752ae
    //its ASM is 2 of 2 multisig: 2 032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de 03e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af5657 2 OP_CHECKMULTISIG
    let raw_tx = hex!("0100000001d611ad58b2f5bc0db7d15dfde4f497d6482d1b4a1e8c462ef077d4d32b3dae7901000000da0047304402203b17b4f64fa7299e8a85a688bda3cb1394b80262598bbdffd71dab1d7f266098022019cc20dc20eae417374609cb9ca22b28261511150ed69d39664b9d3b1bcb3d1201483045022100cfff9c400abb4ce5f247bd1c582cf54ec841719b0d39550b714c3c793fb4347b02201427a961a7f32aba4eeb1b71b080ea8712705e77323b747c03c8f5dbdda1025a01475221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752aeffffffff020ed000000000000016001477800cff52bd58133b895622fd1220d9e2b47a79cd0902000000000017a914da55145ca5c56ba01f1b0b98d896425aa4b0f4468700000000");
    let inp_idx = 0;

    println!("\nsighash_p2sh_multisig_2x2:");
    compute_sighash_legacy(&raw_tx, inp_idx, None);
}

fn sighash_p2wsh_multisig_2x2() {
    //The spending transaction is
    //bitcoin-cli getrawtransaction 2bb157363e7a62d70b92082a9b2c9bb6f329154f816b8d239bd58c35c789a96a  3
    //input 0 (the only input)
    //ScriptPubkey from its Witness data is:
    //bitcoin-cli decodescript 52210289da5da9d3700156db2d01e6362491733f6c886971791deda74b4e9d707190b2210323c437f30384498be79df2990ce5a8de00844e768c0ccce914335b6c26adea7352ae
    //its ASM is 2 0289da5da9d3700156db2d01e6362491733f6c886971791deda74b4e9d707190b2 0323c437f30384498be79df2990ce5a8de00844e768c0ccce914335b6c26adea73 2 OP_CHECKMULTISIG
    let raw_tx = hex!("010000000001011b9eb4122976fad8f809ee4cea8ac8d1c5b6b8e0d0f9f93327a5d78c9a3945280000000000ffffffff02ba3e0d00000000002200201c3b09401aaa7c9709d118a75d301bdb2180fb68b2e9b3ade8ad4ff7281780cfa586010000000000220020a41d0d894799879ca1bd88c1c3f1c2fd4b1592821cc3c5bfd5be5238b904b09f040047304402201c7563e876d67b5702aea5726cd202bf92d0b1dc52c4acd03435d6073e630bac022032b64b70d7fba0cb8be30b882ea06c5f8ec7288d113459dd5d3e294214e2c96201483045022100f532f7e3b8fd01a0edc86de4870db4e04858964d0a609df81deb99d9581e6c2e02206d9e9b6ab661176be8194faded62f518cdc6ee74dba919e0f35d77cff81f38e5014752210289da5da9d3700156db2d01e6362491733f6c886971791deda74b4e9d707190b2210323c437f30384498be79df2990ce5a8de00844e768c0ccce914335b6c26adea7352ae00000000");
    //For the witness transaction sighash computation, we need its referenced output's value from the original transaction:
    //bitcoin-cli getrawtransaction 2845399a8cd7a52733f9f9d0e0b8b6c5d1c88aea4cee09f8d8fa762912b49e1b  3
    //we need vout 0 value in sats:
    let ref_out_value = 968240;

    println!("\nsighash_p2wsh_multisig_2x2:");
    compute_sighash_p2wsh(&raw_tx, 0, ref_out_value);
}

fn sighash_p2ms_multisig_2x3() {
    //Spending tx:
    //bitcoin-cli getrawtransaction 949591ad468cef5c41656c0a502d9500671ee421fadb590fbc6373000039b693  3
    //Inp 0 scriptSig has 2 sigs
    let raw_tx = hex!("010000000110a5fee9786a9d2d72c25525e52dd70cbd9035d5152fac83b62d3aa7e2301d58000000009300483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801ffffffff0180a21900000000001976a914971802edf585cdbc4e57017d6e5142515c1e502888ac00000000");
    //Original transaction:
    //bitcoin-cli getrawtransaction 581d30e2a73a2db683ac2f15d53590bd0cd72de52555c2722d9d6a78e9fea510  3
    //Out 0 scriptPubKey.type “multisig” has 3 uncompressed pubkeys
    let reftx_script_pubkey_bytes = hex!("524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae");
    let inp_idx = 0;

    println!("\nsighash_p2ms_multisig_2x3:");
    compute_sighash_legacy(&raw_tx, inp_idx, Some(&reftx_script_pubkey_bytes));
}
