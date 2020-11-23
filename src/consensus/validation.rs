// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
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

//! Module to perform transaction and script validation.
//! This relies on the `bitcoinconsensus` crate that uses Bitcoin Core
//! libconsensus to perform validation.

use blockdata::script::Script;
use blockdata::transaction::{OutPoint, Transaction, TxOut};

/// An error during transaction validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The sum of the transaction inputs is below the sum of the outputs.
    TxAmountsInBelowOut(u64, u64),
    /// Error validating the script with bitcoinconsensus library
    ScriptVerification(::bitcoinconsensus::Error),
    /// Can not find the spent output
    UnknownSpentOutput(OutPoint),
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            Error::TxAmountsInBelowOut(sum_in, sum_out) => write!(
                f,
                "transaction amounts don't match: sum inputs ({}) < sum outputs ({})",
                sum_in, sum_out
            ),
            Error::ScriptVerification(ref e) => {
                write!(f, "bitcoinconsensus script verification error: {:?}", e)
            }
            Error::UnknownSpentOutput(ref p) => write!(f, "unknown spent output: {}", p),
        }
    }
}

impl ::std::error::Error for Error {}

/// verify spend of an input script
/// # Parameters
///  * index - the input index in spending which is spending this transaction
///  * amount - the amount this script guards
///  * spending - the transaction that attempts to spend the output holding this script
pub fn verify_script(
    script: &Script,
    index: usize,
    amount: u64,
    spending: &[u8],
) -> Result<(), Error> {
    ::bitcoinconsensus::verify(&script[..], amount, spending, index)
        .map_err(Error::ScriptVerification)
}

/// verify spend of an input script with specific verification flags
/// # Parameters
///  * index - the input index in spending which is spending this transaction
///  * amount - the amount this script guards
///  * spending - the transaction that attempts to spend the output holding this script
///  * flags - the verification flags
pub fn verify_script_with_flags(
    script: &Script,
    index: usize,
    amount: u64,
    spending: &[u8],
    flags: u32,
) -> Result<(), Error> {
    ::bitcoinconsensus::verify_with_flags(&script[..], amount, spending, index, flags)
        .map_err(Error::ScriptVerification)
}

/// Verify that this transaction is able to spend its inputs
pub fn verify_transaction<'a, S>(tx: &Transaction, mut get_utxo: S) -> Result<(), Error>
where
    S: FnMut(OutPoint) -> Option<&'a TxOut>,
{
    use std::collections::HashSet;

    let serialized_tx = ::consensus::serialize(tx);
    let mut spent_inputs = HashSet::new();
    let mut sum_in = 0;
    for (idx, input) in tx.input.iter().enumerate() {
        if !spent_inputs.insert(input.previous_output) {
            return Err(Error::UnknownSpentOutput(input.previous_output));
        }
        if let Some(output) = get_utxo(input.previous_output) {
            verify_script(&output.script_pubkey, idx, output.value, serialized_tx.as_slice())?;
            sum_in += output.value;
        } else {
            return Err(Error::UnknownSpentOutput(input.previous_output));
        }
    }

    // Perform a simple check on the input and output amounts.
    let sum_out = tx.output.iter().map(|out| out.value).sum();
    if sum_out > sum_in {
        return Err(Error::TxAmountsInBelowOut(sum_in, sum_out));
    }
    Ok(())
}

impl Script {
    /// verify spend of an input script
    /// # Parameters
    ///  * index - the input index in spending which is spending this transaction
    ///  * amount - the amount this script guards
    ///  * spending - the transaction that attempts to spend the output holding this script
    pub fn verify(&self, index: usize, amount: u64, spending: &[u8]) -> Result<(), Error> {
        verify_script(self, index, amount, spending)
    }
}

impl Transaction {
    /// Verify that this transaction is able to spend its inputs
    pub fn verify<'a, S>(&self, get_utxo: S) -> Result<(), Error>
        where S: FnMut(OutPoint) -> Option<&'a TxOut>
    {
        verify_transaction(self, get_utxo)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hashes::hex::FromHex;

    use blockdata::script::Builder;
    use blockdata::transaction::{OutPoint, Transaction};
    use consensus::deserialize;

    use super::*;

    #[test]
    fn test_bitcoinconsensus() {
        // a random segwit transaction from the blockchain using native segwit
        let spent = Builder::from(Vec::<u8>::from_hex(
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
        ).unwrap()).into_script();
        let spending = Vec::<u8>::from_hex(
            "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
        ).unwrap();
        verify_script(&spent, 0, 18393430, spending.as_slice()).unwrap();
    }

    #[test]
    fn test_transaction_verify() {
        // a random recent segwit transaction from blockchain using both old and segwit inputs
        let mut spending: Transaction = deserialize(Vec::<u8>::from_hex(
            "020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700"
        ).unwrap().as_slice()).unwrap();
        let spent1: Transaction = deserialize(Vec::<u8>::from_hex(
            "020000000001040aacd2c49f5f3c0968cfa8caf9d5761436d95385252e3abb4de8f5dcf8a582f20000000017160014bcadb2baea98af0d9a902e53a7e9adff43b191e9feffffff96cd3c93cac3db114aafe753122bd7d1afa5aa4155ae04b3256344ecca69d72001000000171600141d9984579ceb5c67ebfbfb47124f056662fe7adbfeffffffc878dd74d3a44072eae6178bb94b9253177db1a5aaa6d068eb0e4db7631762e20000000017160014df2a48cdc53dae1aba7aa71cb1f9de089d75aac3feffffffe49f99275bc8363f5f593f4eec371c51f62c34ff11cc6d8d778787d340d6896c0100000017160014229b3b297a0587e03375ab4174ef56eeb0968735feffffff03360d0f00000000001976a9149f44b06f6ee92ddbc4686f71afe528c09727a5c788ac24281b00000000001976a9140277b4f68ff20307a2a9f9b4487a38b501eb955888ac227c0000000000001976a9148020cd422f55eef8747a9d418f5441030f7c9c7788ac0247304402204aa3bd9682f9a8e101505f6358aacd1749ecf53a62b8370b97d59243b3d6984f02200384ad449870b0e6e89c92505880411285ecd41cf11e7439b973f13bad97e53901210205b392ffcb83124b1c7ce6dd594688198ef600d34500a7f3552d67947bbe392802473044022033dfd8d190a4ae36b9f60999b217c775b96eb10dee3a1ff50fb6a75325719106022005872e4e36d194e49ced2ebcf8bb9d843d842e7b7e0eb042f4028396088d292f012103c9d7cbf369410b090480de2aa15c6c73d91b9ffa7d88b90724614b70be41e98e0247304402207d952de9e59e4684efed069797e3e2d993e9f98ec8a9ccd599de43005fe3f713022076d190cc93d9513fc061b1ba565afac574e02027c9efbfa1d7b71ab8dbb21e0501210313ad44bc030cc6cb111798c2bf3d2139418d751c1e79ec4e837ce360cc03b97a024730440220029e75edb5e9413eb98d684d62a077b17fa5b7cc19349c1e8cc6c4733b7b7452022048d4b9cae594f03741029ff841e35996ef233701c1ea9aa55c301362ea2e2f68012103590657108a72feb8dc1dec022cf6a230bb23dc7aaa52f4032384853b9f8388baf9d20700"
        ).unwrap().as_slice()).unwrap();
        let spent2: Transaction = deserialize(Vec::<u8>::from_hex(
            "0200000000010166c3d39490dc827a2594c7b17b7d37445e1f4b372179649cd2ce4475e3641bbb0100000017160014e69aa750e9bff1aca1e32e57328b641b611fc817fdffffff01e87c5d010000000017a914f3890da1b99e44cd3d52f7bcea6a1351658ea7be87024830450221009eb97597953dc288de30060ba02d4e91b2bde1af2ecf679c7f5ab5989549aa8002202a98f8c3bd1a5a31c0d72950dd6e2e3870c6c5819a6c3db740e91ebbbc5ef4800121023f3d3b8e74b807e32217dea2c75c8d0bd46b8665b3a2d9b3cb310959de52a09bc9d20700"
        ).unwrap().as_slice()).unwrap();
        let spent3: Transaction = deserialize(Vec::<u8>::from_hex(
            "01000000027a1120a30cef95422638e8dab9dedf720ec614b1b21e451a4957a5969afb869d000000006a47304402200ecc318a829a6cad4aa9db152adbf09b0cd2de36f47b53f5dade3bc7ef086ca702205722cda7404edd6012eedd79b2d6f24c0a0c657df1a442d0a2166614fb164a4701210372f4b97b34e9c408741cd1fc97bcc7ffdda6941213ccfde1cb4075c0f17aab06ffffffffc23b43e5a18e5a66087c0d5e64d58e8e21fcf83ce3f5e4f7ecb902b0e80a7fb6010000006b483045022100f10076a0ea4b4cf8816ed27a1065883efca230933bf2ff81d5db6258691ff75202206b001ef87624e76244377f57f0c84bc5127d0dd3f6e0ef28b276f176badb223a01210309a3a61776afd39de4ed29b622cd399d99ecd942909c36a8696cfd22fc5b5a1affffffff0200127a000000000017a914f895e1dd9b29cb228e9b06a15204e3b57feaf7cc8769311d09000000001976a9144d00da12aaa51849d2583ae64525d4a06cd70fde88ac00000000"
        ).unwrap().as_slice()).unwrap();

        let mut spent = HashMap::new();
        spent.insert(spent1.txid(), spent1);
        spent.insert(spent2.txid(), spent2);
        spent.insert(spent3.txid(), spent3);
        let spent2 = spent.clone();
        let spent3 = spent.clone();

        verify_transaction(&spending, |point: OutPoint| {
            spent.get(&point.txid).and_then(|tx| tx.output.get(point.vout as usize))
        })
        .unwrap();

        // test that we fail with repeated use of same input
        let mut double_spending = spending.clone();
        let re_use = double_spending.input[0].clone();
        double_spending.input.push(re_use);

        assert!(verify_transaction(&double_spending, |point: OutPoint| {
            spent2.get(&point.txid).and_then(|tx| tx.output.get(point.vout as usize))
        })
        .is_err());

        // test that we get a failure if we corrupt a signature
        spending.input[1].witness[0][10] = 42;
        match verify_transaction(&spending, |point: OutPoint| {
            spent3.get(&point.txid).and_then(|tx| tx.output.get(point.vout as usize))
        })
        .err()
        .unwrap()
        {
            Error::ScriptVerification(_) => {}
            _ => panic!("Wrong error type"),
        }
    }
}
