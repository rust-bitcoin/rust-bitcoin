#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate bitcoin;

type BResult = Result<bitcoin::blockdata::script::Script, bitcoin::util::Error>;
//type BResult = Result<bitcoin::blockdata::transaction::Transaction, bitcoin::util::Error>;
//type BResult = Result<bitcoin::blockdata::transaction::TxIn, bitcoin::util::Error>;
//type BResult = Result<bitcoin::blockdata::transaction::TxOut, bitcoin::util::Error>;
//type BResult = Result<bitcoin::network::constants::Network, bitcoin::util::Error>;

fuzz_target!(|data: &[u8]| {
    let _: BResult = bitcoin::network::serialize::deserialize(data);
});
