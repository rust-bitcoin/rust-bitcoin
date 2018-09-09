//! # Partially Signed Transactions
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
//! except we define PSBTs containing non-standard SigHash types as invalid.

mod error;
pub use self::error::Error;

pub mod raw;

#[macro_use]
mod macros;

pub mod serialize;

mod map;
pub use self::map::{Map, Global};

#[cfg(test)]
mod tests {
    use bitcoin_hashes::hex::FromHex;
    use bitcoin_hashes::sha256d;

    use blockdata::script::Script;
    use blockdata::transaction::{Transaction, TxIn, TxOut, OutPoint};
    use consensus::encode::{deserialize, serialize};
    use util::psbt::map::Global;
    use util::psbt::raw;

    #[test]
    fn serialize_then_deserialize_global() {
        let expected = Global {
            unsigned_tx: Transaction {
                version: 2,
                lock_time: 1257139,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: sha256d::Hash::from_hex(
                            "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126",
                        ).unwrap(),
                        vout: 0,
                    },
                    script_sig: Script::new(),
                    sequence: 4294967294,
                    witness: vec![],
                }],
                output: vec![
                    TxOut {
                        value: 99999699,
                        script_pubkey: hex_script!(
                            "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
                        ),
                    },
                    TxOut {
                        value: 100000000,
                        script_pubkey: hex_script!(
                            "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
                        ),
                    },
                ],
            },
            unknown: Default::default(),
        };

        let actual: Global = deserialize(&serialize(&expected)).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_psbtkvpair() {
        let expected = raw::Pair {
            key: raw::Key {
                type_value: 0u8,
                key: vec![42u8, 69u8],
            },
            value: vec![69u8, 42u8, 4u8],
        };

        let actual: raw::Pair = deserialize(&serialize(&expected)).unwrap();

        assert_eq!(expected, actual);
    }
}
