extern crate bitcoin;

use std::str::FromStr;
use std::{env, process};

use bitcoin::address::Address;
use bitcoin::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::ffi::types::AlignedType;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::PublicKey;

fn main() {
    // This example derives root xprv from a 32-byte seed,
    // derives the child xprv with path m/84h/0h/0h,
    // prints out corresponding xpub,
    // calculates and prints out the first receiving segwit address.
    // Run this example with cargo and seed(hex-encoded) argument:
    // cargo run --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("not enough arguments. usage: {} <hex-encoded 32-byte seed>", &args[0]);
        process::exit(1);
    }

    let seed_hex = &args[1];
    println!("Seed: {}", seed_hex);

    // default network as mainnet
    let network = bitcoin::Network::Bitcoin;
    println!("Network: {:?}", network);

    let seed = Vec::from_hex(seed_hex).unwrap();

    // we need secp256k1 context for key derivation
    let mut buf: Vec<AlignedType> = Vec::new();
    buf.resize(Secp256k1::preallocate_size(), AlignedType::zeroed());
    let secp = Secp256k1::preallocated_new(buf.as_mut_slice()).unwrap();

    // calculate root key from seed
    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();
    println!("Root key: {}", root);

    // derive child xpub
    let path = DerivationPath::from_str("m/84h/0h/0h").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    println!("Child at {}: {}", path, child);
    let xpub = ExtendedPubKey::from_priv(&secp, &child);
    println!("Public key at {}: {}", path, xpub);

    // generate first receiving address at m/0/0
    // manually creating indexes this time
    let zero = ChildNumber::from_normal_idx(0).unwrap();
    let public_key = xpub.derive_pub(&secp, &[zero, zero]).unwrap().public_key;
    let address = Address::p2wpkh(&PublicKey::new(public_key), network).unwrap();
    println!("First receiving address: {}", address);
}
