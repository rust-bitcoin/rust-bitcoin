use bitcoin::secp256k1::rand;
use bitcoin::{Address, FullPublicKey, Network};

/// Generate a P2WPKH (pay-to-witness-public-key-hash) address and print it.
fn main() {
    // Generate secp256k1 public and private key pair.
    let (_secret_key, public_key) = secp256k1::generate_keypair(&mut rand::rng());

    // Create a compressed Bitcoin public key from the secp256k1 public key.
    let public_key = FullPublicKey::from_secp(public_key);

    // Create a Bitcoin P2WPKH address.
    let address = Address::p2wpkh(public_key, Network::Bitcoin);

    println!("Address: {address}");
}
