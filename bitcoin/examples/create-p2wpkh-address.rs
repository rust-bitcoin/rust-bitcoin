use bitcoin::secp256k1::{rand, Secp256k1};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey};

/// Generate a P2WPKH (pay-to-witness-public-key-hash) address and print it
/// along with the associated private key needed to transact.
fn main() {
    // Create new secp256k1 instance.
    let secp = Secp256k1::new();

    // Generate secp256k1 public and private key pair.
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

    // Create a Bitcoin private key to be used on the Bitcoin mainnet.
    let private_key = PrivateKey::new(secret_key, Network::Bitcoin);

    // Create a compressed Bitcoin public key from the secp256k1 public key.
    let public_key = CompressedPublicKey(public_key);

    // Create a Bitcoin P2WPKH address.
    let address = Address::p2wpkh(public_key, Network::Bitcoin);

    println!("Private Key: {private_key}");
    println!("Address: {address}");
}
