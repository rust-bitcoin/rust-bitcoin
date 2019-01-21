
//! Wallet-Import-Format Implementation
//!

use std::fmt;
use secp256k1::SecretKey;
use consensus::encode;
use network::constants::Network;
use util::base58;

/// Write the private key in WIF format.
pub fn fmt_wif(fmt: &mut fmt::Write, key: &SecretKey, network: Network) -> fmt::Result {
    let mut ret = [0; 34];
    ret[0] = match network {
        Network::Bitcoin => 128,
        Network::Testnet | Network::Regtest => 239,
    };
    ret[1..33].copy_from_slice(&key[..]);
    ret[33] = 1;
    fmt.write_str(&base58::check_encode_slice(&ret[..]))
}

/// Write the private key in WIF format for usage with uncompressed public keys.
pub fn fmt_wif_uncompressed(fmt: &mut fmt::Write, key: &SecretKey, network: Network) -> fmt::Result {
    let mut ret = [0; 34];
    ret[0] = match network {
        Network::Bitcoin => 128,
        Network::Testnet | Network::Regtest => 239,
    };
    ret[1..33].copy_from_slice(&key[..]);
    fmt.write_str(&base58::check_encode_slice(&ret[..33]))
}

/// Get WIF encoding of this private key.
pub fn encode(key: &SecretKey, network: Network) -> String {
    let mut buf = String::new();
    fmt_wif(&mut buf, &key, network).unwrap();
    buf.shrink_to_fit();
    buf
}

/// Get WIF encoding of this private key for usage with uncompressed public keys.
pub fn encode_uncompressed(key: &SecretKey, network: Network) -> String {
    let mut buf = String::new();
    fmt_wif_uncompressed(&mut buf, &key, network).unwrap();
    buf.shrink_to_fit();
    buf
}

/// Parse WIF encoded private key.
pub fn decode(wif: &str) -> Result<SecretKey, encode::Error> {
    let (key, _, _) = decode_meta(&wif)?;
    Ok(key)
}

/// Parse WIF encoded private key with it's WIF metadata: the intended network and compressedness.
pub fn decode_meta(wif: &str) -> Result<(SecretKey, Network, bool), encode::Error> {
    let data = base58::from_check(wif)?;

    let compressed = match data.len() {
        33 => false,
        34 => true,
        _ => { return Err(encode::Error::Base58(base58::Error::InvalidLength(data.len()))); }
    };

    let network = match data[0] {
        128 => Network::Bitcoin,
        239 => Network::Testnet,
        x   => { return Err(encode::Error::Base58(base58::Error::InvalidVersion(vec![x]))); }
    };

    let key = SecretKey::from_slice(&data[1..33])
        .map_err(|_| base58::Error::Other("Secret key out of range".to_owned()))?;

    Ok((key, network, compressed))
}

#[cfg(test)]
mod tests {
    use network::constants::Network;

    #[test]
    fn test_key_derivation() {
        // testnet compressed
        let (key, net, com) = super::decode_meta("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(net, Network::Testnet);
        assert_eq!(com, true);
        assert_eq!(super::encode(&key, net), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

        // mainnet uncompressed
        let (key, net, com) = super::decode_meta("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(net, Network::Bitcoin);
        assert_eq!(com, false);
        assert_eq!(super::encode_uncompressed(&key, net), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");
    }
}

