// SPDX-License-Identifier: CC0-1.0

//! Integration tests for version-preserving BIP-0032 extended keys.

use base58::Base58CkString;
use bitcoin_key_expression::bip32::{
    ChildNumber, EncodedXpriv, EncodedXprivDecodeError, EncodedXpub, EncodedXpubDecodeError,
    Fingerprint, InvalidXkeyPartsError, ParseEncodedXpubError, ParseXprivError, ParseXpubError,
    Xpriv, XprivDecodeError, Xpub, XpubDecodeError,
};
use network::NetworkKind;

const CUSTOM_VERSION: [u8; 4] = *b"BKEY";
const KEY_PREFIX: usize = 45;

fn demo_master(network: NetworkKind) -> Xpriv { Xpriv::new_master(network, *b"public demo seed") }

fn with_version(mut payload: [u8; 78], version: [u8; 4]) -> [u8; 78] {
    payload[..4].copy_from_slice(&version);
    payload
}

#[test]
fn arbitrary_versions_round_trip_without_canonicalizing() {
    let xpriv = demo_master(NetworkKind::Main).derive_child(ChildNumber::ONE_NORMAL).unwrap();
    let xpub = xpriv.to_xpub();

    for version in [[0; 4], CUSTOM_VERSION, [0xff; 4]] {
        let public = with_version(xpub.encode(), version);
        let public_text = Base58CkString::encode(&public).unwrap();
        let encoded = EncodedXpub::from_byte_array(&public).unwrap();
        assert_eq!(encoded.version_bytes(), version);
        assert_eq!(encoded.encode(), public);
        assert_eq!(public_text.as_str().parse::<EncodedXpub>().unwrap(), encoded);
        assert_eq!(encoded.to_string(), public_text.as_str());
        assert_eq!(Xpub::try_from(encoded).unwrap_err().version_bytes(), version);
        assert!(matches!(
            public_text.as_str().parse::<Xpub>(),
            Err(ParseXpubError::Decode(XpubDecodeError::UnknownVersion(v))) if v == version
        ));

        let private = with_version(xpriv.encode(), version);
        let private_text = Base58CkString::encode(&private).unwrap();
        let encoded = EncodedXpriv::from_byte_array(&private).unwrap();
        assert_eq!(encoded.version_bytes(), version);
        assert_eq!(encoded.encode(), private);
        assert_eq!(private_text.as_str().parse::<EncodedXpriv>().unwrap(), encoded);
        assert_eq!(encoded.to_string(), private_text.as_str());
        assert_eq!(Xpriv::try_from(encoded).unwrap_err().version_bytes(), version);
        assert!(matches!(
            private_text.as_str().parse::<Xpriv>(),
            Err(ParseXprivError::Decode(XprivDecodeError::UnknownVersion(v))) if v == version
        ));
    }

    let public = with_version(xpub.encode(), CUSTOM_VERSION);
    let mut text = Base58CkString::encode(&public).unwrap().to_string();
    let last = text.pop().unwrap();
    text.push(if last == '1' { '2' } else { '1' });
    assert!(matches!(
        text.parse::<EncodedXpub>(),
        Err(ParseEncodedXpubError::Base58(e)) if e.incorrect_checksum().is_some()
    ));
}

#[test]
fn canonical_conversion_requires_a_matching_version_kind() {
    for network in [NetworkKind::Main, NetworkKind::Test] {
        let xpriv = demo_master(network);
        let xpub = xpriv.to_xpub();
        let public = xpub.encode();
        let private = xpriv.encode();
        let pub_version = public[..4].try_into().unwrap();
        let priv_version = private[..4].try_into().unwrap();

        let encoded_pub = EncodedXpub::from_byte_array(&public).unwrap();
        assert_eq!(EncodedXpub::from(xpub), encoded_pub);
        assert_eq!(Xpub::try_from(encoded_pub).unwrap(), xpub);
        let encoded_priv = EncodedXpriv::from_byte_array(&private).unwrap();
        assert_eq!(EncodedXpriv::from(xpriv), encoded_priv);
        assert_eq!(Xpriv::try_from(encoded_priv).unwrap(), xpriv);

        let public = with_version(public, priv_version);
        let encoded_pub = EncodedXpub::from_byte_array(&public).unwrap();
        assert_eq!(Xpub::try_from(encoded_pub).unwrap_err().version_bytes(), priv_version);
        assert!(EncodedXpriv::from_byte_array(&public).is_err());

        let private = with_version(private, pub_version);
        let encoded_priv = EncodedXpriv::from_byte_array(&private).unwrap();
        assert_eq!(Xpriv::try_from(encoded_priv).unwrap_err().version_bytes(), pub_version);
        assert!(EncodedXpub::from_byte_array(&private).is_err());
    }
}

#[test]
fn rejects_invalid_key_material_even_with_an_unknown_version() {
    let xpriv = demo_master(NetworkKind::Main);
    let mut public = with_version(xpriv.to_xpub().encode(), CUSTOM_VERSION);
    public[KEY_PREFIX] = 0x02;
    public[KEY_PREFIX + 1..].fill(0xff); // X coordinate outside the field.
    assert!(matches!(
        EncodedXpub::from_byte_array(&public),
        Err(EncodedXpubDecodeError::Secp256k1(_))
    ));

    let mut private = with_version(xpriv.encode(), CUSTOM_VERSION);
    private[KEY_PREFIX] = 1;
    assert!(matches!(
        EncodedXpriv::from_byte_array(&private),
        Err(EncodedXprivDecodeError::InvalidPrivateKeyPrefix)
    ));
    private[KEY_PREFIX..].fill(0); // Correct prefix, but a zero secret scalar.
    assert!(matches!(
        EncodedXpriv::from_byte_array(&private),
        Err(EncodedXprivDecodeError::Secp256k1(_))
    ));
}

#[test]
fn rejects_invalid_master_metadata_even_with_an_unknown_version() {
    let xpriv = demo_master(NetworkKind::Main);
    let xpub = xpriv.to_xpub();
    for (offset, byte, expected) in [
        (
            5,
            1,
            InvalidXkeyPartsError::NonZeroParentFingerprintForMasterKey(Fingerprint::from([
                1, 0, 0, 0,
            ])),
        ),
        (
            9,
            0x80,
            InvalidXkeyPartsError::NonZeroChildNumberForMasterKey(ChildNumber::ZERO_HARDENED),
        ),
    ] {
        let mut public = with_version(xpub.encode(), CUSTOM_VERSION);
        let mut private = with_version(xpriv.encode(), CUSTOM_VERSION);
        public[offset] = byte;
        private[offset] = byte;
        assert!(matches!(
            EncodedXpub::from_byte_array(&public),
            Err(EncodedXpubDecodeError::Xkey(e)) if e == expected
        ));
        assert!(matches!(
            EncodedXpriv::from_byte_array(&private),
            Err(EncodedXprivDecodeError::Xkey(e)) if e == expected
        ));
    }
}

#[test]
fn private_debug_does_not_reveal_the_scalar() {
    let mut payload = with_version(demo_master(NetworkKind::Main).encode(), CUSTOM_VERSION);
    let key = EncodedXpriv::from_byte_array(&payload).unwrap();
    payload[KEY_PREFIX + 1..].fill(0x2a);
    let other_key = EncodedXpriv::from_byte_array(&payload).unwrap();
    assert_ne!(key, other_key);
    assert_eq!(format!("{key:?}"), format!("{other_key:?}"));
    assert_eq!(format!("{key:#?}"), format!("{other_key:#?}"));
}

#[test]
#[cfg(feature = "alloc")]
#[cfg(feature = "serde")]
fn serde_preserves_unknown_versions_as_base58check_strings() {
    fn assert_serde<T>(key: &T, text: &str)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Debug + Eq,
    {
        let json = serde_json::to_string(text).unwrap();
        assert_eq!(serde_json::to_string(key).unwrap(), json);
        assert_eq!(&serde_json::from_str::<T>(&json).unwrap(), key);
        let binary = bincode::serialize(text).unwrap();
        assert_eq!(bincode::serialize(key).unwrap(), binary);
        assert_eq!(&bincode::deserialize::<T>(&binary).unwrap(), key);
    }

    let xpriv = demo_master(NetworkKind::Main);
    let public = with_version(xpriv.to_xpub().encode(), CUSTOM_VERSION);
    let private = with_version(xpriv.encode(), CUSTOM_VERSION);
    assert_serde(
        &EncodedXpub::from_byte_array(&public).unwrap(),
        Base58CkString::encode(&public).unwrap().as_str(),
    );
    assert_serde(
        &EncodedXpriv::from_byte_array(&private).unwrap(),
        Base58CkString::encode(&private).unwrap().as_str(),
    );
}
