//! Demo the `PushBytes` API.

use crypto::sighash::EcdsaSighashType;
use bitcoin::ext::*;
use bitcoin::script::{self, ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin::{ecdsa, secp256k1, taproot, LegacyPublicKey};

fn main() {
    // Use the `AsRef<PushBytes> for SerializedLegacyPublicKey` impl.
    let mut script = ScriptPubKeyBuf::new();
    let pk = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        .parse::<LegacyPublicKey>()
        .unwrap();
    let key = pk.to_bytes(); // SerializedLegacyPublicKey
    script.push_slice(script::legacy_public_key_as_push_bytes(&key));

    // Use the `AsRef<PushBytes> for ecdsa::SerializedSignature` impl.
    let mut script = ScriptSigBuf::new();
    const ECDSA: &str = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";
    let sig = ecdsa::Signature {
        signature: ECDSA.parse::<secp256k1::ecdsa::Signature>().unwrap(),
        sighash_type: EcdsaSighashType::All,
    };
    let ecdsa = sig.serialize(); // ecdsa::SerializedSignature
    script.push_slice(script::ecdsa_serialized_signature_as_push_bytes(&ecdsa));

    // Use the `AsRef<PushBytes> for taproot::SerializedSignature` impl.
    let mut script = ScriptSigBuf::new();
    const TAPROOT: &str = "abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab";
    let sig = TAPROOT.parse::<taproot::Signature>().unwrap();
    let taproot = sig.serialize(); // taproot::SerilaizedSignature
    script.push_slice(script::taproot_serialized_signature_as_push_bytes(&taproot));
}
