//! Shared utilities for fuzz targets.

use std::fmt;
use std::ops::Deref;

use bitcoin_consensus_encoding::{decode_from_slice, Decode, Decoder, Encode, Encoder};

/// Checks roundtrip decode -> encode for a type.
///
/// Verifies that for all byte slices that decode successfully, the decoded value
/// re-encodes to a slice that decodes back to the same value.
pub fn check_roundtrip<T>(data: &[u8])
where
    T: Encode + Decode + PartialEq + fmt::Debug,
    <<T as Decode>::Decoder as Decoder>::Error: fmt::Debug,
{
    if let Ok(base_decoded) = decode_from_slice::<T>(data) {
        let decoded = stream_encode_decode::<_, T>(&base_decoded);
        assert_eq!(base_decoded, decoded);
    }
}

/// Checks roundtrip decode -> encode for a script type that derefs to its encoding target.
///
/// Script `Buf` types (e.g. `ScriptPubKeyBuf`) implement `Encode` via `Deref` to their
/// unsized counterpart (e.g. `ScriptPubKey`), so encoding must go through the deref.
pub fn check_script_roundtrip<T>(data: &[u8])
where
    T: Decode + PartialEq + fmt::Debug + Deref,
    <T as Deref>::Target: Encode,
    <<T as Decode>::Decoder as Decoder>::Error: fmt::Debug,
{
    if let Ok(base_decoded) = decode_from_slice::<T>(data) {
        let decoded = stream_encode_decode::<<T as Deref>::Target, T>(&*base_decoded);
        assert_eq!(base_decoded, decoded);
    }
}

#[inline]
fn stream_encode_decode<E, D>(encodable: &E) -> D
where
    E: Encode + ?Sized,
    D: Decode,
    <<D as Decode>::Decoder as Decoder>::Error: fmt::Debug,
{
    let mut encoder = encodable.encoder();
    let mut decoder = D::decoder();
    loop {
        let mut chunk = encoder.current_chunk();
        while !chunk.is_empty() && decoder.push_bytes(&mut chunk).unwrap() {}
        if !chunk.is_empty() || !encoder.advance() {
            break;
        }
    }
    decoder.end().unwrap()
}
