// SPDX-License-Identifier: CC0-1.0

//! Demonstrate reading and writing `rust-bitcoin` objects.
//!
//! The `std::io` module is not exposed in `no-std` Rust so building `no-std` applications which
//! require reading and writing objects via standard traits is not generally possible. To support
//! this we provide the `bitcoin_io` crate which provides `io::Read`, `io::BufRead`, and
//! `io::Write`. This module demonstrates its usage.

use bitcoin::consensus::{Decodable, Encodable as _};
use bitcoin::{OutPoint, Txid};

fn main() {
    // Encode/Decode a `rust-bitcoin` type to/from a stdlib type.
    encode_decode_from_stdlib_type();

    // Encode to a custom type by implementing `bitcoin_io` traits.
    encode_to_custom_type();

    // Encode to a foreign custom type by using the `bitcoin_io::bridge::FromStd` wrapper.
    encode_using_wrapper();
}

/// Encodes/Decodes a `rust-bitcoin` type to/from a stdlib type.
///
/// The consensus encoding and decoding traits are generic over `bitcoin_io::Write` and
/// `bitcoin_io::Read`. However for various stdlib types we implement our traits so _most_ things
/// should just work.
fn encode_decode_from_stdlib_type() {
    let data = dummy_utxo();

    // A type that implements `std::io::Write`.
    let mut v = Vec::new();

    // Under the hood we implement our `io` traits for a bunch of stdlib types so this just works.
    let _bytes_written = data.consensus_encode(&mut v).expect("failed to encode to writer");

    // Slices implement `std::io::Read`.
    let mut reader: &[u8] = v.as_ref();

    let _: OutPoint =
        Decodable::consensus_decode(&mut reader).expect("failed to decode from reader");
}

/// Encodes to a custom type by implementing the `bitcoin_io::Write` trait.
///
/// To use the `Encodable` (and `Decodable`) traits you can implement the `bitcoin_io` traits.
fn encode_to_custom_type() {
    /// A byte counter - counts how many bytes where written to it.
    struct WriteCounter {
        count: usize,
    }

    /// This `io` is `bitcoin_io` - see `Cargo.toml` usage of `io = { package = "bitcoin-io" }`.
    impl io::Write for WriteCounter {
        fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
            let written = buf.len();
            self.count += written;
            Ok(written)
        }
        fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
            self.count += buf.len();
            Ok(())
        }
        fn flush(&mut self) -> Result<(), io::Error> { Ok(()) }
    }

    let data = dummy_utxo();

    let mut counter = WriteCounter { count: 0 };
    let bytes_written = data.consensus_encode(&mut counter).expect("failed to encode to writer");
    assert_eq!(bytes_written, 36); // 32 bytes for txid + 4 bytes for vout.
}

/// Encodes to a custom type by using the `bitcoin_io::bridge` module.
///
/// If you have a type that you don't control that implements `std::io::Write` you can still encode
/// to it by way of the `io::bridge::FromStd` wrapper.
fn encode_using_wrapper() {
    use pretend_this_is_some_other_crate::WriteCounter;

    let data = dummy_utxo();

    // This will not build because `WriteCounter` does not implement `bitcoin_io::Write`.
    //
    // let mut counter = WriteCounter::new();
    // let bytes_written = data.consensus_encode(&mut counter)?;

    let mut counter = io::FromStd::new(WriteCounter::new());
    let bytes_written = data.consensus_encode(&mut counter).expect("failed to encode to writer");
    assert_eq!(bytes_written, 36); // 32 bytes for txid + 4 bytes for vout.
    assert_eq!(bytes_written, counter.get_ref().written());

    // Take back ownership of the `WriteCounter`.
    let _ = counter.into_inner();
}

mod pretend_this_is_some_other_crate {
    /// A byte counter - counts how many bytes where written to it.
    pub struct WriteCounter {
        count: usize,
    }

    impl WriteCounter {
        /// Constructs a new `WriteCounter`.
        pub fn new() -> Self { Self { count: 0 } }

        /// Returns the number of bytes written to this counter.
        pub fn written(&self) -> usize { self.count }
    }

    impl std::io::Write for WriteCounter {
        fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
            let written = buf.len();
            self.count += written;
            Ok(written)
        }
        fn write_all(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
            self.count += buf.len();
            Ok(())
        }
        fn flush(&mut self) -> Result<(), std::io::Error> { Ok(()) }
    }
}

/// Constructs a dummy UTXO that is just to represent some `rust-bitcoin` type that implements the
/// [`consensus::Encodable`] and [`consensus::Decodable`] traits.
fn dummy_utxo() -> OutPoint {
    let txid = Txid::from_byte_array([0xFF; 32]); // Arbitrary invalid dummy value.
    OutPoint { txid, vout: 1 }
}
