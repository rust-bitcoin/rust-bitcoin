//! Test the API surface of `io`.
//!
//! The point of these tests are to check the API surface as opposed to test the API functionality.
//!
//! ref: <https://rust-lang.github.io/api-guidelines/about.html>

#![allow(dead_code)]
#![allow(unused_imports)]

use core::cell::Cell;
use core::convert::Infallible;

// These imports test "typical" usage by user code.
use bitcoin_io::{self as io, BufRead, Cursor, ErrorKind, FromStd, Read, Take, ToStd, Write};

/// An arbitrary error kind.
const ERROR_KIND: ErrorKind = ErrorKind::TimedOut;

/// A struct that includes all public non-error enums.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Enums {
    a: ErrorKind,
}

impl Enums {
    /// Creates an arbitrary `Enums` instance.
    fn new() -> Self { Self { a: ERROR_KIND } }
}

/// A struct that includes all public non-error structs except `Take`.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Structs {
    a: FromStd<u32>,
    b: ToStd<Dummy>,
    c: Cursor<Dummy>,
}

impl Structs {
    fn new() -> Self { Self { a: FromStd::new(0), b: ToStd::new(DUMMY), c: Cursor::new(DUMMY) } }
}

#[derive(Debug)] // `Take` implements Debug (C-DEBUG).
struct Taker<'a> {
    a: Take<'a, Dummy>,
}

/// An arbitrary `Dummy` instance.
static DUMMY: Dummy = Dummy(0);

/// Dummy struct to implement all the traits we provide.
#[derive(Debug, Copy, Clone)]
struct Dummy(u64);

impl Read for Dummy {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if buf.is_empty() {
            Ok(0)
        } else {
            buf[0] = (self.0 & 0xFF) as u8;
            Ok(1)
        }
    }
}

impl BufRead for Dummy {
    fn fill_buf(&mut self) -> Result<&[u8], io::Error> { Ok(&[]) }
    fn consume(&mut self, _: usize) {}
}

impl Write for Dummy {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> { Ok(buf.len()) }
    fn write_all(&mut self, _: &[u8]) -> Result<(), io::Error> { Ok(()) }
    fn flush(&mut self) -> Result<(), io::Error> { Ok(()) }
}

impl AsRef<[u8]> for Dummy {
    fn as_ref(&self) -> &[u8] { &[] }
}

/// A struct that includes all public non-error types.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Types {
    a: Enums,
    b: Structs,
}

impl Types {
    fn new() -> Self { Self { a: Enums::new(), b: Structs::new() } }
}

/// A struct that includes all public error types.
#[derive(Debug)] // `io::Error` only implements `Debug`.
struct Errors {
    a: io::Error,
}

// `Debug` representation is never empty (C-DEBUG-NONEMPTY).
#[test]
fn api_all_non_error_types_have_non_empty_debug() {
    let t = Types::new();

    let debug = format!("{:?}", t.a.a);
    assert!(!debug.is_empty());

    let debug = format!("{:?}", t.b.a);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.b);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.c);
    assert!(!debug.is_empty());
}

#[test]
fn test_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Types>();
}

#[test]
fn test_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<Types>();
}
