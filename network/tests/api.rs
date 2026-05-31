// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `bitcoin-network-kind`.
//!
//! The point of these tests is to check the API surface as opposed to test the API functionality.
//!
//! See [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/about.html).

#![allow(dead_code)]
#![allow(unused_imports)]

use core::fmt;
use core::str::FromStr;

use bitcoin_network_kind::{Network, NetworkKind, ParseNetworkError, TestnetVersion};

/// A struct that includes all public non-error enums.
/// C-COMMON-TRAITS: `Copy`, `Clone`, `Debug`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash`
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Enums {
    a: NetworkKind,
    b: Network,
    c: TestnetVersion,
}

impl Enums {
    fn new() -> Self { Self { a: NetworkKind::Main, b: Network::Bitcoin, c: TestnetVersion::V3 } }
}

/// A struct that includes all public error types.
/// This set of derives for errors are `rust-bitcoin` policy.
/// C-COMMON-TRAITS: `Clone`, `Debug`, `PartialEq`, `Eq`
#[derive(Clone, Debug, PartialEq, Eq)]
struct Errors {
    a: ParseNetworkError,
}

impl Errors {
    fn new() -> Self { Self { a: Network::from_str("invalid").unwrap_err() } }
}

/// C-SEND-SYNC: Tests that all public types implement `Send` + `Sync`.
#[test]
fn api_all_types_implement_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}

    is_send_sync::<Enums>();
    is_send_sync::<Errors>();
}

/// C-DEBUG-NONEMPTY: Tests that all public types have non-empty Debug.
#[test]
fn api_all_types_have_non_empty_debug() {
    let enums = Enums::new();
    let errors = Errors::new();

    assert!(!format!("{:?}", enums.a).is_empty());
    assert!(!format!("{:?}", enums.b).is_empty());
    assert!(!format!("{:?}", enums.c).is_empty());
    assert!(!format!("{:?}", errors.a).is_empty());
}

/// C-GOOD-ERR: Tests that all public error types implement Display.
#[test]
fn api_all_error_types_implement_display() {
    fn assert_display<T: fmt::Display>() {}

    assert_display::<ParseNetworkError>();
}

/// C-GOOD-ERR: Tests that all public error types implement [`std::error::Error`].
#[test]
#[cfg(feature = "std")]
fn api_all_error_types_implement_error() {
    fn assert_error<T: std::error::Error>() {}

    assert_error::<ParseNetworkError>();
}

/// C-CONV-TRAITS: Tests that conversion traits are implemented where expected.
#[test]
fn api_conversion_traits_implemented() {
    fn assert_from<T: From<U>, U>() {}
    fn assert_fromstr<T: FromStr>() {}
    fn assert_asref_self<T: AsRef<T>>() {}

    assert_from::<NetworkKind, Network>();
    assert_fromstr::<Network>();
    assert_asref_self::<Network>();
}

/// C-SERDE: Tests that serde traits are implemented where expected.
#[test]
#[cfg(feature = "serde")]
fn api_serde_traits_implemented() {
    fn assert_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}

    assert_serde::<NetworkKind>();
    assert_serde::<Network>();
}
