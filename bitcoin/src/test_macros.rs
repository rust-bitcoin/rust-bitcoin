// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin serde macros.
//!
//! This module provides internal macros used for unit tests.
//!

#[cfg(feature = "serde")]
macro_rules! serde_round_trip (
    ($var:expr) => ({
        use serde_json;

        let encoded = serde_json::to_value(&$var).unwrap();
        let decoded = serde_json::from_value(encoded).unwrap();
        assert_eq!($var, decoded);
    })
);
