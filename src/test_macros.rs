// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Updated for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash serde macros.
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

/// Checks that error contains a message
#[cfg(test)]
#[macro_export]
macro_rules! assert_error_contains {
    ($result:ident, $contains:expr) => {
        match $result {
            Ok(o) => {
                panic!("expected error, but returned: {:?}", o);
            }
            Err(e) => {
                let string_error = e.to_string();
                if !string_error.contains($contains) {
                    panic!(
                        "assertion error: '{}' hasn't been found in '{}'",
                        $contains, string_error
                    );
                }
            }
        }
    };
}
