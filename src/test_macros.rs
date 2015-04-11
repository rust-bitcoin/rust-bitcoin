// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Macros
//!
//! Internal macros used for unit tests

#[macro_export]
macro_rules! serde_round_trip (
    ($var:expr) => ({
        use serde::{json, Serialize, Deserialize};

        let start = $var;
        let mut encoded = Vec::new();
        {
            let mut serializer = json::ser::Serializer::new(&mut encoded);
            start.serialize(&mut serializer).unwrap();
        }
        let mut deserializer = json::de::Deserializer::new(encoded.iter().map(|c| Ok(*c))).unwrap();
        let decoded = Deserialize::deserialize(&mut deserializer);
        assert_eq!(Some(start), decoded.ok());
    })
);

