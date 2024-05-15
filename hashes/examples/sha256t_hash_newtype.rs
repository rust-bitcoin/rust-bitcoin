//! Demonstrates how to use the `sha256t_hash_newtype` macro.

use bitcoin_hashes::HashEngine;

use self::abstraction::GeneralHash;

fn main() {
    let hash = general_hash();
    println!("A general tagged hash of []: {}", hash);

    let hash = GeneralHash::hash(&[]);
    println!("A general tagged hash of []: {}", hash);

    let hash = abstraction::limited_hash(&[]);
    println!("A limited tagged hash of []: {}", hash);

    // This does not build, as is expected.
    // let hash = abstraction::LimitedHash::hash(&[]);
}

/// A general hash can be used to hash arbitrary data.
fn general_hash() -> GeneralHash {
    let mut engine = GeneralHash::engine();
    engine.input(&[]);
    GeneralHash::from_engine(engine)
}

/// Abstraction for an example crate/module.
mod abstraction {
    use bitcoin_hashes::{sha256t_hash_newtype, HashEngine, Tag};

    sha256t_hash_newtype! {
        /// A `GeneralTag` for tagging general hashes.
        pub struct GeneralTag = hash_str("general");

        /// A general purpose tagged hash wrapper type.
        pub struct GeneralHash(pub _);
    }

    sha256t_hash_newtype! {
        /// A `LimitedTag` for tagging limited hashes.
        pub struct LimitedTag = hash_str("limited");

        /// A limited purpose tagged hash wrapper type.
        pub struct LimitedHash(_);
    }

    /// A limited tagged hash cannot be used to hash arbitrary data.
    ///
    /// `LimitedHash` demonstrates a usecase where we want to provide some particular hashing logic,
    /// as opposed to allowing consumers to hash arbitrary data.
    ///
    /// Only the module/crate that defines the `LimitedHash` can hash arbitrary data, consumers of
    /// the type do not have access to the `engine()` function.
    pub fn limited_hash(data: &[u8]) -> LimitedHash {
        let mut engine = LimitedHash::engine();

        // Some example custom hashing logic.
        engine.input(b"some example data that gets hash first");
        engine.input(data);

        LimitedHash::from_engine(engine)
    }
}
