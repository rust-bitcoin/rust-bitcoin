//! Demonstrates how to use the `hash_newtype` macro.

use bitcoin_hashes::HashEngine;

use self::abstraction::{Foo, General, GeneralEngine};

fn main() {
    // Quick hash of some arbitrary data.
    let hash = General::hash(&[]);
    println!("A general (sha256) hash of []: {}", hash);

    // Full access to the engine and use of the `HashEngine` trait.
    let mut engine = GeneralEngine::new();
    engine.input(b"some data");
    let _ = General::from_engine(engine);

    // As expected, this does not build.
    // let hash = abstraction::Custom::hash(&[]);

    let hash = abstraction::custom_hash(&[]);
    println!("A limited (sha256) hash of []: {}", hash);

    // As expected, this does not build.
    // let hash = abstraction::Limited::hash(&[]);

    let hash = abstraction::limited_hash(Foo::default());
    println!("A limited (sha256) hash of []: {}", hash);

    // As expected, this does not build.
    // let hash = abstraction::Private::hash(&[]);
}

/// Abstraction for an example crate/module.
mod abstraction {
    use bitcoin_hashes::{hash_newtype, sha256, HashEngine};

    hash_newtype! {
        /// The new private engine wrapper type using the sha256 hashing algorithm.
        struct PrivateEngine(sha256);

        /// A private hash wrapper type.
        struct Private(_);
    }

    hash_newtype! {
        /// The new private engine type, using custom hashing logic.
        struct CustomEngine(sha256);

        /// A custom purpose hash wrapper type.
        pub struct Custom(_);
    }

    hash_newtype! {
        /// The new private engine type, providing some limited hashing logic.
        struct LimitedEngine(sha256);

        /// A limited purpose hash wrapper type.
        pub struct Limited(_);
    }

    hash_newtype! {
        /// The new public engine type.
        pub struct GeneralEngine(sha256);

        /// A general purpose hash wrapper type.
        pub struct General(_);
    }

    /// A custom hash used to control how arbitrary data is hashed.
    ///
    /// `Custom` demonstrates a usecase where we want to provide some particular hashing logic,
    /// as opposed to allowing consumers to hash arbitrary data.
    ///
    /// Only the module/crate that defines the `Custom` can hash arbitrary data, consumers of
    /// the type do not have access to the `engine()` function.
    pub fn custom_hash(data: &[u8]) -> Custom {
        let mut engine = Custom::engine();

        // Some example custom hashing logic.
        engine.input(b"some example data that gets hash first");
        engine.input(data);

        Custom::from_engine(engine)
    }

    /// A limited hash used to prohibit hashing arbitrary data.
    ///
    /// This is how we do things in `rust-bitcoin` e.g., `Txid`.
    ///
    /// `Limited` demonstrates a usecase where we want to provide some particular hashing logic,
    /// as opposed to allowing consumers to hash arbitrary data.
    ///
    /// Only the module/crate that defines the `Limited` can hash arbitrary data, consumers of
    /// the type do not have access to the `engine()` function.
    pub fn limited_hash(f: Foo) -> Limited {
        let mut engine = Limited::engine();

        // Some example custom hashing logic that depends on `foo`.
        engine.input(b"foo");
        engine.input(&f.this.to_be_bytes());
        engine.input(&f.that.to_be_bytes());

        Limited::from_engine(engine)
    }

    /// Some type that can be hashed into a `Limited` type.
    pub struct Foo {
        this: u32,
        that: u32,
    }

    impl Default for Foo {
        fn default() -> Self { Self { this: 1, that: 2 } }
    }
}
