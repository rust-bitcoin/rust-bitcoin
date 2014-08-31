// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Rust Bitcoin Library
//!
//! This is a library for which supports the Bitcoin network protocol and associated
//! primitives. It is designed for Rust programs built to work with the Bitcoin
//! network.
//!
//! It is also written entirely in Rust to illustrate the benefits of strong type
//! safety, including ownership and lifetime, for financial and/or cryptographic
//! software.
//!

#![crate_name = "bitcoin"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

// Experimental features we need
#![feature(globs)]
#![feature(macro_rules)]
#![feature(overloaded_calls)]
#![feature(unsafe_destructor)]
#![feature(default_type_params)]
#![feature(struct_variant)]
#![feature(unboxed_closure_sugar)]
#![feature(unboxed_closures)]

#![comment = "Rust Bitcoin Library"]
#![license = "CC0"]

// Coding conventions
#![warn(non_uppercase_statics)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_doc)]

extern crate alloc;
extern crate collections;
extern crate core;
extern crate num;
extern crate rand;
extern crate rustrt;
extern crate serialize;
extern crate sync;
extern crate time;

extern crate secp256k1 = "bitcoin-secp256k1-rs";
extern crate crypto = "rust-crypto";

mod internal_macros;
pub mod macros;
pub mod network;
pub mod blockdata;
pub mod util;
pub mod wallet;

