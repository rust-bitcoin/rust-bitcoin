// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
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

//! # A trick that makes cutting-out `secp256k1` easy.
//!
//! One issue with cutting out secp256k1 is that we can't just blindly `#[cfg]`
//! all items that depend on it. Such would include removing enum variants and
//! that would be a huge footgun. Suppose a dependent library of rust-bitcoin
//! would not require secp256k1 and exhaustively match on an enum returned from
//! a function. If another crate depended on `rust-bitcoin` **with**
//! `secp256k1 ` got included in a same project, it would cause breakage.
//!
//! A sane approach is to keep the enum variants and just don't construct them.
//! This works but we want to avoid a sea of `#[cfg]` attributes. So the easiest
//! way to do that is to have a separate module not requiring `secp256k1` and
//! `pub use` its submodules in backwards-compatible way.

pub mod raw;
pub(crate) mod error;

pub(crate) use self::error::Error;
