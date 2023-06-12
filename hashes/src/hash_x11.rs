// Rust Dash Library
// Originally written in 2014 by
//     Dmitrii Golubev <dmitrii.golubev@dash.org>
//     For Dash
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

//! An implementation of a hash engine to support the X1 hash,
//! which is a wrapper around the rs-x11-hash library.

use core::ops::Index;
use core::slice::SliceIndex;
use core::{str};

#[cfg(feature = "std")]
use std::io;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(all(feature = "core2", not(feature = "std")))]
use core2::io;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use crate::alloc::vec::Vec;

use crate::{hex, Error, HashEngine as _};

crate::internal_macros::hash_type! {
    256,
    true,
    "Output of the X11 hash function.",
    "crate::util::json_hex_string::len_32"
}

/// Output of the X11 hash function
fn from_engine(e: HashEngine) -> Hash {
    return Hash(e.midstate().to_byte_array());
}

/// A hashing engine of X11 algorithm, which bytes can be serialized into
#[derive(Clone)]
pub struct HashEngine {
    buf: Vec<u8>,
    length: usize,
}

impl Default for HashEngine {
    fn default() -> Self {
        HashEngine {
            buf: Vec::new(),
            length: 0,
        }
    }
}

impl crate::HashEngine for HashEngine {
    type MidState = Midstate;

    const BLOCK_SIZE: usize = 32;

    fn midstate(&self) -> Self::MidState {
        Midstate(rs_x11_hash::get_x11_hash(self.buf.as_slice()))
    }

    fn input(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn n_bytes_hashed(&self) -> usize {
        self.length.clone()
    }
}

/// Output of the X11 hash function
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct Midstate(pub [u8; 32]);

crate::internal_macros::arr_newtype_fmt_impl!(Midstate, 32);
serde_impl!(Midstate, 32);
borrow_slice_impl!(Midstate);

impl<I: SliceIndex<[u8]>> Index<I> for Midstate {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output { &self.0[index] }
}

impl str::FromStr for Midstate {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { hex::FromHex::from_hex(s) }
}

impl Midstate {
    /// Length of the midstate, in bytes.
    const LEN: usize = 32;

    /// Flag indicating whether user-visible serializations of this hash
    /// should be backward. For some reason Satoshi decided this should be
    /// true for `Sha256dHash`, so here we are.
    const DISPLAY_BACKWARD: bool = true;

    /// Construct a new [`Midstate`] from the inner value.
    pub const fn from_byte_array(inner: [u8; 32]) -> Self { Midstate(inner) }

    /// Copies a byte slice into the [`Midstate`] object.
    pub fn from_slice(sl: &[u8]) -> Result<Midstate, Error> {
        if sl.len() != Self::LEN {
            Err(Error::InvalidLength(Self::LEN, sl.len()))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Midstate(ret))
        }
    }

    /// Unwraps the [`Midstate`] and returns the underlying byte array.
    pub fn to_byte_array(self) -> [u8; 32] { self.0 }

    /// Unwraps the [Midstate] and returns the underlying byte array.
    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl hex::FromHex for Midstate {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
        where
            I: Iterator<Item=Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        // DISPLAY_BACKWARD is true
        Ok(Midstate::from_byte_array(hex::FromHex::from_byte_iter(iter.rev())?))
    }
}

impl io::Write for HashEngine {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
