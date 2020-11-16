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

//! Network Support
//!
//! This module defines support for (de)serialization and network transport
//! of Bitcoin data and network messages.
//!

use std::fmt;
use std::io;
use std::error;

mod address;
mod constants;
mod message;
mod message_blockdata;
mod message_network;
mod message_filter;
mod stream_reader;

// Re-export all network types.
pub use self::address::{Address, AddrV2, AddrV2Message};
pub use self::constants::{Network, PROTOCOL_VERSION, ServiceFlags};
pub use self::message::{CommandString, NetworkMessage, RawNetworkMessage};
pub use self::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
pub use self::message_network::{Reject, RejectReason, VersionMessage};
pub use self::message_filter::{
    CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters,
};
pub use self::stream_reader::StreamReader;

/// Network error
#[derive(Debug)]
pub enum Error {
    /// And I/O error
    Io(io::Error),
    /// Socket mutex was poisoned
    SocketMutexPoisoned,
    /// Not connected to peer
    SocketNotConnectedToPeer,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => fmt::Display::fmt(e, f),
            Error::SocketMutexPoisoned => f.write_str("socket mutex was poisoned"),
            Error::SocketNotConnectedToPeer => f.write_str("not connected to peer"),
        }
    }
}

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::SocketMutexPoisoned | Error::SocketNotConnectedToPeer => None,
        }
    }
}
