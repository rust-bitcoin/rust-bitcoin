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

//! Sockets
//!
//! This module provides support for low-level network communication.
//!

use std::time::{UNIX_EPOCH, SystemTime};
use rand::{thread_rng, Rng};
use std::io::Write;
use std::net;
use std::sync::{Arc, Mutex};

use network;
use network::constants;
use network::address::Address;
use network::encodable::{ConsensusEncodable, ConsensusDecodable};
use network::message::{RawNetworkMessage, NetworkMessage};
use network::message::NetworkMessage::Version;
use network::message_network::VersionMessage;
use network::serialize::{self, RawEncoder, RawDecoder};
use util;

/// Format an IP address in the 16-byte bitcoin protocol serialization
fn ipaddr_to_bitcoin_addr(addr: &net::SocketAddr) -> [u16; 8] {
    match *addr {
        net::SocketAddr::V4(ref addr) => addr.ip().to_ipv6_mapped().segments(),
        net::SocketAddr::V6(ref addr) => addr.ip().segments()
    }
}

/// A network socket along with information about the peer
#[derive(Clone)]
pub struct Socket {
    /// The underlying TCP socket
    socket: Arc<Mutex<Option<net::TcpStream>>>,
    /// Services supported by us
    pub services: u64,
    /// Our user agent
    pub user_agent: String,
    /// Nonce to identify our `version` messages
    pub version_nonce: u64,
    /// Network magic
    pub magic: u32
}

macro_rules! with_socket(($s:ident, $sock:ident, $body:block) => ({
    use ::std::ops::DerefMut;
    let sock_lock = $s.socket.lock();
    match sock_lock {
        Err(_) => {
            Err(network::Error::SocketMutexPoisoned.into())
        }
        Ok(mut guard) => {
            match *guard.deref_mut() {
                Some(ref mut $sock) => {
                    $body
                }
                None => {
                    Err(network::Error::SocketNotConnectedToPeer.into())
                }
            }
        }
    }
}));

impl Socket {
    // TODO: we fix services to 0
    /// Construct a new socket
    pub fn new(network: constants::Network) -> Socket {
        let mut rng = thread_rng();
        Socket {
            socket: Arc::new(Mutex::new(None)),
            services: 0,
            version_nonce: rng.gen(),
            user_agent: constants::USER_AGENT.to_owned(),
            magic: network.magic(),
        }
    }

    /// (Re)connect to the peer
    pub fn connect(&mut self, host: &str, port: u16) -> Result<(), network::Error> {
        // Entirely replace the Mutex, in case it was poisoned;
        // this will also drop any preexisting socket that might be open
        match net::TcpStream::connect((host, port)) {
            Ok(s) => {
                self.socket = Arc::new(Mutex::new(Some(s)));
                Ok(()) 
            }
            Err(e) => {
                self.socket = Arc::new(Mutex::new(None));
                Err(network::Error::Io(e))
            }
        }
    }

    /// Peer address
    pub fn receiver_address(&mut self) -> Result<Address, network::Error> {
        with_socket!(self, sock, {
            match sock.peer_addr() {
                Ok(addr) => {
                    Ok(Address {
                        services: self.services,
                        address: ipaddr_to_bitcoin_addr(&addr),
                        port: addr.port()
                    })
                },
                Err(e) => Err(network::Error::Io(e))
            }
        })
    }

    /// Our own address
    pub fn sender_address(&mut self) -> Result<Address, network::Error> {
        with_socket!(self, sock, {
            match sock.local_addr() {
                Ok(addr) => {
                    Ok(Address {
                        services: self.services,
                        address: ipaddr_to_bitcoin_addr(&addr),
                        port: addr.port()
                    })
                },
                Err(e) => Err(network::Error::Io(e))
            }
        })
    }

    /// Produce a version message appropriate for this socket
    pub fn version_message(&mut self, start_height: i32) -> Result<NetworkMessage, network::Error> {
        let recv_addr = self.receiver_address()?;
        let send_addr = self.sender_address()?;
        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(dur) => dur,
            Err(err) => err.duration(),
        }.as_secs() as i64;

        Ok(Version(VersionMessage {
            version: constants::PROTOCOL_VERSION,
            services: constants::SERVICES,
            timestamp: timestamp,
            receiver: recv_addr,
            sender: send_addr,
            nonce: self.version_nonce,
            user_agent: self.user_agent.clone(),
            start_height: start_height,
            relay: false
        }))
    }

    /// Send a general message across the line
    pub fn send_message(&mut self, payload: NetworkMessage) -> Result<(), util::Error> {
        with_socket!(self, sock, {
            let message = RawNetworkMessage { magic: self.magic, payload: payload };
            message.consensus_encode(&mut RawEncoder::new(&mut *sock))?;
            sock.flush().map_err(network::Error::Io).map_err(util::Error::Network)
        })
    }

    /// Receive the next message from the peer, decoding the network header
    /// and verifying its correctness. Returns the undecoded payload.
    pub fn receive_message(&mut self) -> Result<NetworkMessage, util::Error> {
        with_socket!(self, sock, { Socket::do_receive_message(sock, self.magic) })
    }

    /// Tries to receive message from the peer if there is some. If there is no message
    /// waiting, returns immediately.
    pub fn try_receive_message(&mut self) -> Result<Option<NetworkMessage>, util::Error> {
        with_socket!(self, sock, {
            let buf = &mut [0; 32];
            match sock.peek(buf) {
                Err(reason) => Err(util::Error::Network(network::Error::Io(reason))),
                Ok(0) => Ok(None),
                Ok(_) => match Socket::do_receive_message(sock, self.magic) {
                    Ok(payload) => Ok(Some(payload)),
                    Err(reason) => Err(reason)
                }
            }
        })
    }
    
    fn do_receive_message(stream: &net::TcpStream, magic: u32) -> Result<NetworkMessage, util::Error> {
        // We need a new scope since the closure in here borrows read_err,
        // and we try to read it afterward. Letting `iter` go out fixes it.
        let mut decoder = RawDecoder::new(stream);

        let decoded: RawNetworkMessage = ConsensusDecodable::consensus_decode(&mut decoder)?;

        // Then for magic (this should come before parse error, but we can't
        // get to it if the deserialization failed). TODO restructure this
        if decoded.magic != magic {
            Err(serialize::Error::UnexpectedNetworkMagic {
                expected: magic,
                actual: decoded.magic,
            }.into())
        } else {
            Ok(decoded.payload)
        }
    }
    
}

