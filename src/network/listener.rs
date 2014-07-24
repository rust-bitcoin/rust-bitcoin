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

//! # Abstract Bitcoin listener
//!
//! This module defines a listener on the Bitcoin network which is able
//! to connect to a peer, send network messages, and receive Bitcoin data.
//!

use std::io::{IoResult, standard_error, ConnectionFailed};
use std::io::timer;

use network::constants::Network;
use network::message::{NetworkMessage, Verack};
use network::socket::Socket;

/// A message which can be sent on the Bitcoin network
pub trait Listener {
  /// Return a string encoding of the peer's network address
  fn peer<'a>(&'a self) -> &'a str;
  /// Return the port we have connected to the peer on
  fn port(&self) -> u16;
  /// Return the network this `Listener` is operating on
  fn network(&self) -> Network;
  /// Main listen loop
  fn start(&self) -> IoResult<(Receiver<NetworkMessage>, Socket)> {
    // Open socket
    let mut ret_sock = Socket::new(self.network());
    match ret_sock.connect(self.peer(), self.port()) {
      Ok(_) => {},
      Err(_) => return Err(standard_error(ConnectionFailed))
    }
    let mut sock = ret_sock.clone();

    let (recv_tx, recv_rx) = channel();

    // Send version message to peer
    let version_message = try!(sock.version_message(0));
    try!(sock.send_message(version_message));

    // Message loop
    spawn(proc() {
      let mut handshake_complete = false;
      let mut sock = sock;
      loop {
        // Receive new message
        match sock.receive_message() {
          Ok(payload) => {
            // React to any network messages that affect our state.
            match payload {
              // Make an exception for verack since there is no response required
              Verack => {
                // TODO: when the timeout stuff in std::io::net::tcp is sorted out we should
                // actually time out if the verack doesn't come in in time
                if handshake_complete {
                  println!("Received second verack (peer is misbehaving)");
                } else {
                  handshake_complete = true;
                }
              }
              _ => {}
            };
            // We have to pass the message to the main thread for processing,
            // unfortunately, because sipa says we have to handle everything
            // in order.
            recv_tx.send(payload);
          }
          Err(e) => {
            println!("Received error {:} when decoding message. Pausing for 5 seconds then reconnecting.", e);
            timer::sleep(5000);
            // Reconnect
            sock.reconnect()
              // Create version message
              .and_then(|_| sock.version_message(0))
              // Send it out
              .and_then(|msg| sock.send_message(msg))
              // For now, not much we can do on error
              .unwrap_or_else(|e| println!("Error {} when reconnecting.", e));
            handshake_complete = false;
          }
        }
      }
    });
    Ok((recv_rx, ret_sock))
  }
}

