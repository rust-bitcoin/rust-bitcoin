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

//! Network message
//!
//! This module defines the `Message` traits which are used
//! for (de)serializing Bitcoin objects for transmission on the network. It
//! also defines (de)serialization routines for many primitives.
//!

use std::iter;
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::sync::mpsc::Sender;

use blockdata::block;
use blockdata::transaction;
use network::address::Address;
use network::message_network;
use network::message_blockdata;
use consensus::encode::{Decodable, Encodable};
use consensus::encode::CheckedData;
use consensus::encode::{self, serialize, Encoder, Decoder};
use util;

/// Serializer for command string
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CommandString(pub String);

impl<S: Encoder> Encodable<S> for CommandString {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        let &CommandString(ref inner_str) = self;
        let mut rawbytes = [0u8; 12];
        let strbytes = inner_str.as_bytes();
        if strbytes.len() > 12 {
            panic!("Command string longer than 12 bytes");
        }
        for x in 0..strbytes.len() {
            rawbytes[x] = strbytes[x];
        }
        rawbytes.consensus_encode(s)
    }
}

impl<D: Decoder> Decodable<D> for CommandString {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<CommandString, encode::Error> {
        let rawbytes: [u8; 12] = Decodable::consensus_decode(d)?;
        let rv = iter::FromIterator::from_iter(rawbytes.iter().filter_map(|&u| if u > 0 { Some(u as char) } else { None }));
        Ok(CommandString(rv))
    }
}

#[derive(Debug)]
/// Struct used to configure stream reader function
pub struct StreamReaderConfig {
    /// Number of attempts to read data from the stream if the reader returns 0 bytes
    pub iterations: usize,
    /// Size of allocated buffer for a single read opetaion
    pub buffer_size: usize
}

/// Defining default values
impl Default for StreamReaderConfig {
    fn default() -> Self { Self { iterations: 16, buffer_size: 64 * 1024 } }
}

#[derive(Debug)]
/// A Network message
pub struct RawNetworkMessage {
    /// Magic bytes to identify the network these messages are meant for
    pub magic: u32,
    /// The actual message data
    pub payload: NetworkMessage
}

/// A response from the peer-connected socket
pub enum SocketResponse {
    /// A message was received
    MessageReceived(NetworkMessage),
    /// An error occurred and the socket needs to close
    ConnectionFailed(util::Error, Sender<()>)
}

#[derive(Clone, PartialEq, Eq, Debug)]
/// A Network message payload. Proper documentation is available on at
/// [Bitcoin Wiki: Protocol Specification](https://en.bitcoin.it/wiki/Protocol_specification)
pub enum NetworkMessage {
    /// `version`
    Version(message_network::VersionMessage),
    /// `verack`
    Verack,
    /// `addr`
    Addr(Vec<(u32, Address)>),
    /// `inv`
    Inv(Vec<message_blockdata::Inventory>),
    /// `getdata`
    GetData(Vec<message_blockdata::Inventory>),
    /// `notfound`
    NotFound(Vec<message_blockdata::Inventory>),
    /// `getblocks`
    GetBlocks(message_blockdata::GetBlocksMessage),
    /// `getheaders`
    GetHeaders(message_blockdata::GetHeadersMessage),
    /// `mempool`
    MemPool,
    /// tx
    Tx(transaction::Transaction),
    /// `block`
    Block(block::Block),
    /// `headers`
    Headers(Vec<block::LoneBlockHeader>),
    /// `getaddr`
    GetAddr,
    // TODO: checkorder,
    // TODO: submitorder,
    // TODO: reply,
    /// `ping`
    Ping(u64),
    /// `pong`
    Pong(u64),
    // TODO: reject,
    // TODO: bloom filtering
    // TODO: alert
    /// `alert`
    Alert(Vec<u8>)
}

impl RawNetworkMessage {
    /// Return the message command. This is useful for debug outputs.
    pub fn command(&self) -> String {
        match self.payload {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack     => "verack",
            NetworkMessage::Addr(_)    => "addr",
            NetworkMessage::Inv(_)     => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::MemPool    => "mempool",
            NetworkMessage::Tx(_)      => "tx",
            NetworkMessage::Block(_)   => "block",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::GetAddr    => "getaddr",
            NetworkMessage::Ping(_)    => "ping",
            NetworkMessage::Pong(_)    => "pong",
            NetworkMessage::Alert(_)    => "alert",
        }.to_owned()
    }

    /// Reads stream from a TCP socket and parses first message from it, returing
    /// the rest of the unparsed buffer for later usage.
    pub fn from_stream(stream: &mut Read, remaining_part: &mut Vec<u8>,
                       StreamReaderConfig { iterations, buffer_size }: StreamReaderConfig) -> Result<Self, encode::Error> {
        println!("Called with {} iterations and {} ubffer size", iterations, buffer_size);
        let mut iterations = iterations;
        while iterations > 0 {
            iterations -= 1;

            if remaining_part.len() > 0 {
                match encode::deserialize_partial::<RawNetworkMessage>(&remaining_part) {
                    // In this case we just have an incomplete data, so we need to read more
                    Err(encode::Error::Io(ref err)) if err.kind() == io::ErrorKind::UnexpectedEof => (),
                    // All other types of errors should be passed up to the caller
                    Err(err) => return Err(err),
                    // We have successfully read from the buffer
                    Ok((message, index)) => {
                        println!("Deserialized {} bytes", index);
                        remaining_part.drain(..index);
                        return Ok(message)
                    },
                }
            }

            let mut new_data = vec![0u8; buffer_size];
            let count = stream.read(&mut new_data)?;
            if count > 0 {
                remaining_part.extend(new_data[0..count].iter());
            }
            println!("Read {} bytes, remaining part now is {} bytes length", count, remaining_part.len());
        }
        Err(encode::Error::ParseFailed("Zero-length input"))
    }
}

impl<S: Encoder> Encodable<S> for RawNetworkMessage {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.magic.consensus_encode(s)?;
        CommandString(self.command()).consensus_encode(s)?;
        CheckedData(match self.payload {
            NetworkMessage::Version(ref dat) => serialize(dat),
            NetworkMessage::Addr(ref dat)    => serialize(dat),
            NetworkMessage::Inv(ref dat)     => serialize(dat),
            NetworkMessage::GetData(ref dat) => serialize(dat),
            NetworkMessage::NotFound(ref dat) => serialize(dat),
            NetworkMessage::GetBlocks(ref dat) => serialize(dat),
            NetworkMessage::GetHeaders(ref dat) => serialize(dat),
            NetworkMessage::Tx(ref dat)      => serialize(dat),
            NetworkMessage::Block(ref dat)   => serialize(dat),
            NetworkMessage::Headers(ref dat) => serialize(dat),
            NetworkMessage::Ping(ref dat)    => serialize(dat),
            NetworkMessage::Pong(ref dat)    => serialize(dat),
            NetworkMessage::Alert(ref dat)    => serialize(dat),
            NetworkMessage::Verack
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr => vec![],
        }).consensus_encode(s)
    }
}

impl<D: Decoder> Decodable<D> for RawNetworkMessage {
    fn consensus_decode(d: &mut D) -> Result<RawNetworkMessage, encode::Error> {
        let magic = Decodable::consensus_decode(d)?;
        let CommandString(cmd): CommandString= Decodable::consensus_decode(d)?;
        let CheckedData(raw_payload): CheckedData = Decodable::consensus_decode(d)?;

        let mut mem_d = Cursor::new(raw_payload);
        let payload = match &cmd[..] {
            "version" => NetworkMessage::Version(Decodable::consensus_decode(&mut mem_d)?),
            "verack"  => NetworkMessage::Verack,
            "addr"    => NetworkMessage::Addr(Decodable::consensus_decode(&mut mem_d)?),
            "inv"     => NetworkMessage::Inv(Decodable::consensus_decode(&mut mem_d)?),
            "getdata" => NetworkMessage::GetData(Decodable::consensus_decode(&mut mem_d)?),
            "notfound" => NetworkMessage::NotFound(Decodable::consensus_decode(&mut mem_d)?),
            "getblocks" => NetworkMessage::GetBlocks(Decodable::consensus_decode(&mut mem_d)?),
            "getheaders" => NetworkMessage::GetHeaders(Decodable::consensus_decode(&mut mem_d)?),
            "mempool" => NetworkMessage::MemPool,
            "block"   => NetworkMessage::Block(Decodable::consensus_decode(&mut mem_d)?),
            "headers" => NetworkMessage::Headers(Decodable::consensus_decode(&mut mem_d)?),
            "getaddr" => NetworkMessage::GetAddr,
            "ping"    => NetworkMessage::Ping(Decodable::consensus_decode(&mut mem_d)?),
            "pong"    => NetworkMessage::Pong(Decodable::consensus_decode(&mut mem_d)?),
            "tx"      => NetworkMessage::Tx(Decodable::consensus_decode(&mut mem_d)?),
            "alert"   => NetworkMessage::Alert(Decodable::consensus_decode(&mut mem_d)?),
            _ => return Err(encode::Error::UnrecognizedNetworkCommand(cmd)),
        };
        Ok(RawNetworkMessage {
            magic: magic,
            payload: payload
        })
    }
}

#[cfg(test)]
mod test {
    extern crate tempfile;
    use super::{RawNetworkMessage, NetworkMessage, CommandString};
    use consensus::encode::{deserialize, deserialize_partial, serialize};
    use std::io::{Write, Seek, SeekFrom};
    use std::fs::File;

    #[test]
    fn serialize_commandstring_test() {
        let cs = CommandString("Andrew".to_owned());
        assert_eq!(serialize(&cs), vec![0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn deserialize_commandstring_test() {
        let cs: Result<CommandString, _> = deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.unwrap(), CommandString("Andrew".to_owned()));

        let short_cs: Result<CommandString, _> = deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0]);
        assert!(short_cs.is_err());
    }

    #[test]
    fn serialize_verack_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Verack }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61,
                                  0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_ping_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Ping(100) }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x70, 0x69, 0x6e, 0x67,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x08, 0x00, 0x00, 0x00, 0x24, 0x67, 0xf1, 0x1d,
                                  0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }


    #[test]
    fn serialize_mempool_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::MemPool }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x6d, 0x65, 0x6d, 0x70,
                                  0x6f, 0x6f, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_getaddr_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::GetAddr }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                                  0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn deserialize_getaddr_test() {
        let msg = deserialize(
            &[0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
        let preimage = RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::GetAddr };
        assert!(msg.is_ok());
        let msg : RawNetworkMessage = msg.unwrap();
        assert_eq!(preimage.magic, msg.magic);
        assert_eq!(preimage.payload, msg.payload);
    }

    #[test]
    fn deserialize_version_test() {
        let msg = deserialize::<RawNetworkMessage>(
            &[  0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
                0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
                0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
                0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
                0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
                0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01 ]);

        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, 70015);
            assert_eq!(version_msg.services, 1037);
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert_eq!(version_msg.relay, true);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn deserialize_partial_message_test() {
        let data = [  0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01, 0, 0 ];
        let msg = deserialize_partial::<RawNetworkMessage>(&data);
        assert!(msg.is_ok());

        let (msg, consumed) = msg.unwrap();
        assert_eq!(consumed, data.to_vec().len() - 2);
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, 70015);
            assert_eq!(version_msg.services, 1037);
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert_eq!(version_msg.relay, true);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn deserealize_partialmsg_from_stream_test() {
        let mut tmpfile: File = tempfile::tempfile().unwrap();
        tmpfile.write_all(&[
            // version message
            0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
        ]).unwrap();
        tmpfile.flush().unwrap();
        tmpfile.seek(SeekFrom::Start(0)).unwrap();

        let mut buffer = vec![];
        let msg = RawNetworkMessage::from_stream(&mut tmpfile, &mut buffer, Default::default());
        assert!(buffer.len() > 0);
        assert!(msg.is_err());
    }

    #[test]
    fn deserealize_2msgs_from_stream_test() {
        let mut tmpfile: File = tempfile::tempfile().unwrap();
        tmpfile.write_all(&[
            // version message
            0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01,
            // Ping(100) message
            0xf9, 0xbe, 0xb4, 0xd9, 0x70, 0x69, 0x6e, 0x67,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x24, 0x67, 0xf1, 0x1d,
            0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]).unwrap();
        tmpfile.flush().unwrap();
        tmpfile.seek(SeekFrom::Start(0)).unwrap();

        let mut buffer = vec![];
        let msg = RawNetworkMessage::from_stream(&mut tmpfile, &mut buffer, Default::default()).unwrap();
        assert!(buffer.len() > 0);
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, 70015);
            assert_eq!(version_msg.services, 1037);
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert_eq!(version_msg.relay, true);
        } else {
            panic!("Wrong message type");
        }

        println!("{:?}", &buffer);
        let msg = RawNetworkMessage::from_stream(&mut tmpfile, &mut buffer,Default::default()).unwrap();
        assert_eq!(buffer.len(), 0);
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Ping(nonce) = msg.payload {
            assert_eq!(nonce, 100);
        } else {
            panic!("Wrong message type");
        }
    }
}
