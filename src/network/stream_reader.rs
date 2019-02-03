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

//! Stream reader
//!
//! This module defines `StreamReader` struct and its implementation which is used
//! for parsing incoming stream into separate `RawNetworkMessage`s, handling assembling
//! messages from multiple packets or dealing with partial or multiple messages in the stream
//! (like can happen with reading from TCP socket)
//!

use std::fmt;
use std::io;
use std::io::Read;
use std::sync::mpsc::Sender;

use util;
use network::message::{NetworkMessage, RawNetworkMessage};
use consensus::encode;

/// A response from the peer-connected socket
pub enum SocketResponse {
    /// A message was received
    MessageReceived(NetworkMessage),
    /// An error occurred and the socket needs to close
    ConnectionFailed(util::Error, Sender<()>)
}

/// Struct used to configure stream reader function
pub struct StreamReader<'a> {
    /// Size of allocated buffer for a single read opetaion
    pub buffer_size: usize,
    /// Stream to read from
    pub stream: &'a mut Read,
    /// Buffer containing unparsed message part
    unparsed: Vec<u8>
}

impl<'a> fmt::Debug for StreamReader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "StreamReader with buffer_size={} and unparsed content {:?}",
               self.buffer_size, self.unparsed)
    }
}

impl<'a> StreamReader<'a> {
    /// Constructs new stream reader for a given input stream `stream` with
    /// optional parameter `buffer_size` determining reading buffer size
    pub fn new(stream: &mut Read, buffer_size: Option<usize>) -> StreamReader {
        StreamReader {
            stream,
            buffer_size: buffer_size.unwrap_or(64 * 1024),
            unparsed: vec![]
        }
    }

    /// Reads stream and parses messages from its current input,
    /// also taking into account previously unparsed partial message (if there was such).
    pub fn read_messages(&mut self) -> Result<Vec<RawNetworkMessage>, encode::Error> {
        let mut messages: Vec<RawNetworkMessage> = vec![];
        let mut data = vec![0u8; self.buffer_size];
        while messages.len() == 0 {
            let count = self.stream.read(&mut data)?;
            if count > 0 {
                self.unparsed.extend(data[0..count].iter());
            }
            messages.append(&mut self.parse()?);
        }
        return Ok(messages)
    }

    fn parse(&mut self) -> Result<Vec<RawNetworkMessage>, encode::Error> {
        let mut messages: Vec<RawNetworkMessage> = vec![];
        while self.unparsed.len() > 0 {
            match encode::deserialize_partial::<RawNetworkMessage>(&self.unparsed) {
                // In this case we just have an incomplete data, so we need to read more
                Err(encode::Error::Io(ref err)) if err.kind() == io::ErrorKind::UnexpectedEof =>
                    return Ok(messages),
                // All other types of errors should be passed up to the caller
                Err(err) => return Err(err),
                // We have successfully read from the buffer
                Ok((message, index)) => {
                    messages.push(message);
                    self.unparsed.drain(..index);
                },
            }
        }
        Ok(messages)
    }
}

#[cfg(test)]
mod test {
    extern crate tempfile;

    use std::thread;
    use std::time::Duration;
    use std::fs::File;
    use std::io::{Write, Seek, SeekFrom};

    use super::StreamReader;
    use network::message::NetworkMessage;

    const MSG_VERSION: [u8; 126] = [
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
        0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01
    ];

    const MSG_PING: [u8; 32] = [
        0xf9, 0xbe, 0xb4, 0xd9, 0x70, 0x69, 0x6e, 0x67,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x24, 0x67, 0xf1, 0x1d,
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    fn init_stream(buf: &[u8]) -> File {
        let mut tmpfile: File = tempfile::tempfile().unwrap();
        write_file(&mut tmpfile, &buf);
        tmpfile
    }

    fn write_file(tmpfile: &mut File, buf: &[u8]) {
        tmpfile.seek(SeekFrom::End(0)).unwrap();
        tmpfile.write(&buf).unwrap();
        tmpfile.flush().unwrap();
        tmpfile.seek(SeekFrom::Start(0)).unwrap();
    }

    #[test]
    fn read_partialmsg_test() {
        let len = MSG_VERSION.len();
        let mut stream = init_stream(&MSG_VERSION[..len-10]);
        thread::spawn(move || {
            StreamReader::new(&mut stream, None).read_messages().unwrap();
            panic!("I should never complete");
        });
        thread::sleep(Duration::from_secs(1));
    }

    #[test]
    fn read_singlemsg_test() {
        let mut stream = init_stream(&MSG_VERSION);
        let messages = StreamReader::new(&mut stream, None).read_messages().unwrap();
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn read_doublemsgs_test() {
        let mut stream = init_stream(&MSG_VERSION);
        write_file(&mut stream, &MSG_PING);

        let messages = StreamReader::new(&mut stream, None).read_messages().unwrap();
        assert_eq!(messages.len(), 2);

        let msg = messages.first().unwrap();
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(ref version_msg) = msg.payload {
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

        let msg = messages.last().unwrap();
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Ping(nonce) = msg.payload {
            assert_eq!(nonce, 100);
        } else {
            panic!("Wrong message type");
        }
    }
}
