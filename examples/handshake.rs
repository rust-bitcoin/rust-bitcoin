use rand::Rng;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode;
use bitcoin::network::address;
use bitcoin::network::constants;
use bitcoin::network::message;
use bitcoin::network::message_network;
use bitcoin::network::stream_reader::StreamReader;

fn main() {
    // This example establishes a connection to a Bitcoin node, sends the intial
    // "version" message, waits for the reply, and finally closes the connection.

    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(130, 149, 80, 221)), 8333);

    let version_message = build_version_message(address);

    let first_message = message::RawNetworkMessage {
        magic: constants::Network::Bitcoin.magic(),
        payload: version_message,
    };

    if let Ok(mut stream) = TcpStream::connect(address) {
        // Send the message
        let _ = stream.write(encode::serialize(&first_message).as_slice());
        println!("Sent version message");

        // Wait for reply and close stream

        loop {
            let reply = StreamReader::new(&mut stream, None).read_next();
            let unwrapped: message::RawNetworkMessage = reply.unwrap();
            match unwrapped.payload {
                message::NetworkMessage::Version(_) => {
                    println!("Received version message: {:?}", unwrapped.payload);

                    let second_message = message::RawNetworkMessage {
                        magic: constants::Network::Bitcoin.magic(),
                        payload: message::NetworkMessage::Verack,
                    };

                    let _ = stream.write(encode::serialize(&second_message).as_slice());
                    println!("Sent verack message");
                }
                message::NetworkMessage::Verack => {
                    println!("Received verack message: {:?}", unwrapped.payload);
                    break;
                }
                _ => {
                    println!("Received unknown message: {:?}", unwrapped.payload);
                    break;
                }
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    } else {
        eprintln!("Failed to open connection");
    }
}

fn build_version_message(address: SocketAddr) -> message::NetworkMessage {
    // Building version message, see https://en.bitcoin.it/wiki/Protocol_documentation#version
    let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    // "bitfield of features to be enabled for this connection"
    let services = constants::ServiceFlags::NONE;

    // "standard UNIX timestamp in seconds"
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs();

    // "The network address of the node receiving this message"
    let addr_recv = address::Address::new(&address, constants::ServiceFlags::NONE);

    // "The network address of the node emitting this message"
    let addr_from = address::Address::new(&my_address, constants::ServiceFlags::NONE);

    // "Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self."
    let nonce: u64 = rand::thread_rng().gen();

    // "User Agent (0x00 if string is 0 bytes long)"
    let user_agent = String::from("rust-example");

    // "The last block received by the emitting node"
    let start_height: i32 = 0;

    // Construct the message
    message::NetworkMessage::Version(message_network::VersionMessage::new(
        services,
        timestamp as i64,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
    ))
}
