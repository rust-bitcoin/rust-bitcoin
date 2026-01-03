use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use bitcoin_p2p_messages::message_network::{ClientSoftwareVersion, UserAgent, UserAgentVersion};
use bitcoin_p2p_messages::{
    self, address, message, message_network, Magic, ProtocolVersion, ServiceFlags,
};

const SOFTWARE_VERSION: ClientSoftwareVersion =
    ClientSoftwareVersion::SemVer { major: 0, minor: 1, revision: 0 };
const USER_AGENT_VERSION: UserAgentVersion = UserAgentVersion::new(SOFTWARE_VERSION);
const SOFTWARE_NAME: &str = "rust-client";

fn main() {
    // This example establishes a connection to a Bitcoin node, sends the initial
    // "version" message, waits for the reply, and finally closes the connection.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("not enough arguments");
        process::exit(1);
    }

    let str_address = &args[1];

    let address: SocketAddr = str_address.parse().unwrap_or_else(|error| {
        eprintln!("error parsing address: {error:?}");
        process::exit(1);
    });

    let version_message = build_version_message(address);

    let first_message = message::RawNetworkMessage::new(Magic::BITCOIN, version_message);

    if let Ok(mut stream) = TcpStream::connect(address) {
        // Send the message
        encoding::encode_to_writer(&first_message, &mut stream).unwrap();
        println!("Sent version message");

        // Setup StreamReader
        let read_stream = stream.try_clone().unwrap();
        let mut stream_reader = BufReader::new(read_stream);
        loop {
            // Loop and retrieve new messages
            let reply =
                encoding::decode_from_read::<message::RawNetworkMessage, _>(&mut stream_reader)
                    .unwrap();
            match reply.payload() {
                message::NetworkMessage::Version(_) => {
                    println!("Received version message: {:?}", reply.payload());

                    let second_message = message::RawNetworkMessage::new(
                        Magic::BITCOIN,
                        message::NetworkMessage::Verack,
                    );

                    encoding::encode_to_writer(&second_message, &mut stream).unwrap();
                    println!("Sent verack message");
                }
                message::NetworkMessage::Verack => {
                    println!("Received verack message: {:?}", reply.payload());
                }
                message::NetworkMessage::Alert(a) => {
                    println!("Danger, will robinson!: {:?}", a);
                    break;
                }
                _ => {
                    println!("Received unknown message: {:?}", reply.payload());
                    break;
                }
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    } else {
        eprintln!("failed to open connection");
    }
}

fn build_version_message(address: SocketAddr) -> message::NetworkMessage {
    // Building version message, see https://en.bitcoin.it/wiki/Protocol_documentation#version
    let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    // The version of the p2p protocol this client will use
    let protocol_version = ProtocolVersion::BIP0031_VERSION;

    // "bitfield of features to be enabled for this connection"
    let services = ServiceFlags::NONE;

    // "standard UNIX timestamp in seconds"
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time error").as_secs();

    // "The network address of the node receiving this message"
    let addr_recv = address::Address::new(&address, ServiceFlags::NONE);

    // "The network address of the node emitting this message"
    let addr_from = address::Address::new(&my_address, ServiceFlags::NONE);

    // "Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self."
    // Because this crate does not include the `rand` dependency, this is a fixed value.
    let nonce: u64 = 42;

    // "The last block received by the emitting node"
    let start_height: i32 = 0;

    // A formatted string describing the software in use.
    let user_agent = UserAgent::new(SOFTWARE_NAME, &USER_AGENT_VERSION);

    // Construct the message
    message::NetworkMessage::Version(message_network::VersionMessage::new(
        protocol_version,
        services,
        timestamp as i64,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
    ))
}
