use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
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
    // This example establishes a connection to a Bitcoin node, performs the handshake,
    // and sends a "getaddr" message to request a list of known peers.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: cargo run --example get_addr -- <address> [network]");
        process::exit(1);
    }

    let str_address = &args[1];
    let address: SocketAddr = str_address.parse().unwrap_or_else(|error| {
        eprintln!("error parsing address: {error:?}");
        process::exit(1);
    });

    let network_name = if args.len() > 2 { &args[2] } else { "bitcoin" };
    let magic = match network_name {
        "bitcoin" => Magic::BITCOIN,
        "testnet" => Magic::TESTNET3,
        "signet" => Magic::SIGNET,
        "regtest" => Magic::REGTEST,
        _ => {
            eprintln!("unknown network: {}", network_name);
            process::exit(1);
        }
    };

    let version_message = build_version_message(address, magic);
    let first_message = message::RawNetworkMessage::new(magic, version_message);

    match TcpStream::connect(address) {
        Ok(mut stream) => {
            // Send Version
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
                        println!("Received version message");
                        let verack_message =
                            message::RawNetworkMessage::new(magic, message::NetworkMessage::Verack);
                        encoding::encode_to_writer(&verack_message, &mut stream).unwrap();
                        println!("Sent verack message");
                    }
                    message::NetworkMessage::Verack => {
                        println!("Received verack message");

                        // Handshake complete, send getaddr
                        let msg = message::RawNetworkMessage::new(
                            magic,
                            message::NetworkMessage::GetAddr,
                        );
                        encoding::encode_to_writer(&msg, &mut stream).unwrap();
                        println!("Sent getaddr message");
                    }
                    message::NetworkMessage::Addr(addr_msg) => {
                        let count = addr_msg.0.len();
                        println!("Received addr message: {} addresses", count);
                        for (i, (timestamp, addr)) in addr_msg.0.iter().enumerate() {
                            if i >= 10 {
                                println!("... and {} more", count - 10);
                                break;
                            }
                            // Just print IP and Port
                            println!(
                                "  [{}] {:?}:{} (Time: {})",
                                i, addr.address, addr.port, timestamp
                            );
                        }
                        break;
                    }
                    message::NetworkMessage::AddrV2(addr_msg) => {
                        let count = addr_msg.0.len();
                        println!("Received addrv2 message: {} addresses", count);
                        // AddrV2 is preferred by modern nodes, handle it too just in case
                        for (i, addr) in addr_msg.0.iter().enumerate() {
                            if i >= 10 {
                                println!("... and {} more", count - 10);
                                break;
                            }
                            println!("  [{}] {:?}", i, addr);
                        }
                        break;
                    }
                    _ => {
                        // println!("Received other message: {}", reply.cmd());
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("failed to open connection: {}", e);
        }
    }
}

fn build_version_message(address: SocketAddr, magic: Magic) -> message::NetworkMessage {
    let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    let protocol_version = if magic == Magic::SIGNET {
        ProtocolVersion::from_nonstandard(70014)
    } else {
        ProtocolVersion::BIP0031_VERSION
    };

    // Advertise that we can understand AddrV2 (optional but good practice)
    let services = ServiceFlags::NONE;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time error").as_secs();
    let addr_recv = address::Address::new(&address, ServiceFlags::NONE);
    let addr_from = address::Address::new(&my_address, ServiceFlags::NONE);
    let nonce: u64 = 42;
    let start_height: i32 = 0;
    let user_agent = UserAgent::new(SOFTWARE_NAME, &USER_AGENT_VERSION);

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
