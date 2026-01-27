use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process, thread, time};

use bitcoin_p2p_messages::message_network::{ClientSoftwareVersion, UserAgent, UserAgentVersion};
use bitcoin_p2p_messages::{
    self, address, message, message_network, Magic, ProtocolVersion, ServiceFlags,
};

const SOFTWARE_VERSION: ClientSoftwareVersion =
    ClientSoftwareVersion::SemVer { major: 0, minor: 1, revision: 0 };
const USER_AGENT_VERSION: UserAgentVersion = UserAgentVersion::new(SOFTWARE_VERSION);
const SOFTWARE_NAME: &str = "rust-client";

fn main() {
    // This example establishes a connection, performs handshake, and then exchanges PING/PONG messages.
    // It measures the Round Trip Time (RTT).
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: cargo run --example ping_pong -- <address> [network]");
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

            let mut my_ping_nonce: u64 = 0;
            let mut ping_sent_time = SystemTime::now();

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

                        // Handshake complete, send PING
                        my_ping_nonce =
                            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
                        let msg = message::RawNetworkMessage::new(
                            magic,
                            message::NetworkMessage::Ping(my_ping_nonce),
                        );
                        encoding::encode_to_writer(&msg, &mut stream).unwrap();
                        ping_sent_time = SystemTime::now();
                        println!("Sent PING message (nonce: {})", my_ping_nonce);
                    }
                    message::NetworkMessage::Ping(nonce) => {
                        println!("Received PING (nonce: {}). Sending PONG...", nonce);
                        let msg = message::RawNetworkMessage::new(
                            magic,
                            message::NetworkMessage::Pong(*nonce),
                        );
                        encoding::encode_to_writer(&msg, &mut stream).unwrap();
                    }
                    message::NetworkMessage::Pong(nonce) => {
                        println!("Received PONG (nonce: {})", nonce);
                        if *nonce == my_ping_nonce {
                            let rtt = SystemTime::now().duration_since(ping_sent_time).unwrap();
                            println!("Round Trip Time (RTT): {:.2} ms", rtt.as_secs_f64() * 1000.0);

                            // Wait a bit and send another ping
                            println!("Waiting 2 seconds before next ping...");
                            thread::sleep(time::Duration::from_secs(2));

                            my_ping_nonce =
                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
                                    as u64;
                            let msg = message::RawNetworkMessage::new(
                                magic,
                                message::NetworkMessage::Ping(my_ping_nonce),
                            );
                            encoding::encode_to_writer(&msg, &mut stream).unwrap();
                            ping_sent_time = SystemTime::now();
                            println!("Sent PING message (nonce: {})", my_ping_nonce);
                        } else {
                            println!("Received unsolicited Pong or from old ping");
                        }
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
