use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bitcoin::consensus::Decodable;
use bitcoin::p2p::address::AddrV2;
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let mut cursor = std::io::Cursor::new(data);
    let addr_v2 = if let Ok(addr) = AddrV2::consensus_decode(&mut cursor) {
        addr
    } else {
        return;
    };

    if let Ok(ip_addr) = IpAddr::try_from(addr_v2.clone()) {
        let round_trip: AddrV2 = AddrV2::from(ip_addr);
        assert_eq!(
            addr_v2, round_trip,
            "AddrV2 -> IpAddr -> AddrV2 should round-trip correctly"
        );
    }

    if let Ok(ip_addr) = Ipv4Addr::try_from(addr_v2.clone()) {
        let round_trip: AddrV2 = AddrV2::from(ip_addr);
        assert_eq!(
            addr_v2, round_trip,
            "AddrV2 -> Ipv4Addr -> AddrV2 should round-trip correctly"
        );
    }

    if let Ok(ip_addr) = Ipv6Addr::try_from(addr_v2.clone()) {
        let round_trip: AddrV2 = AddrV2::from(ip_addr);
        assert_eq!(
            addr_v2, round_trip,
            "AddrV2 -> Ipv6Addr -> AddrV2 should round-trip correctly"
        );
    }

    if let Ok(socket_addr) = SocketAddr::try_from(addr_v2.clone()) {
        let round_trip: AddrV2 = AddrV2::from(socket_addr);
        assert_eq!(
            addr_v2, round_trip,
            "AddrV2 -> SocketAddr -> AddrV2 should round-trip correctly"
        );
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(all(test, fuzzing))]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
