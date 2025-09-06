use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use arbitrary::{Arbitrary, Unstructured};
use honggfuzz::fuzz;
use p2p::address::AddrV2;

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let a = AddrV2::arbitrary(&mut u);

    if let Ok(addr_v2) = a {
        if let Ok(ip_addr) = IpAddr::try_from(addr_v2.clone()) {
            let round_trip: AddrV2 = AddrV2::from(ip_addr);
            assert_eq!(addr_v2, round_trip, "AddrV2 -> IpAddr -> AddrV2 should round-trip correctly");
        }

        if let Ok(ip_addr) = Ipv4Addr::try_from(addr_v2.clone()) {
            let round_trip: AddrV2 = AddrV2::from(ip_addr);
            assert_eq!(addr_v2, round_trip, "AddrV2 -> Ipv4Addr -> AddrV2 should round-trip correctly");
        }

        if let Ok(ip_addr) = Ipv6Addr::try_from(addr_v2.clone()) {
            let round_trip: AddrV2 = AddrV2::from(ip_addr);
            assert_eq!(addr_v2, round_trip, "AddrV2 -> Ipv6Addr -> AddrV2 should round-trip correctly");
        }
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
