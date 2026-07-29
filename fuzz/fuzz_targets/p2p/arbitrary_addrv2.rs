#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use p2p::address::AddrV2;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(addr_v2: AddrV2) {
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

fuzz_target!(|data: AddrV2| {
    do_test(data);
});
