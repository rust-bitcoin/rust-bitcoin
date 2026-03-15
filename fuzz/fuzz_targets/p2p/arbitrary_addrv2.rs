#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

use arbitrary::{Arbitrary, Unstructured};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use p2p::address::AddrV2;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let a = AddrV2::arbitrary(&mut u);

    if let Ok(addr_v2) = a {
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
    }
}

fuzz_target!(|data| {
    do_test(data);
});
