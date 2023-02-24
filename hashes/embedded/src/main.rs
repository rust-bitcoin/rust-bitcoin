#![cfg_attr(feature = "alloc", feature(alloc_error_handler))]
#![no_std]
#![no_main]

#[macro_use]
extern crate bitcoin_hashes;

#[cfg(feature = "alloc")] extern crate alloc;
#[cfg(feature = "alloc")] use alloc_cortex_m::CortexMHeap;
#[cfg(feature = "alloc")] use core::alloc::Layout;
#[cfg(feature = "alloc")] use cortex_m::asm;
#[cfg(feature = "alloc")] use alloc::string::ToString;

use bitcoin_hashes::{sha256, Hash, HashEngine};
use core2::io::Write;
use core::str::FromStr;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_halt as _;

hash_newtype! {
    struct TestType(sha256::Hash);
}

// this is the allocator the application will use
#[cfg(feature = "alloc")]
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

#[cfg(feature = "alloc")]
const HEAP_SIZE: usize = 1024; // in bytes

#[entry]
fn main() -> ! {
    #[cfg(feature = "alloc")]
    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    let mut engine = TestType::engine();
    engine.write_all(b"abc").unwrap();
    check_result(engine);

    let mut engine = TestType::engine();
    engine.input(b"abc");
    check_result(engine);

    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}

fn check_result(engine: sha256::HashEngine) {
    let hash = TestType::from_engine(engine);

    let hash_check =
        TestType::from_str("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    hprintln!("hash:{} hash_check:{}", hash, hash_check).unwrap();
    if hash != hash_check {
        debug::exit(debug::EXIT_FAILURE);
    }

    #[cfg(feature = "alloc")]
    if hash.to_string() != hash_check.to_string() {
        debug::exit(debug::EXIT_FAILURE);
    }
}

// define what happens in an Out Of Memory (OOM) condition
#[cfg(feature = "alloc")]
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    asm::bkpt();

    loop {}
}
