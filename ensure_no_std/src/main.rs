//! Test for no-std comparability in dependant crates.
//!
//! Idea taken from: https://blog.dbrgn.ch/2019/12/24/testing-for-no-std-compatibility/
//! Build with: `cargo rustc -- -C link-arg=-nostartfiles`.
//!
//! To verify a crate, add it as a dependency and add (using bech32 as an example):
//! 
//!    #[allow(unused_imports)]
//!    use bech32;
//!

#![no_std]
#![no_main]

use core::panic::PanicInfo;

/// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {}
}
