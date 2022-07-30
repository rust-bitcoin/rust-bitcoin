extern crate bitcoin;

use std::fmt;

// faster than String, we don't need to actually produce the value, just check absence of panics
struct NullWriter;

impl fmt::Write for NullWriter {
    fn write_str(&mut self, _s: &str) -> fmt::Result {
        Ok(())
    }

    fn write_char(&mut self, _c: char) -> fmt::Result {
        Ok(())
    }
}

fn do_test(data: &[u8]) {
    let mut writer = NullWriter;
    bitcoin::Script::from_bytes(data).fmt_asm(&mut writer);
}

#[cfg(feature = "afl")]
#[macro_use] extern crate afl;
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data| {
        do_test(&data);
    });
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
