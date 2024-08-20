const MAX_USED_VERSION: u64 = 80;

use std::io;

fn main() {
    let rustc = std::env::var_os("RUSTC");
    let rustc = rustc.as_ref().map(std::path::Path::new).unwrap_or_else(|| "rustc".as_ref());
    let output = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("failed to run `{:?} --version`: {:?}", rustc, error));
    assert!(output.status.success(), "{:?} -- version returned non-zero exit code", rustc);
    let stdout = String::from_utf8(output.stdout).expect("rustc produced non-UTF-8 output");
    let version_prefix = "rustc ";
    if !stdout.starts_with(version_prefix) {
        panic!("unexpected rustc output: {}", stdout);
    }

    let version = &stdout[version_prefix.len()..];
    let end = version.find(&[' ', '-'] as &[_]).unwrap_or(version.len());
    let version = &version[..end];
    let mut version_components = version.split('.');
    let major = version_components.next().unwrap();
    assert_eq!(major, "1", "unexpected Rust major version");
    let minor = version_components
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .expect("invalid Rust minor version");

    let msrv = std::env::var("CARGO_PKG_RUST_VERSION").unwrap();
    let mut msrv = msrv.split(".");
    let msrv_major = msrv.next().unwrap();
    assert_eq!(msrv_major, "1", "unexpected Rust major version");
    let msrv_minor = msrv.next().unwrap().parse::<u64>().unwrap();

    let out_dir = std::env::var_os("OUT_DIR").expect("missing OUT_DIR env var");
    let out_dir = std::path::PathBuf::from(out_dir);
    let macro_file = std::fs::File::create(out_dir.join("rust_version.rs")).expect("failed to create rust_version.rs");
    let macro_file = io::BufWriter::new(macro_file);
    write_macro(macro_file, msrv_minor, minor).expect("failed to write to rust_version.rs");
}

fn write_macro(mut macro_file: impl io::Write, msrv_minor: u64, minor: u64) -> io::Result<()> {
    writeln!(macro_file, "/// Expands code based on Rust version this is compiled under.")?;
    writeln!(macro_file, "///")?;
    writeln!(macro_file, "/// Example:")?;
    writeln!(macro_file, "/// ```")?;
    writeln!(macro_file, "/// bitcoin_internals::rust_version! {{")?;
    writeln!(macro_file, "///     if >= 1.70 {{")?;
    writeln!(macro_file, "///         println!(\"This is Rust 1.70+\");")?;
    writeln!(macro_file, "///     }} else {{")?;
    writeln!(macro_file, "///         println!(\"This is Rust < 1.70\");")?;
    writeln!(macro_file, "///     }}")?;
    writeln!(macro_file, "/// }}")?;
    writeln!(macro_file, "/// ```")?;
    writeln!(macro_file, "///")?;
    writeln!(macro_file, "/// The `else` branch is optional.")?;
    writeln!(macro_file, "/// Currently only the `>=` operator is supported.")?;
    writeln!(macro_file, "#[macro_export]")?;
    writeln!(macro_file, "macro_rules! rust_version {{")?;
    for version in msrv_minor..=minor {
        writeln!(macro_file, "    (if >= 1.{} {{ $($if_yes:tt)* }} $(else {{ $($if_no:tt)* }})?) => {{", version)?;
        writeln!(macro_file, "        $($if_yes)*")?;
        writeln!(macro_file, "    }};")?;
    }
    for version in (minor + 1)..(MAX_USED_VERSION + 1) {
        writeln!(macro_file, "    (if >= 1.{} {{ $($if_yes:tt)* }} $(else {{ $($if_no:tt)* }})?) => {{", version)?;
        writeln!(macro_file, "        $($($if_no)*)?")?;
        writeln!(macro_file, "    }};")?;
    }
    writeln!(macro_file, "    (if >= $unknown:tt $($rest:tt)*) => {{")?;
    writeln!(macro_file, "        compile_error!(concat!(\"unknown Rust version \", stringify!($unknown)));")?;
    writeln!(macro_file, "    }};")?;
    writeln!(macro_file, "}}")?;
    writeln!(macro_file, "pub use rust_version;")?;
    macro_file.flush()
}
