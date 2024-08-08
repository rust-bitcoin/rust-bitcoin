use std::fs;

fn parse_msrv_minor() -> Option<u64> {
    let cargo_toml =
        fs::read_to_string("Cargo.toml").expect("Should have been able to read the file");

    let mut msrv_minor = None;
    for line in cargo_toml.lines() {
        if line.starts_with("rust-version") {
            let mut v_line = line.split("=");

            let v = match (v_line.next(), v_line.next()) {
                (Some(_lhs), Some(rhs)) => rhs,
                _ => panic!("Unable to parse MSRV"),
            };

            let mut semvar = v.split(".");
            msrv_minor = match (semvar.next(), semvar.next()) {
                (Some(_), Some(m)) => Some(m.parse::<u64>().expect("invalid Rust minor version")),
                _ => panic!("Unable to parse semvar"),
            };
        }
    }

    msrv_minor
}

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

    // print cfg for all interesting versions less than or equal to minor
    for version in parse_msrv_minor().unwrap()..=minor {
        println!("cargo:rustc-cfg=rust_v_1_{}", version);
    }
}
