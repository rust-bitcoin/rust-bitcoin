use std::fs;

pub fn parse_msrv_minor() -> u64 {
    let cargo_toml = fs::read_to_string("Cargo.toml").expect("manifest exists");

    for line in cargo_toml.lines() {
        if line.starts_with("rust-version") {
            let mut bits = line.split("=");
            bits.next();        // Skip "rust-version" string.
            let semver = bits.next().unwrap();

            let mut nums = semver.split(".");
            nums.next();        // Skip major version number.
            let minor = nums.next().unwrap();
            return minor.parse::<u64>().unwrap();
        }
    }

    panic!("unable to read rust-version field from manifest")
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
    for version in parse_msrv_minor()..=minor {
        println!("cargo:rustc-cfg=rust_v_1_{}", version);
    }
}
