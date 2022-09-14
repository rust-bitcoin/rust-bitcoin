fn main() {
    let rustc = std::env::var_os("RUSTC");
    let rustc = rustc.as_ref().map(std::path::Path::new).unwrap_or_else(|| "rustc".as_ref());
    let output = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("Failed to run `{:?} --version`: {:?}", rustc, error));
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
    assert_eq!(major, "1", "Unexpected Rust major version");
    let minor = version_components
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .expect("invalid Rust minor version");

    // print cfg for all interesting versions less than or equal to minor
    // 46 adds `track_caller`
    for version in &[46] {
        if *version <= minor {
            println!("cargo:rustc-cfg=rust_v_1_{}", version);
        }
    }
}
