fn main() {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .expect("Failed to run rustc --version");
    assert!(output.status.success(), "Failed to get rust version");
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
    assert_eq!(major, "1", "Unexpected Rust version");
    let minor = version_components
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .expect("invalid Rust minor version");

    for activate_version in &[46, 53, 60] {
        if minor >= *activate_version {
            println!("cargo:rustc-cfg=rust_v_1_{}", activate_version);
        }
    }
}
