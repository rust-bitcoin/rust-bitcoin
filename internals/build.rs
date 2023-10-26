use std::collections::HashSet;
use std::iter::FromIterator;

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
        .parse::<usize>()
        .expect("invalid Rust minor version");

    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR");
    let manifest_dir = manifest_dir.as_ref().map(std::path::Path::new).unwrap();
    let parent = manifest_dir.parent().unwrap();

    assert!(std::env::set_current_dir(parent).is_ok());
    let git_grep = std::process::Command::new("git")
        .arg("grep")
        .arg("rust_v_1_")
        .output()
        .unwrap_or_else(|_| panic!("Failed to run `git grep rust_v_1_`"));

    let stdout: String =
        String::from_utf8(git_grep.stdout).expect("git grep produced non-UTF-8 output");

    let locations: Vec<_> = stdout.rmatch_indices("rust_v_1").collect();
    let z = locations
        .iter()
        .map(|(i, _)| &stdout[i + 9..i + 11])
        .map(|minor| minor.parse::<usize>().unwrap_or(0))
        .filter(|&minor| minor != 0);
    let set: HashSet<usize> = HashSet::from_iter(z);
    let mut included_versions: Vec<_> = set.into_iter().collect();
    included_versions.sort();

    let versions = vec![53, 55, 60];
    assert_eq!(versions, included_versions, "Unexpected version");

    for version in &versions {
        if *version <= minor {
            println!("cargo:rustc-cfg=rust_v_1_{}", version);
        }
    }
}
