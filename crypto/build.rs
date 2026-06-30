use std::fs;
use std::path::PathBuf;

/// Copy all rust files from `../include` for inclusion via `include!()` macro.
fn copy_include_files() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let include_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../include");

    for entry in fs::read_dir(&include_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            fs::copy(&path, out_dir.join(path.file_name().unwrap())).unwrap();
        }
    }

    println!("cargo:rerun-if-changed=../include");
}

fn main() {
    copy_include_files();
}
