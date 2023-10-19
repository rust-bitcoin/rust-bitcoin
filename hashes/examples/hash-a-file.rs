//! Use `bitcoin_hashes` to sha256 hash the contents of a file.

use std::io::{self, BufRead};

use bitcoin_hashes::{sha256, Hash as _, HashEngine as _};

const FILE: &str = "a mock text file \n a line of text \n and another one \n";

fn main() {
    // This would usually be BufReader::new(File::open(path)?);
    let reader = io::Cursor::new(&FILE);

    let mut engine = sha256::Hash::engine();

    for line in reader.lines() {
        let line = line.expect("line read failed");
        engine.input(line.as_bytes());
    }
    let hash = sha256::Hash::from_engine(engine);

    println!("\n\t{}", hash);
}
