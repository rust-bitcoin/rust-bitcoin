//! Continuous Integration: rust-bitcoin test runner.
//!
//! This program is used by our CI pipeline to test the library. It can, of course, also be used
//! from the command line also.
//!
//! # Hints and tips
//!
//! - Build and run (from the repo root directory)
//!
//!    `cd ci; cargo build --target-dir target; cd ..; ci/target/debug/ci [OPTIONS]`
//!
//! - If you would like more verbose output from cargo consider setting `CARGO_TERM_VERBOSE`.
//!
//! - To debug or just see that the tests you think are running are running consider sending
//!   stdout /dev/null and use `--debug` to see descriptive output.
//!
//! - To control the toolchain use `RUSTUP_TOOLCHAIN=nightly`.

use std::process;

use cmd_lib::*;
use clap::Parser;

/// The list of individual features that we test.
const FEATURES: &str = "base64 bitcoinconsensus serde rand secp-recovery";

/// Test runner for the rust-bitcoin library.
#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Build and test the "no-std" feature.
    #[clap(long)]
    no_std: bool,

    /// Control which toolchain is used.
    #[clap(long, value_parser, default_value = "")]
    toolchain: String,

    /// Build and test each feature and various combinations of features.
    #[clap(long)]
    feature_matrix: bool,

    /// Build the docs.
    #[clap(long)]
    docs: bool,

    /// Run the fuzz tests.
    #[clap(long)]
    fuzz: bool,

    /// Run the bench marks.
    #[clap(long)]
    bench: bool,

    /// Test bitcoin can be used as a dependency.
    #[clap(long)]
    as_dependency: bool,

    /// Turn on debug output.
    #[clap(short, long)]
    debug: bool,
}

fn main() -> CmdResult {
    let args = Args::parse();

    // Debugging output: Use a closure so we do not have to pass `args.debug` around.
    let debug = |msg| if args.debug {
        eprintln!("{}", msg);
    };

    // If `--no-std` option is not set we are running "std" build/tests only.
    let std = !args.no_std;

    debug("\nRunning the rust-bitcoin test suite\n");
    if std {
        debug("\t - using \"std\"");
    } else {
        debug("\t - using \"no-std\"");
    }

    // Some commands below do not work with a stable toolchain because they use unstable features
    // (e.g. doc_cfg and tests crate) however the error message from the compiler is a bit obscure
    // so we attempt to provide more information.
    let is_stable_toolchain = {
        let is_nightly = run_fun!(cargo --version | grep nightly).is_ok();
        let is_beta = run_fun!(cargo --version | grep beta).is_ok();

        if args.debug {
            eprintln!("\t - using {} toolchain", {
                if is_nightly {
                    "nightly"
                } else if is_beta {
                    "beta"
                } else {
                    "stable"
                }
            });
        }

        !(is_nightly || is_beta)
    };

    // Sanity check, do this up front so we fail early.
    run_cmd!(cargo --version)?;
    run_cmd!(rustc --version)?;

    // Help troubleshoot CI runs, display the status of all features if `--debug` is set.
    display_features(&args);

    // "std" and "no-std" tests, examples, and feature matrix.
    //
    // Since rust-bitcoin requires either "std" or "no-std" to be enabled we group the test
    // accordingly. If `--feature-matrix` is set we test each of `FEATURES` coupled with std/no-std.
    if std {
        debug("Build and test the default features ...");
        run_cmd!(cargo build)?;
        run_cmd!(cargo test)?;

        if args.feature_matrix {
            debug("Build and test with no features other than std ...");
            run_cmd!(cargo build --no-default-features --features="std")?;
            run_cmd!(cargo test --no-default-features --features="std")?;

            debug("Build and test individual features along with \"std\":");
            for feature in FEATURES.split(" ") {
                let features = format!("std {}", feature);
                if args.debug {
                    eprintln!("\t feature \"{}\"", feature);
                }
                run_cmd!(cargo test --no-default-features --features="$features")?;
            }

            debug("Build std + no_std, to make sure they are not incompatible ...");
            run_cmd!(cargo build --no-default-features --features="std no-std")?;
        }

        debug("Run the examples with the \"std\" feature enabled ...\n");
        run_cmd!(cargo run --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd)?;

    } else {
        debug("Build no_std, to make sure that cfg(test) doesn't hide any issues ...");
        run_cmd!(cargo build --no-default-features --features="no-std")?;

        debug("Test with no features other than \"no-std\" ...");
        run_cmd!(cargo test --no-default-features --features="no-std")?;

        debug("Build all the features excluding \"std\" ...");
        let features = format!("no-std {}", FEATURES);
        run_cmd!(cargo test --no-default-features --features="$features")?;

        if args.feature_matrix {
            debug("Build and test individual features along with \"no-std\" ...");
            for feature in FEATURES.split(" ") {
                let features = format!("no-std {}", feature);
                run_cmd!(cargo test --no-default-features --features="$features")?;
            }
        }

        debug("Run the examples without \"std\" and with \"no-std\"  ...");
        run_cmd!(cargo run --no-default-features --features no-std --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd)?;
    }

    if args.docs {
        if is_stable_toolchain {
            eprintln!("docs build cannot be doe with a stable toolchain");
            process::exit(1);
        }
        debug("Building the docs ...");
        run_cmd!(RUSTDOCFLAGS="--cfg docsrs" cargo doc --features="$FEATURES")?;
    }

    if args.fuzz {
        debug("Running fuzz tests ...");
        run_cmd!(cd fuzz; cargo test; ./travis-fuzz.sh)?;
    }

    if args.bench {
        if is_stable_toolchain {
            eprintln!("bench marks cannot be run with a stable toolchain");
            process::exit(1);
        }
        debug("Running bench marks ...");
        std::env::set_var("RUSTFLAGS", "--cfg=bench");
        run_cmd!(cargo bench)?;
    }

    if args.as_dependency {
        debug("\nTesting bitcoin can be used as a dependency ...");
        let dep = "bitcoin = { path = \"..\", features = [\"serde\"] }";

        run_cmd!(cargo new dep_test; echo "$dep" >> dep_test/Cargo.toml; cargo test --manifest-path dep_test/Cargo.toml)?;
        run_cmd!(rm -rf dep_test)?;
    }

    debug("All tests ran successfully.");
    Ok(())
}

/// Print the status of each feature flag.
fn display_features(args: &Args) {
    if args.debug {
        eprintln!(r###"
Feature flags:

	 - feature-matrix: {}
	 - docs: {}
	 - fuzz: {}
	 - bench: {}
	 - as_dependency: {}
"###, args.feature_matrix, args.docs, args.fuzz, args.bench, args.as_dependency);
    }
}
