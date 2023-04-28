# Fuzzing

`bitcoin` and `bitcoin_hashes` have fuzzing harnesses setup for use with
honggfuzz.

To run the fuzz-tests as in CI -- briefly fuzzing every target -- simply
run

    ./fuzz.sh

in this directory.

To build honggfuzz, you must have libunwind on your system, as well as
libopcodes and libbfd from binutils **2.38** on your system. The most
recently-released binutils 2.39 has changed their API in a breaking way.

On Nix, you can obtain these libraries by running

    nix-shell -p libopcodes_2_38 -p libunwind

and then run fuzz.sh as above.

# Fuzzing with weak cryptography

You may wish to replace the hashing and signing code with broken crypto,
which will be faster and enable the fuzzer to do otherwise impossible
things such as forging signatures or finding preimages to hashes.

Doing so may result in spurious bug reports since the broken crypto does
not respect the encoding or algebraic invariants upheld by the real crypto. We
would like to improve this but it's a nontrivial problem -- though not
beyond the abilities of a motivated student with a few months of time.
Please let us know if you are interested in taking this on!

Meanwhile, to use the broken crypto, simply compile (and run the fuzzing
scripts) with

    RUSTFLAGS="--cfg=hashes_fuzz --cfg=secp256k1_fuzz"

which will replace the hashing library with broken hashes, and the
secp256k1 library with broken cryptography.

Needless to say, NEVER COMPILE REAL CODE WITH THESE FLAGS because if a
fuzzer can break your crypto, so can anybody.

# Long-term fuzzing

To see the full list of targets, the most straightforward way is to run

    source ./fuzz-util.sh
    listTargetNames

To run each of them for an hour, run

    ./cycle.sh

To run a single fuzztest indefinitely, run

    HFUZZ_BUILD_ARGS='--features honggfuzz_fuzz' cargo hfuzz run <target>

This script uses the `chrt` utility to try to reduce the priority of the
jobs. If you would like to run for longer, the most straightforward way
is to edit `cycle.sh` before starting. To run the fuzz-tests in parallel,
you will need to implement a custom harness.

# Adding fuzz tests

All fuzz tests can be found in the `fuzz_target/` directory. Adding a new
one is as simple as copying an existing one and editing the `do_test`
function to do what you want.

If your test clearly belongs to a specific crate, please put it in that
crate's directory. Otherwise you can put it directly in `fuzz_target/`.

If you need to add dependencies, edit the file `generate-files.sh` to add
it to the generated `Cargo.toml`.

Once you've added a fuzztest, regenerate the `Cargo.toml` and CI job by
running

    ./generate-files.sh

Then to test your fuzztest, run

    ./fuzz.sh <target>

If it is working, you will see a rapid stream of data for many seconds
(you can hit Ctrl+C to stop it early). If not, you should quickly see
an error.

# Reproducing Failures

If a fuzztest fails, it will exit with a summary which looks something like

```
...
 fuzzTarget      : hfuzz_target/x86_64-unknown-linux-gnu/release/hashes_sha256 
CRASH:
DESCRIPTION: 
ORIG_FNAME: 00000000000000000000000000000000.00000000.honggfuzz.cov
FUZZ_FNAME: hfuzz_workspace/hashes_sha256/SIGABRT.PC.7ffff7c8abc7.STACK.18826d9b64.CODE.-6.ADDR.0.INSTR.mov____%eax,%ebp.fuzz
...
=====================================================================
fff400610004
```

The final line is a hex-encoded version of the input that caused the crash. You
can test this directly by editing the `duplicate_crash` test to copy/paste the
hex output into the call to `extend_vec_from_hex`. Then run the test with

    cargo test

Note that if you set your `RUSTFLAGS` while fuzzing (see above) you must make
sure they are set the same way when running `cargo test`.

