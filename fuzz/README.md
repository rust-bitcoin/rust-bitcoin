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


