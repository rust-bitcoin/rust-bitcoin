# Fuzzing

`rust-bitcoin` has fuzzing harnesses setup for use with
`cargo-fuzz`.

To run the fuzz-tests as in CI -- briefly fuzzing every target -- simply
run

```bash
./fuzz.sh
```

in this directory.

## Fuzzing with weak cryptography

You may wish to replace the hashing and signing code with broken crypto,
which will be faster and enable the fuzzer to do otherwise impossible
things such as forging signatures or finding preimages to hashes.

Doing so may result in spurious bug reports since the broken crypto does
not respect the encoding or algebraic invariants upheld by the real crypto. We
would like to improve this, but it's a nontrivial problem -- though not
beyond the abilities of a motivated student with a few months of time.
Please let us know if you are interested in taking this on!

Meanwhile, to use the broken crypto, simply compile (and run the fuzzing
scripts) with

```bash
RUSTFLAGS="--cfg=hashes_fuzz --cfg=secp256k1_fuzz"
```

which will replace the hashing library with broken hashes, and the
`secp256k1` library with broken cryptography.

Needless to say, NEVER COMPILE REAL CODE WITH THESE FLAGS because if a
fuzzer can break your crypto, so can anybody.

## Long-term fuzzing

To see the full list of targets, the most straightforward way is to run

```bash
cargo fuzz list
```

To run each of them for an hour, run

```bash
./cycle.sh
```
This script uses the `chrt` utility to try to reduce the priority of the
jobs. If you would like to run for longer, the most straightforward way
is to edit `cycle.sh` before starting. To run the fuzz-tests in parallel,
you will need to implement a custom harness.

To run a single fuzztest indefinitely, run

```bash
cargo +nightly fuzz run "<target>" 
```

## Adding fuzz tests

All fuzz tests can be found in the `fuzz_target/` directory. Adding a new
one is as simple as copying an existing one and editing the `do_test`
function to do what you want.

If your test clearly belongs to a specific crate, please put it in that
crate's directory. Otherwise, you can put it directly in `fuzz_target/`.

If you need to add dependencies, edit the file `generate-files.sh` to add
it to the generated `Cargo.toml`.

Once you've added a fuzztest, regenerate the `Cargo.toml` and CI job by
running

```bash
./generate-files.sh
```

Then to test your fuzztest, run

```bash
./fuzz.sh <target>
```

If it is working, you will see a rapid stream of data for many seconds
(you can hit Ctrl+C to stop it early) that looks something like this:
```text
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2953319389
INFO: Loaded 1 modules   (9121 inline 8-bit counters): 9121 [0x104132ea0, 0x104135241),
INFO: Loaded 1 PC tables (9121 PCs): 9121 [0x104135248,0x104158c58),
INFO:        0 files found in /some/path/to/rust-bitcoin/fuzz/corpus/units_arbitrary_weight
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 42 ft: 42 corp: 1/1b exec/s: 0 rss: 36Mb
#411	NEW    cov: 43 ft: 43 corp: 2/9b lim: 8 exec/s: 0 rss: 37Mb L: 8/8 MS: 4 ChangeBinInt-ShuffleBytes-ShuffleBytes-InsertRepeatedBytes-
#1329	NEW    cov: 43 ft: 44 corp: 3/26b lim: 17 exec/s: 0 rss: 37Mb L: 17/17 MS: 3 InsertRepeatedBytes-CMP-CopyPart- DE: "\001\000\000\000"-
#1357	REDUCE cov: 43 ft: 44 corp: 3/25b lim: 17 exec/s: 0 rss: 37Mb L: 16/16 MS: 3 CopyPart-CMP-EraseBytes- DE: "\000\000\000\000\000\000\000\000"-
...
```
If you don't see this, you should quickly see an error.

## Reproducing Failures

If a fuzztest fails, it will exit with a summary which looks something like
```text
...
thread '<unnamed>' (3001874) panicked at units/src/weight.rs:103:25:
attempt to multiply with overflow
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
==66478== ERROR: libFuzzer: deadly signal
    #0 0x0001049fd3c4 in __sanitizer_print_stack_trace+0x28 (librustc-nightly_rt.asan.dylib:arm64+0x5d3c4)
    #1 0x000104078b90 in fuzzer::PrintStackTrace()+0x30 (units_arbitrary_weight:arm64+0x100070b90)
    #2 0x00010406d074 in fuzzer::Fuzzer::CrashCallback()+0x54 (units_arbitrary_weight:arm64+0x100065074)
    #3 0x000180d26740 in _sigtramp+0x34 (libsystem_platform.dylib:arm64+0x3740)
    ...
```
This will tell you where the test failed and is followed by information about how to reproduce the crash.
It will look something like this:

```text
...
NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 2 ChangeByte-CopyPart-; base unit: 25058c6b0d02cd1d71a030ad61c46b7396ddcdb9
0x5e,0x5e,0x5e,0x5e,0x5e,0x44,0x0,0x0,0x0,0x0,0x0,0x5d,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x5e,0xa,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0xa5,0x1,0x1,0x1,
^^^^^D\000\000\000\000\000]\001\000\000\000\000\000\000^\012\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\245\001\001\001
artifact_prefix='/some/path/to/rust-bitcoin/fuzz/artifacts/units_arbitrary_weight/'; Test unit written to /some/path/to/rust-bitcoin/fuzz/artifacts/units_arbitrary_weight/crash-1b454523d38a6c3f45d453dfea4099f3cb574822
Base64: Xl5eXl5EAAAAAABdAQAAAAAAAF4KAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBpQEBAQ==
────────────────────────────────────────────────────────────────────────────────

Failing input:

	fuzz/artifacts/units_arbitrary_weight/crash-1b454523d38a6c3f45d453dfea4099f3cb574822

Output of `std::fmt::Debug`:

	[94, 94, 94, 94, 94, 68, 0, 0, 0, 0, 0, 93, 1, 0, 0, 0, 0, 0, 0, 94, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 165, 1, 1, 1]

Reproduce with:

	cargo fuzz run units_arbitrary_weight fuzz/artifacts/units_arbitrary_weight/crash-1b454523d38a6c3f45d453dfea4099f3cb574822

Minimize test case with:

	cargo fuzz tmin units_arbitrary_weight fuzz/artifacts/units_arbitrary_weight/crash-1b454523d38a6c3f45d453dfea4099f3cb574822

────────────────────────────────────────────────────────────────────────────────
```
