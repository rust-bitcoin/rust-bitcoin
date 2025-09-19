# Rust Bitcoin Benchmarks

Criterion based benchmarks for `rust-bitcoin`.

## Minimum Supported Rust Version (MSRV)

This crate’s MSRV is determined by its Criterion dependency. It currently requires **Rust 1.81**.
This higher MSRV applies only to the benches crate and does not affect other crates in this repository.

## Running the benchmarks

Examples below are run from within the crates folder `benches/`, if running from the repo root pass in `--manifest-path benches/Cargo.toml`.

Run all benchmarks in this crate:

```bash
cargo bench
```

Run a specific benchmark target:

```bash
cargo bench --bench block
```

Pass options through to Criterion (see [More information](#more-information) for details):

```bash
# Save current results as a baseline named "before-change"
cargo bench -- --save-baseline before-change

# Compare to the saved baseline
cargo bench -- --baseline before-change
```

View reports:

- Criterion writes detailed html reports that are linked to in `target/criterion/report/index.html`.

## Adding a new benchmark

1. Create a new Rust file for your benchmark in the subfolder for the crate e.g. `benches/bitcoin/base58.rs`.
2. Add it in `benches/Cargo.toml` including the path, with `harness = false`:

```toml
[[bench]]
name = "base58"
path = "bitcoin/base58.rs"
harness = false
```

3. Criterion code template:

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_new_bench(c: &mut Criterion) {
    c.bench_function("new_bench", |b| {
        b.iter(|| {
            // Benchmark code
        })
    });
}

criterion_group!(benches, bench_new_bench);
criterion_main!(benches);
```

## More information

- Criterion Book: <https://bheisler.github.io/criterion.rs/book/>
- Criterion GitHub: <https://github.com/bheisler/criterion.rs>

## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](../LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
