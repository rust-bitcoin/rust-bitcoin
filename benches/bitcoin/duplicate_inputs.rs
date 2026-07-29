// SPDX-License-Identifier: CC0-1.0

use std::collections::{BTreeSet, HashSet};
use std::hint::black_box;

use bitcoin::transaction::OutPoint;
use bitcoin::Txid;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// we put duplicate at the very end
fn generate_worst_case(n: usize) -> Vec<OutPoint> {
    let mut inputs: Vec<OutPoint> = (0..n)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[31] = i as u8;
            OutPoint { txid: Txid::from_byte_array(bytes), vout: i as u32 }
        })
        .collect();
    if n > 1 {
        inputs[n - 1] = inputs[n - 2];
    }
    inputs
}



fn check_hashset(inputs: &[OutPoint]) -> bool {
    let mut seen: HashSet<&OutPoint> = HashSet::with_capacity(inputs.len());
    for input in inputs {
        if !seen.insert(input) {
            return true;
        }
    }
    false
}

fn check_pairwise(inputs: &[OutPoint]) -> bool {
    for i in 0..inputs.len() {
        for j in (i + 1)..inputs.len() {
            if inputs[i] == inputs[j] {
                return true;
            }
        }
    }
    false
}

// current implementation
fn check_btreeset(inputs: &[OutPoint]) -> bool {
    let mut seen = BTreeSet::new();
    for input in inputs {
        if !seen.insert(input) {
            return true;
        }
    }
    false
}

fn check_sorted(inputs: &[OutPoint]) -> bool {
    let mut sorted: Vec<_> = inputs.iter().collect();
    sorted.sort();
    sorted.windows(2).any(|w| w[0] == w[1])
}

fn check_sorted_unstable(inputs: &[OutPoint]) -> bool {
    let mut sorted: Vec<_> = inputs.iter().collect();
    sorted.sort_unstable();
    sorted.windows(2).any(|w| w[0] == w[1])
}

fn bench_duplicate_inputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("duplicate_inputs");

    for size in [2, 5, 10, 50, 100, 500, 1000] {
        let inputs = generate_worst_case(size);
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(BenchmarkId::new("pairwise", size), &inputs, |b, inputs| {
            b.iter(|| black_box(check_pairwise(black_box(inputs))))
        });

        group.bench_with_input(BenchmarkId::new("btreeset", size), &inputs, |b, inputs| {
            b.iter(|| black_box(check_btreeset(black_box(inputs))))
        });

        group.bench_with_input(BenchmarkId::new("sorted", size), &inputs, |b, inputs| {
            b.iter(|| black_box(check_sorted(black_box(inputs))))
        });

        group.bench_with_input(
            BenchmarkId::new("sorted_unstable", size),
            &inputs,
            |b, inputs| b.iter(|| black_box(check_sorted_unstable(black_box(inputs)))),
        );

        group.bench_with_input(BenchmarkId::new("hashset", size), &inputs, |b, inputs| {
            b.iter(|| black_box(check_hashset(black_box(inputs))))
        });

    }

    group.finish();
}

criterion_group!(benches, bench_duplicate_inputs);
criterion_main!(benches);
