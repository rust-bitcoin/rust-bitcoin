// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

use chacha20_poly1305::{chacha20::ChaCha20, Key, Nonce};

fn bench_chacha20(c: &mut Criterion) {
    let mut g = c.benchmark_group("chacha20");
    g.measurement_time(Duration::from_secs(5)).warm_up_time(Duration::from_secs(2));

    for &size in &[10usize, 1024, 65536] {
        let key = Key::new([0u8; 32]);
        let nonce = Nonce::new([0u8; 12]);
        let count = 1u32;
        let mut cipher = ChaCha20::new(key, nonce, count);
        let mut buf = vec![0u8; size];
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::new("apply_keystream", size), |b| {
            b.iter(|| {
                cipher.apply_keystream(black_box(&mut buf));
            });
        });
    }

    g.finish();
}

criterion_group!(benches, bench_chacha20);
criterion_main!(benches);
