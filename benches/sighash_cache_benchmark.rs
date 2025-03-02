use criterion::{black_box, criterion_group, criterion_main, Criterion};
use bitcoin::sighash::SighashCache;
use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut, OutPoint};
use bitcoin::locktime::absolute;
use bitcoin::ScriptBuf;
use bitcoin::Amount;
use bitcoin::Txid;

fn dummy_transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0u8; 32]),
                vout: 0, 
            },
            script_sig: ScriptBuf::new(), 
            sequence: bitcoin::Sequence::MAX, 
            witness: bitcoin::Witness::new(), 
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0), 
            script_pubkey: ScriptBuf::new(),
        }],
    }
}


fn benchmark_sighash_cache_creation(c: &mut Criterion) {
    let tx = dummy_transaction();
    
    c.bench_function("SighashCache Creation", |b| {
        b.iter(|| {
            let cache = SighashCache::new(black_box(&tx));
            black_box(cache);
        })
    });
}

fn benchmark_sighash_cache_access(c: &mut Criterion) {
    let tx = dummy_transaction();
    let cache = SighashCache::new(&tx);

    c.bench_function("Access SighashCache", |b| {
        b.iter(|| {
            let _ = black_box(&cache);
        })
    });
}

fn benchmark_sighash_cache_clone(c: &mut Criterion) {
    let tx = dummy_transaction();
    let cache = SighashCache::new(&tx);

    c.bench_function("Clone SighashCache", |b| {
        b.iter(|| {
            let cloned_cache = cache.clone();
            black_box(cloned_cache);
        })
    });
}

criterion_group!(
    benches,
    benchmark_sighash_cache_creation,
    benchmark_sighash_cache_access,
    benchmark_sighash_cache_clone,
);
criterion_main!(benches);
