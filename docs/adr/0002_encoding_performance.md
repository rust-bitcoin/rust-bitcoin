# ADR 0002: Consensus Encoding Performance

* Status: draft
* Date: 2026-11-17
* Authors: Nick Johnson
* Packages: `bitcoin-consensus-encoding`

## Context

The `bitcoin-consensus-encoding` crate provides a pull-based, zero-copy, sans-I/O
encoding architecture. The initial 1.0.0 design prioritized correctness and
composability over raw speed.

## Improving 1.0 Performance

```rust
pub trait Encoder {
    fn current_chunk(&self) -> &[u8];
    fn advance(&mut self) -> EncoderStatus;
}

pub enum EncoderStatus {
    HasMore,
    Finished,
}
```

The 1.0 `Encoder` interface has two functions. The read-only `current_chunk`
exposes a slice of bytes to encode. The mutable `advance` updates the encoder to
its next state and returns its status.

Benchmarks comparing the sans-io pull encoding of `bitcoin-consensus-encoding` to the
legacy push encoding of the `io` module show that the flexible sans-io interface
has a non-negligible dispatch cost.

> Note: Unless otherwise noted, all benchmarks were run with LTO enabled and
codegen-units 1 to remove any optimization barriers for consistency. All tests
are on a consumer-grade laptop.

```toml
[profile.bench]
lto = "fat"
codegen-units = 1
```

`eea7927cb` is the *legacy* push-encoding, `Encodable`, baseline. We are using
two `Block` serialization benchmarks: `serialize/big` and `serialize_logic/big`.
The first includes a memcpy into a vector, where as the second skips that and
theoretically just measures the encoding steps.

`bitcoin-concensus-encoding@1.3.0` with all optimization attempts removed is
the baseline for the new pull-encoding.

| Variant    | Benchmark           | Time (no LTO) | Time (LTO) |
|------------|---------------------|---------------|------------|
| legacy     | serialize/big       |        264 us |     185 us |
| legacy     | serialize_logic/big |        105 us |      35 us |
| pull-based | serialize/big       |        718 us |     676 us |
| pull-based | serialize_logic/big |        529 us |     531 us |

Two things of note. First, with LTO this is a **3.7x** slowdown with memcpy
(serialize/big) and **15.2x** slowdown of just the serialization logic
(serialize_logic/big). And second, the legacy push-encoding is able to take
better advantage of LTO optimizations.

Is it possible to regain some of this performance while maintaining the
flexibility of sans-io?

### Skipping Empty Chunks

One thought was to take advantage of a tighter contract on `current_chunk`
with implementers.

> "implementers MUST NOT return an empty slice unless the encoded type is truly empty."

Composite encoders (`Encoder2/3/4/6`, `IterEncoder`) are extended with logic to
skip encoders that produce a zero-byte chunk before yielding data.

| Benchmark             | Time    |
|-----------------------|---------|
| `serialize/big`       | 1537 us |
| `serialize_logic/big` | 1155 us |

Oh dang! Unfortunately, the extra conditionals make it 2.3x slower. Perhaps the
conditionals are somehow not letting the compiler optimize paths it usually can?

Additional naive benchmarks appear to show that an iterator needs about
~25% empty encoders for the checks to be worth it. However, nesting encoders
increases the cost. Given that bitcoin encoders are highly nested and dense,
this strategy is not going to pay off unless we can somehow skip the checks
when possible.

### Add a `drain_with` Interface

The work in [#6753] explored a new `drain_with` interface which was able to match the
performance of the legacy push encoding's serialization logic.

Instead of the caller pulling chunks through every level of the encoder tree
on every iteration, `drain_with` uses the *call stack* to efficiently track
the encoder's position. An `Encoder6::drain_with` sequentially drains child 1,
then child 2, etc. Each level recurses directly into its children rather than
re-dispatching from the top, skipping a ton of comparisons like "I am encoder
2 at index 3".

```rust
pub trait Encoder {
    /// Drains all remaining bytes, passing each chunk to `sink`.
    /// Composite encoders override to recurse directly into children.
    fn drain_with(&mut self, sink: &mut dyn FnMut(&[u8])) {
        // Default to standard pull-based loop.
        loop {
            sink(self.current_chunk());
            if self.advance().has_finished() { break; }
        }
    }
}
```

This benchmark is from `bitcoin-concensus-encoding@1.3.0` with all
optimization attempts removed.

| Benchmark             | Time   |
|-----------------------|--------|
| `serialize/big`       | 257 us |
| `serialize_logic/big` |  42 us |

This almost matches the old school push encoding performance. It appears the
dispatching in every `current_chunk` and `advance` of the pull-based interface
is the majority of the slow down.

However, `drain_with` introduces a new, fragile API. If any layer "breaks the chain" and
doesn't pass on the drain to the layers below, the whole thing falls apart.
Worse, the interface does not expose any yield points, so is not useful in an
async runtime. Unlike the pull-based interface with yields after each chunk.

### Flatten Layers

The `drain_with` experimentation shows that the main cost of the pull-encoding
is the data state. Here is the `BlockEncoder` which shows up to 8 layers of
nesting as of `9eeb7774`.

```text
1  BlockEncoder(Encoder2)
   0 HeaderEncoder(Encoder6) [6 array fields, cold]
2  1 PrefixedSliceEncoder<Transaction>(Encoder2)
      0 CompactSizeEncoder
3     1 SliceEncoder<Transaction>(IterEncoder)
        (per tx)
4        TransactionEncoder(Encoder6)
           0 VersionEncoder(Array<4>)
           1 Option<ArrayEncoder<2>>
5          2 PrefixedSliceEncoder<TxIn>(Encoder2)
               0 CompactSizeEncoder
6              1 SliceEncoder<TxIn>(IterEncoder)
                 (per input)
7                  TxInEncoder(Encoder3)
                     0 OutPointEncoder(Encoder2)
8                      0 BytesEncoder<32>
                       1 ArrayEncoder<4>
                     1 ScriptEncoder(Encoder2)
                       0 CompactSizeEncoder
                       1 BytesEncoder
                     2 SequenceEncoder(Array<4>)
           3 PrefixedSliceEncoder<TxOut>(Encoder2)
               0 CompactSizeEncoder
               1 SliceEncoder<TxOut>(IterEncoder)
                 (per output)
                   TxOutEncoder(Encoder2)
                     0 AmountEncoder(Array<8>)
                     1 ScriptEncoder(Encoder2)
                       0 CompactSizeEncoder
                       1 BytesEncoder
           4 Option<WitnessesEncoder>
                (per witness) WitnessEncoder(Encoder2)
                 0 CompactSizeEncoder
                 1 BytesEncoder
           5 LockTimeEncoder(Array<4>)
```

Benchmarks show that flattening these out into less layers does increase
performance by ~5%. But a lot of dispatch calls are still unavoidable.

### Trampoline

While matching the raw performance of `drain_with` is probably not possible
without using the call stack for dispatch, could a synthetic stack be used?
Something which held a cache of what stage an encoder is in, to avoid re-finding
the leaf encoder on each `current_chunk` and `advance` call. This goal is at
odds with encoders exposing a limited view of their state (by design)
through `current_chunk` and `advance`.

## Potential 2.0 Improvements

Does a breaking API change allow us to recoup the performance?

### `type More` and `type Empty`

Theoretically, if the compiler knew more about an encoder could it further
optimize an encoder? Or does the compiler already have this figured it out 99%
of the time and nothing else can be done?

> Note: Rust `1.100.0` stabilized the `never` type `!` as a first-class type.
Potentially associated types can be added to `Encoder` which can be set to
`never` to allow the compiler to optimize. However, we not have to wait for that
MSRV and we just use a `const bool` for the following scenarios.

One piece of info is if an encoder is a single chunk. This could be captured
in a `More` type associated with the encoder. Does this allow the compiler
to cut out some `advance()` calls? My suspicion is that it is already able
to do this since single-chunk encoders (e.g. `ArrayEncoder`) already hardcode
`advance` to return `Finished`.

```rust
pub enum EncoderStatus<M = ()> {
    HasMore(M),
    Finished,
}

pub trait Encoder {
    type More;  // ! for single-chunk, () for multi-chunk
    fn advance(&mut self) -> EncoderStatus<Self::More>;
}
```

Another piece of info is if an encoder can be empty. Maybe `is_empty` checks
could be more performant if only checked on encoders which can be empty?

```rust
pub trait Encoder {
    type Empty;  // ! = never empty, () = maybe empty
    fn current_chunk(&self) -> &[u8];
    fn advance(&mut self) -> EncoderStatus;
}
```

Even if these can't be taken advantage of now, should we break the API now so
future features like [specialization] possibly can?

#### Make `Encode::encoder()` fallible

A twist to the `Empty` type is to return `Result` with an `Empty` error for
zero-byte types. Catches empty encoders at construction time instead of checking
on every `advance()` call.

```rust
pub trait Encode {
    type Encoder<'e>: Encoder where Self: 'e;
    fn encoder(&self) -> Result<Self::Encoder<'_>, Empty>;
}
```

[#6753]: https://github.com/rust-bitcoin/rust-bitcoin/pull/6753
[specialization]: https://rust-lang.github.io/rfcs/1210-impl-specialization.html
