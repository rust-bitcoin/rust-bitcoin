# consensus_encoding crate for sans-I/O

* Status: accepted
* Authors: Andrew Poelstra
* Date: 2025-09-06
* Targeted modules: `consensus_encoding`, `primitives`, `units`
* Associated tickets/PRs: #4912

## Context and Problem Statement

The rust-bitcoin project needs a way to perform consensus encoding/decoding operations without depending on std. The existing consensus encoding approach is somewhat tied to the `std::io` interfaces, but in order to make it no-std compatible, the `bitcoin-io` crate was introduced with "bridges" to the std I/O traits. But despite the best efforts of the bridges, there is still a lot of caller friction. Plus there is a requirement to always deal with I/O errors even in non-I/O contexts (e.g. hashing an encoding).

Is there a way to better support encoding in no-std, std, non-I/O, and even async contexts?

## Decision Drivers

* Support no_std environments.
* Reduce API friction.
* Eliminate I/O errors in non-I/O contexts.

## Considered Options

#### Option 1: Roll with the existing bitcoin-io crate

The crate has its pain points, but it gets the job done.

**Pros:**

* Maintains existing API surface.

**Cons:**

* Pain points for the general `std::io` case and error handling remain.
* The interface would be tied to the v1.0.0 release of the `primitives` and `units` crates, requiring maintenance support for a very long time.

#### Option 2: Adopt the push_decode crate

Martin Habovštiak wrote a general purpose sans-I/O encoding/decoding crate, [`push_decode`], which satisfies the technical requirements.

**Pros:**

* Already written.
* Removes ties to std I/O and I/O errors.

**Cons:**

* Is general purpose, so has a few layers of abstraction and complexity not required in the bitcoin domain.

#### Option 3: Create dedicated consensus_encoding crate

Extract consensus encoding/decoding logic into a new crate which is sans-I/O and focused only on the bitcoin domain.

**Pros:**

* Removes ties to std I/O and I/O errors.
* Interface is tailored for the bitcoin domain.

**Cons:**

* Requires most amount of new code to write and maintain.

## Decision Outcome

Option #3, dedicated `consensus_encoding` crate. While it is new code, it is heavily based on [`push_decode`] and slimmed down to just what is required in the workspace. It supports no-std, std, non-I/O, and could support async contexts. It should be relatively cheap to maintain given the limited domain.

## Technical Design

The `consensus_encoding` crate provides traits and utilities for encoding and decoding Bitcoin data types in a consensus-consistent way. This crate implements a **sans-I/O** architecture, designed to work efficiently in `no_std` environments while supporting both synchronous and asynchronous I/O when needed.

The implementation is heavily based on the more general [`push_decode`] crate written by Martin Habovštiak. But where `push_decode` is flexible to handle many different encoding scenarios, `consensus_encoding` has been slimmed down to only handle what is required by the Bitcoin ecosystem.

Sans-I/O architecture separates data codecs from I/O operations. Instead of reading directly from `io::Read` traits or writing to `io::Write` traits, the core types work with byte slices and provide iterator-like interfaces for consuming data. Same codec logic works for sync I/O, async I/O, or other use cases such as hash engines. So unlike traditional "pull decoders" that read data on-demand, this crate uses a "push" approach where *decoders* consume data in chunks and maintain internal state. The *caller* drives the process by managing buffers and I/O to push bytes into the decoder. And on the other side, *encoders* produce data in chunks which a caller pulls in order to write to a sink.

Encoding is generally infallible (e.g. encoding to `Vec` never fails). Decoding on the other hand has to deal with many failure scenarios due to not owning the bytes it's consuming. This complicates the interface as decoders provide specific errors for failure modes (`UnexpectedEof`, `InvalidData`, etc.). But I/O errors are handled by the caller functions, keeping the core codec logic I/O-agnostic.

### Encoders

```rust
pub trait Encodable {
    type Encoder<'s>: Encoder
    where
        Self: 's;

    fn encoder(&self) -> Self::Encoder<'_>;
}

pub trait Encoder {
    fn current_chunk(&self) -> &[u8];
    fn advance(&mut self) -> bool;
}
```

A Bitcoin type implements `Encodable` in order to produce `Encoder` instances for its type. So for example a `Transaction` type is made `Encodable` and linked to a `TransactionEncoder` type which implements `Encoder`. The `Encodable` trait makes use of Rust's [Generic Associated Type (GAT)] feature which ties `Encoder` lifetimes to the instance of the type they are encoding. This allows the encoder to avoid any copy or clones of bytes, instead referencing them directly, which is often powerful in the Bitcoin context where bytes are already in encoded form.

Once a caller has an `Encoder` instance, it pulls bytes out with calls to `Encoder::current_chunk`. The caller bounces between `Encoder::current_chunk` and `Encoder::advance` until the encoder is exhausted which is signaled by `Encoder::advance` returning `false`. While we considered making these a single method, the "immutable accessor method plus mutable advance state method" greatly simplifies lifetime management when encoders are combined. And encoder composition is very common in Bitcoin types which are generally composed internally of other Bitcoin types. 

### Decoders

```rust
pub trait Decodable {
    type Decoder: Decoder<Output = Self>;
    fn decoder() -> Self::Decoder;
}

pub trait Decoder: Sized {
    type Output;
    type Error;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error>;
    fn end(self) -> Result<Self::Output, Self::Error>;
    fn read_limit(&self) -> usize;
}
```

Similar to encoding, Bitcoin types implement `Decodable` in order to generate `Decoder`s. Unlike encoding, no GAT is required since the decoder is taking ownership of the bytes.

The caller interface is significantly more complex than encoding since `Decoder`s are fallible, so both `Decoder::push_bytes` and `Decoder::end` return a `Result`. A caller pushes bytes through `Decoder::push_bytes` until it returns `false`. That is the signal for the caller to now consume the `Decoder` with `Decoder::end` and get the output type. The `bytes` parameter of `Decoder::push_bytes` is mutable to allow the decoder to "consume" bytes by advancing the slice. Any un-used bytes remain in the `bytes` buffer.

The `Decoder::read_limit` method has no encoding parallel. It is another complexity due to decoders not having a priori knowledge about the amount of bytes they will be dealing with. But this helper function supplies hints to callers which allows them to better manage their buffer for the decoder, avoiding both inefficient under-reads and unnecessary over-reads.

### Callers

Library consumers can always define callers for their specific needs (e.g. async), but callers for the most common use cases are provided by the crate as free functions. Here are the signatures of the provided callers which obviously connect codecs to the standard library I/O.

```rust
#[cfg(feature = "std")]
pub fn encode_to_writer<T, W>(object: &T, mut writer: W) -> Result<(), std::io::Error>
where
    T: Encodable + ?Sized,
    W: std::io::Write,
{}

#[cfg(feature = "std")]
pub fn decode_from_read<T, R>(mut reader: R) -> Result<T, ReadError<<T::Decoder as Decoder>::Error>>
where
    T: Decodable,
    R: std::io::BufRead,
{}
```

The keen eye will catch how the decode caller requires the use of a `std::io::BufRead` instead of just `std::io::Read`. While the crate also supports `std::io::Read`, `std::io::BufRead` mitigates a lot of the complexity for decoder buffer management and will almost always be more performant.

## Links

* Initial implementation in [#4912].
* First release in [#5160].

[#4912]: <https://github.com/rust-bitcoin/rust-bitcoin/pull/4912>
[#5160]: <https://github.com/rust-bitcoin/rust-bitcoin/pull/5160>
[`push_decode`]: <https://github.com/Kixunil/push_decode>
[Generic Associated Type (GAT)]: <https://blog.rust-lang.org/2022/10/28/gats-stabilization/>
