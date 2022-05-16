# Build Stage
FROM ubuntu:20.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y cmake clang curl
RUN curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN ${HOME}/.cargo/bin/rustup default nightly
RUN ${HOME}/.cargo/bin/cargo install afl

## Add source code to the build stage.
ADD . /rust-bitcoin
WORKDIR /rust-bitcoin
RUN cd fuzz && \
	${HOME}/.cargo/bin/cargo afl build --features=afl --release

# Package Stage
FROM ubuntu:20.04

COPY --from=builder rust-bitcoin/fuzz/target/release/deserialize_address /
COPY --from=builder rust-bitcoin/fuzz/target/release/deserialize_block /
COPY --from=builder rust-bitcoin/fuzz/target/release/deserialize_script /
COPY --from=builder rust-bitcoin/fuzz/target/release/deserialize_transaction /