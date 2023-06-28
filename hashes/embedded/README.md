# Running

To run the embedded test, first prepare your environment:

```shell
sudo ./scripts/install-deps
rustup +nightly target add thumbv7m-none-eabi
```

Then:

```shell
source ./scripts/env.sh && cargo +nightly run --target thumbv7m-none-eabi
```

Output should be something like:

```text
hash:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad hash_check:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
hash:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad hash_check:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## Cleanup

After sourcing `scripts/env.sh` and _before_ building again using another target
you'll want to unset `RUSTFLAGS` otherwise you'll get linker errors.

```shell
unset RUSTFLAGS
```
