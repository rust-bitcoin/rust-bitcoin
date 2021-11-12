export RUSTFLAGS="-C link-arg=-Tlink.x"
export CARGO_TARGET_THUMBV7M_NONE_EABI_RUNNER="qemu-system-arm -cpu cortex-m3 -machine mps2-an385 -nographic -semihosting-config enable=on,target=native -kernel"
