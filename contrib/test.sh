#!/bin/sh

set -ex

# Work out if we are using a nightly toolchain.
if cargo +nightly --version >/dev/null 2>&1; then
  NIGHTLY=true
else
  NIGHTLY=false
fi

# Print the versions of Rust and Cargo
echo "Rust version:"
if $NIGHTLY; then
  rustc +nightly --version --verbose
else
  rustc --version --verbose
fi

echo "Cargo version:"
if $NIGHTLY; then
  cargo +nightly --version --verbose
else
  cargo --version --verbose
fi

# Print clippy version if available
if command -v cargo-clippy &> /dev/null; then
  echo "Clippy version:"
  cargo clippy --version --verbose
fi

# Print fmt version if available
if command -v cargo-fmt &> /dev/null; then
  echo "Fmt version:"
  cargo fmt --version --verbose
fi

CRATES="bitcoin hashes internals"

for crate in ${CRATES}
do
    (
        cd "$crate"
        ./contrib/test.sh
    )
done

exit 0
