#!/usr/bin/env bash
# Report every crash input under fuzz/artifacts.

set -euo pipefail

# shellcheck source=fuzz/rustflags.sh
. "$(dirname "$0")/rustflags.sh"

artifact_name="${1:?Usage: $0 ARTIFACT_NAME}"
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

cd "$(git rev-parse --show-toplevel)"

found=0
for tdir in fuzz/artifacts/*/; do
  [ -d "$tdir" ] || continue
  target=$(basename "$tdir")
  for f in "$tdir"*; do
    [ -f "$f" ] || continue
    found=1
    name=$(basename "$f")
    size=$(wc -c < "$f")
    {
      echo "## Fuzz crash: $target"
      echo ""
      echo "\`$name\` ($size bytes)"
      echo ""
      if [ "$size" -gt 1024 ]; then
        echo "First 1024 bytes:"
        echo ""
      fi
      echo '```'
      xxd -l 1024 "$f"
      echo '```'
      echo ""
      if [ "$size" -le 65536 ]; then
        echo "Reproduce locally (base64 of the full input):"
        echo ""
        echo '```'
        base64 -w0 "$f"
        echo ""
        echo '```'
        echo ""
      else
        echo "Input too large to inline, grab it from the $artifact_name artifact."
        echo ""
      fi
      echo '```sh'
      flags="$(fuzz_rustflags "$target")"
      if [ -n "$flags" ]; then
        echo "export RUSTFLAGS=\"$flags\""
      fi
      echo "base64 -d > crash <<'EOF' # paste the base64 line above in terminal"
      echo "EOF"
      echo "cargo +nightly fuzz run $target crash"
      echo '```'
      echo ""
    } >> "$summary"
    echo "::error title=Fuzz crash in $target::$name ($size bytes), read the job summary github page for reproduction instructions"
  done
done

if [ "$found" = 0 ]; then
  echo "::error title=Fuzz failure::job failed without producing a crash artifact"
fi
