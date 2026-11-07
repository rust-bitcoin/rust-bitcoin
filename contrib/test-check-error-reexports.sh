#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat > "$tmp/bin/grep" <<'STUB'
#!/usr/bin/env bash
exit 2
STUB
cat > "$tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
printf 'cargo must not be invoked before prerequisites pass\n' >&2
exit 99
STUB
chmod +x "$tmp/bin/grep" "$tmp/bin/cargo"
if PATH="$tmp/bin:$PATH" bash "$script_dir/check-error-reexports.sh" > "$tmp/output" 2>&1; then
    cat "$tmp/output"
    exit 1
fi
case "$(cat "$tmp/output")" in
    *"need grep with Perl-compatible regular expression support (-P)"*) ;;
    *) cat "$tmp/output"; exit 1 ;;
esac
case "$(cat "$tmp/output")" in
    *"cargo must not"*|*"All checks passed"*) cat "$tmp/output"; exit 1 ;;
esac
printf 'Unsupported grep is rejected before generating API files.\n'
