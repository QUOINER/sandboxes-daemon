#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
extract="$root/scripts/extract-release-notes.sh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/rheic-release-notes.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

fixture="$tmp_dir/CHANGELOG.md"
actual="$tmp_dir/actual.md"
expected="$tmp_dir/expected.md"

expect_failure() {
  local version=$1
  if "$extract" "$version" "$fixture" >"$actual" 2>"$tmp_dir/error"; then
    printf 'expected release note extraction to fail for version %s\n' "$version" >&2
    exit 1
  fi
}

printf '## v0.0.42 — current\n\nrelease notes\n\n## v0.0.41 — previous\n\nold notes\n' > "$fixture"
printf 'release notes\n' > "$expected"
"$extract" 0.0.42 "$fixture" > "$actual"
diff -u "$expected" "$actual"

printf '## v0x0x42 — fake\n\nwrong version\n' > "$fixture"
expect_failure 0.0.42

printf '## v0.0.42 — first\n\nfirst\n\n## v0.0.42 — duplicate\n\nsecond\n' > "$fixture"
expect_failure 0.0.42

printf '## v0.0.41 — older\n\nold notes\n' > "$fixture"
expect_failure 0.0.42

printf '## v0.0.42 — empty\n\n## v0.0.41 — older\n\nold notes\n' > "$fixture"
expect_failure 0.0.42

if "$extract" 0.0x42 "$fixture" >"$actual" 2>"$tmp_dir/error"; then
  printf 'accepted invalid version argument\n' >&2
  exit 1
fi

if "$extract" 0.0.042 "$fixture" >"$actual" 2>"$tmp_dir/error"; then
  printf 'accepted version with a leading zero\n' >&2
  exit 1
fi
