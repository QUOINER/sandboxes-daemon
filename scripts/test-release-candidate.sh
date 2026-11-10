#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rheic-pretag-check.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

git -c init.defaultBranch=main init --bare "$tmp/origin.git" >/dev/null
git init --initial-branch=main "$tmp/checkout" >/dev/null
git -C "$tmp/checkout" config user.name 'Rheic Release Test'
git -C "$tmp/checkout" config user.email 'release-test@example.invalid'
mkdir -p "$tmp/checkout/scripts"
cp "$root/scripts/validate-release-candidate.sh" "$tmp/checkout/scripts/"
cp "$root/scripts/extract-release-notes.sh" "$tmp/checkout/scripts/"
chmod +x "$tmp/checkout/scripts/"*.sh
cat > "$tmp/checkout/CHANGELOG.md" <<'CHANGELOG'
# Changelog

## v0.0.2 — 2026-11-09

Synthetic current release notes.

## v0.0.1 — 2026-11-08

Synthetic older notes.
CHANGELOG
git -C "$tmp/checkout" add CHANGELOG.md scripts
git -C "$tmp/checkout" commit -m 'Add synthetic candidate fixture' >/dev/null
git -C "$tmp/checkout" remote add origin "$tmp/origin.git"
git -C "$tmp/checkout" push -u origin main >/dev/null 2>&1
sha=$(git -C "$tmp/checkout" rev-parse HEAD)
helper="$tmp/checkout/scripts/validate-release-candidate.sh"

if ! (cd "$tmp/checkout" && GITHUB_REF=refs/heads/main GITHUB_SHA="$sha" "$helper" 0.0.2); then
  printf 'valid main SHA and newest changelog version were rejected\n' >&2
  exit 1
fi
expect_failure() {
  local name=$1
  local version=$2
  shift 2
  if (cd "$tmp/checkout" && env "$@" "$helper" "$version") >/dev/null 2>&1; then
    printf 'pre-tag validation accepted negative control: %s\n' "$name" >&2
    exit 1
  fi
}
expect_failure wrong-ref 0.0.2 GITHUB_REF=refs/heads/feature/release GITHUB_SHA="$sha"
expect_failure wrong-sha 0.0.2 GITHUB_REF=refs/heads/main GITHUB_SHA=0000000000000000000000000000000000000000
expect_failure invalid-version 0.0.x GITHUB_REF=refs/heads/main GITHUB_SHA="$sha"
expect_failure leading-zero-version 0.0.02 GITHUB_REF=refs/heads/main GITHUB_SHA="$sha"
expect_failure stale-changelog-version 0.0.1 GITHUB_REF=refs/heads/main GITHUB_SHA="$sha"

git -C "$tmp/checkout" remote set-url origin "$tmp/missing-origin.git"
expect_failure unavailable-origin 0.0.2 GITHUB_REF=refs/heads/main GITHUB_SHA="$sha"
git -C "$tmp/checkout" remote set-url origin "$tmp/origin.git"

git -C "$tmp/checkout" tag v0.0.2
git -C "$tmp/checkout" push origin refs/tags/v0.0.2 >/dev/null 2>&1
expect_failure existing-remote-tag 0.0.2 GITHUB_REF=refs/heads/main GITHUB_SHA="$sha"

printf 'PASS: 1 positive and 7 negative pre-tag controls\n'
