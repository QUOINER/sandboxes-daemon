#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'usage: %s VERSION\n' "${0##*/}" >&2
  exit 2
fi
version=$1
root=$(cd "$(dirname "$0")/.." && pwd)

if [[ "${GITHUB_REF:-}" != "refs/heads/main" ]]; then
  printf 'release validation must run from main\n' >&2
  exit 1
fi
if [[ -z "${GITHUB_SHA:-}" ]]; then
  printf 'release validation requires GITHUB_SHA\n' >&2
  exit 1
fi
head=$(git rev-parse --verify 'HEAD^{commit}')
if [[ "$head" != "$GITHUB_SHA" ]]; then
  printf 'release validation SHA does not match checked out commit\n' >&2
  exit 1
fi
first_heading=$(awk '/^## / { print; exit }' "$root/CHANGELOG.md")
case "$first_heading" in
  "## v$version"|"## v$version "*) ;;
  *)
    printf 'release version must match the newest changelog entry\n' >&2
    exit 1
    ;;
esac
tag_ref="refs/tags/v$version"
if ! remote_tags=$(git ls-remote --refs origin "$tag_ref"); then
  printf 'could not check remote release tag\n' >&2
  exit 1
fi
if [[ -n "$remote_tags" ]]; then
  printf 'release tag already exists\n' >&2
  exit 1
fi
"$root/scripts/extract-release-notes.sh" "$version" >/dev/null
