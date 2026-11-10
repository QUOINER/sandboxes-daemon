#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ! "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'usage: %s VERSION [CHANGELOG]\n' "${0##*/}" >&2
  exit 2
fi

version=$1
changelog=${2:-CHANGELOG.md}

LC_ALL=C awk -v version="$version" '
function target_heading(line, expected, next_char) {
  expected = "## v" version
  if (index(line, expected) != 1) return 0
  next_char = substr(line, length(expected) + 1, 1)
  return next_char == "" || next_char ~ /[[:space:]]/
}
{
  if (target_heading($0)) {
    count++
    in_section = count == 1
    next
  }
  if (in_section && /^## /) in_section = 0
  if (in_section) {
    if ($0 != "" || content != "") content = content (content == "" ? "" : "\n") $0
  }
}
END {
  if (count != 1) exit 1
  sub(/\n+$/, "", content)
  if (content ~ /^[[:space:]]*$/) exit 1
  print content
}
' "$changelog"
