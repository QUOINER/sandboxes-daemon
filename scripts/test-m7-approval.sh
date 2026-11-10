#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
helper="$root/scripts/require-m7-approval.sh"
sha=0123456789abcdef0123456789abcdef01234567
"$helper" "$sha" "$sha"
expect_failure() {
  local label=$1
  shift
  if "$helper" "$@" >/dev/null 2>&1; then
    printf 'M7 approval accepted negative control: %s\n' "$label" >&2
    exit 1
  fi
}
expect_failure missing '' "$sha"
expect_failure malformed short "$sha"
expect_failure uppercase 0123456789ABCDEF0123456789ABCDEF01234567 "$sha"
expect_failure mismatch "$sha" 1123456789abcdef0123456789abcdef01234567
printf 'PASS: 1 positive and 4 negative M7 approval controls\n'
condition='if [[ ! "$M7_EXTERNAL_SECURITY_REVIEW_APPROVED_COMMIT" =~ ^[0-9a-f]{40}$ || "$M7_EXTERNAL_SECURITY_REVIEW_APPROVED_COMMIT" != "$GITHUB_SHA" ]]; then'
matched=0
for workflow in "$root"/.github/workflows/*.yml; do
  if grep -Fq 'M7_EXTERNAL_SECURITY_REVIEW_APPROVED_COMMIT' "$workflow"; then
    grep -Fq "$condition" "$workflow"
    grep -Fq 'M7_EXTERNAL_SECURITY_REVIEW_APPROVED_COMMIT: ${{ vars.M7_EXTERNAL_SECURITY_REVIEW_APPROVED_COMMIT }}' "$workflow"
    grep -Fq 'environment: m7-external-security-review' "$workflow"
    matched=$((matched + 1))
  fi
done
[[ "$matched" -ge 2 ]]
printf 'PASS: commit-bound inline condition present in %s gated workflows\n' "$matched"
workflow="$root/.github/workflows/m7-pretag-approval.yml"
[[ "$(grep -Ec '^  create_tag:$' "$workflow")" -eq 1 ]]
create_tag_job=$(awk '
  /^  create_tag:$/ { in_job = 1 }
  in_job && /^  [[:alnum:]_-]+:$/ && $0 != "  create_tag:" { exit }
  in_job { print }
' "$workflow")
grep -Fq '    needs: m7_approval' <<<"$create_tag_job"
grep -Fq '      contents: write' <<<"$create_tag_job"
grep -Fq '[[ "$GITHUB_REF" == "refs/heads/main" ]]' <<<"$create_tag_job"
grep -Fq '[[ "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]' <<<"$create_tag_job"
grep -Fq '[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]' <<<"$create_tag_job"
grep -Fq 'ref=refs/tags/$tag' <<<"$create_tag_job"
grep -Fq 'object=$GITHUB_SHA' <<<"$create_tag_job"
grep -Fq 'sha=$tag_object' <<<"$create_tag_job"
grep -Fq 'GH_TOKEN: ${{ github.token }}' <<<"$create_tag_job"
! grep -Fq 'actions/checkout' <<<"$create_tag_job"
! grep -Fq 'scripts/' <<<"$create_tag_job"
[[ "$(grep -Fc 'contents: write' "$workflow")" -eq 1 ]]
if grep -Eq -- '--force|--force-with-lease' <<<"$create_tag_job"; then
  printf 'release tag workflow must never force-update refs\n' >&2
  exit 1
fi
dispatch_job=$(awk '
  /^  dispatch_release:$/ { in_job = 1 }
  in_job && /^  [[:alnum:]_-]+:$/ && $0 != "  dispatch_release:" { exit }
  in_job { print }
' "$workflow")
grep -Fq '    needs: create_tag' <<<"$dispatch_job"
grep -Fq "if: github.repository == 'rheic/sandboxes-daemon' || github.repository == 'rheic/sandboxes-cli'" <<<"$dispatch_job"
grep -Fq 'TAG: v${{ inputs.version }}' <<<"$dispatch_job"
grep -Fq 'ref=$TAG' <<<"$dispatch_job"
! grep -Fq 'contents: write' <<<"$dispatch_job"
grep -Fq '      actions: write' <<<"$dispatch_job"
grep -Fq 'actions/workflows/release.yml/dispatches' <<<"$dispatch_job"
[[ "$(grep -Fc 'actions: write' "$workflow")" -eq 1 ]]
if [[ -f "$root/.github/workflows/release.yml" ]]; then
  grep -Fq '  workflow_dispatch:' "$root/.github/workflows/release.yml"
fi
printf 'PASS: tag write token is isolated; release dispatch has a separate minimal job\n'
