#!/usr/bin/env bash
set -euo pipefail
approved_commit=${1-}
candidate_commit=${2-}
[[ "$approved_commit" =~ ^[0-9a-f]{40}$ ]]
[[ "$candidate_commit" =~ ^[0-9a-f]{40}$ ]]
[[ "$approved_commit" == "$candidate_commit" ]]
