#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "error: $*" >&2
  exit 1
}

resolve_commit() {
  local ref="$1"

  git rev-parse --verify "${ref}^{commit}" 2>/dev/null ||
    fail "unable to resolve commit for $ref"
}

release_ref="${1:-${GITHUB_SHA:-}}"
main_ref="${2:-origin/main}"

[ -n "$release_ref" ] || fail "pass the release commit or set GITHUB_SHA"

release_sha="$(resolve_commit "$release_ref")"
main_sha="$(resolve_commit "$main_ref")"

if [ "$release_sha" != "$main_sha" ]; then
  fail "release commit $release_sha does not match protected main head $main_sha ($main_ref)"
fi

echo "Release commit $release_sha matches protected main head $main_ref"
