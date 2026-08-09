#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "error: $*" >&2
  exit 1
}

release_ref="${1:-}"
latest_mode="${2:---latest}"
gh_bin="${GH_BIN:-gh}"
release_repository="${GITHUB_REPOSITORY:-}"

[ -n "$release_ref" ] || fail "pass a tag like v0.9.0"
[[ "$release_ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "release tag must look like vX.Y.Z"
command -v "$gh_bin" >/dev/null 2>&1 || fail "GitHub CLI not found: $gh_bin"

case "$latest_mode" in
  --latest)
    latest_flag="--latest"
    ;;
  --not-latest)
    latest_flag="--latest=false"
    ;;
  *)
    fail "latest mode must be --latest or --not-latest"
    ;;
esac

run_gh() {
  if [ -n "$release_repository" ]; then
    "$gh_bin" "$@" --repo "$release_repository"
  else
    "$gh_bin" "$@"
  fi
}

notes_file="$(mktemp)"
trap 'rm -f "$notes_file"' EXIT
./scripts/release-notes.sh "$release_ref" > "$notes_file"

if run_gh release view "$release_ref" >/dev/null 2>&1; then
  run_gh release edit "$release_ref" \
    --verify-tag \
    --title "$release_ref" \
    --notes-file "$notes_file" \
    "$latest_flag"
else
  run_gh release create "$release_ref" \
    --verify-tag \
    --title "$release_ref" \
    --notes-file "$notes_file" \
    "$latest_flag"
fi
