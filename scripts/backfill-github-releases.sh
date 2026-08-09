#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "error: $*" >&2
  exit 1
}

latest_tag="$(git tag --list --sort=version:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | tail -n 1 || true)"
[ -n "$latest_tag" ] || fail "repository has no stable vX.Y.Z tags"

release_count=0
while IFS= read -r release_ref; do
  [ -n "$release_ref" ] || continue

  latest_mode="--not-latest"
  if [ "$release_ref" = "$latest_tag" ]; then
    latest_mode="--latest"
  fi

  ./scripts/publish-github-release.sh "$release_ref" "$latest_mode"
  release_count=$((release_count + 1))
done < <(git tag --list --sort=version:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$')

echo "Synchronized $release_count stable GitHub Releases; $latest_tag is Latest"
