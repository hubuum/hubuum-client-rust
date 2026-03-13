#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "error: $*" >&2
  exit 1
}

read_package_field() {
  local manifest="$1"
  local key="$2"

  awk -F'=' -v key="$key" '
    /^\[package\]$/ {
      in_package = 1
      next
    }

    /^\[/ {
      if (in_package) {
        exit
      }
    }

    in_package {
      lhs = $1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
      if (lhs == key) {
        value = substr($0, index($0, "=") + 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        gsub(/^"/, "", value)
        gsub(/"$/, "", value)
        print value
        exit
      }
    }
  ' "$manifest"
}

read_dependency_version() {
  local manifest="$1"
  local dependency="$2"

  sed -nE "s/^${dependency}[[:space:]]*=.*version[[:space:]]*=[[:space:]]*\"([^\"]+)\".*$/\1/p" "$manifest" | head -n1
}

require_manifest_field() {
  local manifest="$1"
  local key="$2"
  local value

  value="$(read_package_field "$manifest" "$key")"
  [ -n "$value" ] || fail "$manifest is missing [package].$key"
}

release_ref="${1:-${GITHUB_REF_NAME:-}}"
[ -n "$release_ref" ] || fail "pass a tag like v0.0.1 or set GITHUB_REF_NAME"

case "$release_ref" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    fail "release tag must look like vX.Y.Z"
    ;;
esac

release_version="${release_ref#v}"
root_manifest="Cargo.toml"
derive_manifest="hubuum_client_derive/Cargo.toml"

[ -f "$root_manifest" ] || fail "missing $root_manifest"
[ -f "$derive_manifest" ] || fail "missing $derive_manifest"
[ -f "CHANGELOG.md" ] || fail "missing CHANGELOG.md"
[ -f "README.md" ] || fail "missing README.md"

root_version="$(read_package_field "$root_manifest" version)"
derive_version="$(read_package_field "$derive_manifest" version)"
dependency_version="$(read_dependency_version "$root_manifest" hubuum_client_derive)"

[ "$root_version" = "$release_version" ] || fail "Cargo.toml version $root_version does not match $release_ref"
# [ "$derive_version" = "$release_version" ] || fail "hubuum_client_derive/Cargo.toml version $derive_version does not match $release_ref"
# [ "$dependency_version" = "$derive_version" ] || fail "Cargo.toml depends on hubuum_client_derive $dependency_version but hubuum_client_derive/Cargo.toml is $derive_version"

grep -Eq '^## \[Unreleased\]$' CHANGELOG.md || fail "CHANGELOG.md must keep an [Unreleased] section"
grep -Eq "^## \\[$release_version\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md || fail "CHANGELOG.md must contain a dated heading for $release_version"
grep -Fq "hubuum_client = \"$release_version\"" README.md || fail "README.md must reference hubuum_client = \"$release_version\""

if grep -Fq 'not yet available from `crates.io`' README.md; then
  fail "README.md still says the crate is not available from crates.io"
fi

for key in description license repository documentation readme; do
  require_manifest_field "$root_manifest" "$key"
done

for key in description license repository documentation readme; do
  require_manifest_field "$derive_manifest" "$key"
done

echo "Release metadata looks good for $release_ref"
