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

read_metadata_field() {
  local manifest="$1"
  local key="$2"

  awk -F'=' -v key="$key" '
    /^\[package\.metadata\.hubuum\]$/ {
      in_metadata = 1
      next
    }

    /^\[/ {
      if (in_metadata) {
        exit
      }
    }

    in_metadata {
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
[ -f "COMPATIBILITY.md" ] || fail "missing COMPATIBILITY.md"

root_version="$(read_package_field "$root_manifest" version)"
derive_version="$(read_package_field "$derive_manifest" version)"
dependency_version="$(read_dependency_version "$root_manifest" hubuum_client_derive)"
server_version="$(read_metadata_field "$root_manifest" server-version)"
server_image="$(read_metadata_field "$root_manifest" server-image)"

[ "$root_version" = "$release_version" ] || fail "Cargo.toml version $root_version does not match $release_ref"
[ "$derive_version" = "$release_version" ] || fail "hubuum_client_derive/Cargo.toml version $derive_version does not match $release_ref"
[ "$dependency_version" = "$derive_version" ] || fail "Cargo.toml depends on hubuum_client_derive $dependency_version but hubuum_client_derive/Cargo.toml is $derive_version"
[ -n "$server_version" ] || fail "Cargo.toml is missing [package.metadata.hubuum].server-version"
[ -n "$server_image" ] || fail "Cargo.toml is missing [package.metadata.hubuum].server-image"
printf '%s\n' "$server_image" | grep -Eq '^ghcr\.io/hubuum/hubuum-server@sha256:[0-9a-f]{64}$' || fail "Cargo.toml server-image must be an immutable Hubuum image digest"

grep -Eq '^## \[Unreleased\]$' CHANGELOG.md || fail "CHANGELOG.md must keep an [Unreleased] section"
grep -Eq "^## \\[$release_version\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md || fail "CHANGELOG.md must contain a dated heading for $release_version"
grep -Fq "hubuum_client = \"$release_version\"" README.md || fail "README.md must reference hubuum_client = \"$release_version\""
grep -Fq "hubuum_client\` $release_version targets Hubuum server v$server_version" README.md || fail "README.md must state that hubuum_client $release_version targets Hubuum server v$server_version"
grep -Fq "| $release_version | $server_version | \`$server_image\` |" COMPATIBILITY.md || fail "COMPATIBILITY.md must record client $release_version, server $server_version, and $server_image"
grep -Fq "This release explicitly targets Hubuum server v$server_version" CHANGELOG.md || fail "CHANGELOG.md must state the Hubuum server v$server_version target"
grep -Fq "pub const TARGET_SERVER_VERSION: &str = \"$server_version\";" src/lib.rs || fail "TARGET_SERVER_VERSION must match Hubuum server v$server_version"
grep -Fq "HUBUUM_TARGET_SERVER_VERSION: \"$server_version\"" .github/workflows/ci.yml || fail "CI target server version must match $server_version"
grep -Fq "HUBUUM_TARGET_SERVER_IMAGE: $server_image" .github/workflows/ci.yml || fail "CI target server image must match $server_image"
grep -Fq "/v$server_version/docs/openapi.json" scripts/openapi-contract.py || fail "pinned OpenAPI source must target Hubuum server v$server_version"

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
