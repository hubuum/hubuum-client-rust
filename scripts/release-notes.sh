#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "error: $*" >&2
  exit 1
}

release_ref="${1:-}"
changelog="${2:-CHANGELOG.md}"

[ -n "$release_ref" ] || fail "pass a tag like v0.9.0"
[[ "$release_ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "release tag must look like vX.Y.Z"
[ -f "$changelog" ] || fail "missing $changelog"

release_version="${release_ref#v}"
escaped_release_version="${release_version//./\\.}"
heading_pattern="^## \\[$escaped_release_version\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$"
heading_count="$(grep -Ec "$heading_pattern" "$changelog" || true)"

[ "$heading_count" -eq 1 ] || fail "$changelog must contain exactly one dated heading for $release_version"
heading="$(grep -E "$heading_pattern" "$changelog")"

if ! awk -v heading="$heading" '
  /^## / {
    if (in_release) {
      exit
    }
    if ($0 == heading) {
      in_release = 1
    }
    next
  }

  in_release {
    if ($0 ~ /^[[:space:]]*$/) {
      if (printed) {
        pending_blank_lines = pending_blank_lines "\n"
      }
      next
    }

    printf "%s", pending_blank_lines
    pending_blank_lines = ""
    print
    printed = 1
  }

  END {
    if (!in_release || !printed) {
      exit 1
    }
  }
' "$changelog"; then
  fail "$changelog has no release notes for $release_version"
fi
