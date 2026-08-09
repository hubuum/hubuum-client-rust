#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "error: $*" >&2
  exit 1
}

task_temp_dir="$(mktemp -d)"
trap 'rm -rf "$task_temp_dir"' EXIT
repo_root="$(pwd)"

fixture="$task_temp_dir/CHANGELOG.md"
cat > "$fixture" <<'EOF'
# Changelog

## [Unreleased]

- Unreleased note that must not leak.

## [1.2.3] - 2026-08-09

### Added

- First release note.

### Fixed

- Second release note.

## [1.2.2] - 2026-08-08

- Older note that must not leak.
EOF

expected="$task_temp_dir/expected.md"
cat > "$expected" <<'EOF'
### Added

- First release note.

### Fixed

- Second release note.
EOF

actual="$task_temp_dir/actual.md"
./scripts/release-notes.sh v1.2.3 "$fixture" > "$actual"
diff -u "$expected" "$actual"

if ./scripts/release-notes.sh v1.2.4 "$fixture" >/dev/null 2>&1; then
  fail "missing release section was accepted"
fi

if ./scripts/release-notes.sh 1.2.3 "$fixture" >/dev/null 2>&1; then
  fail "release tag without v prefix was accepted"
fi

mock_gh="$task_temp_dir/gh"
cat > "$mock_gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = "release" ] && [ "${2:-}" = "view" ]; then
  [ "${FAKE_RELEASE_EXISTS:-false}" = "true" ]
  exit
fi

printf '%s\n' "$*" >> "$FAKE_GH_LOG"

while [ "$#" -gt 0 ]; do
  if [ "$1" = "--notes-file" ]; then
    cp "$2" "$FAKE_NOTES_COPY"
    break
  fi
  shift
done
EOF
chmod +x "$mock_gh"

cp "$fixture" "$task_temp_dir/publish-CHANGELOG.md"
(
  cd "$task_temp_dir"
  mv publish-CHANGELOG.md CHANGELOG.md
  mkdir scripts
  cp "$repo_root/scripts/release-notes.sh" scripts/release-notes.sh
  GH_BIN="$mock_gh" \
    GITHUB_REPOSITORY=hubuum/hubuum-client-rust \
    FAKE_RELEASE_EXISTS=false \
    FAKE_GH_LOG="$task_temp_dir/create.log" \
    FAKE_NOTES_COPY="$task_temp_dir/create-notes.md" \
    "$repo_root/scripts/publish-github-release.sh" v1.2.3 --latest
) || fail "create path failed"

grep -Fq "release create v1.2.3" "$task_temp_dir/create.log"
grep -Fq -- "--verify-tag" "$task_temp_dir/create.log"
grep -Fq -- "--latest" "$task_temp_dir/create.log"
grep -Fq -- "--repo hubuum/hubuum-client-rust" "$task_temp_dir/create.log"
diff -u "$expected" "$task_temp_dir/create-notes.md"

(
  cd "$task_temp_dir"
  GH_BIN="$mock_gh" \
    FAKE_RELEASE_EXISTS=true \
    FAKE_GH_LOG="$task_temp_dir/edit.log" \
    FAKE_NOTES_COPY="$task_temp_dir/edit-notes.md" \
    "$repo_root/scripts/publish-github-release.sh" v1.2.3 --not-latest
) || fail "edit path failed"

grep -Fq "release edit v1.2.3" "$task_temp_dir/edit.log"
grep -Fq -- "--latest=false" "$task_temp_dir/edit.log"
diff -u "$expected" "$task_temp_dir/edit-notes.md"

(
  cd "$task_temp_dir"
  cp "$repo_root/scripts/publish-github-release.sh" scripts/publish-github-release.sh
  cp "$repo_root/scripts/backfill-github-releases.sh" scripts/backfill-github-releases.sh
  git init --quiet
  git config user.email release-test@example.invalid
  git config user.name "Release Test"
  git config commit.gpgsign false
  git add CHANGELOG.md scripts
  git commit --quiet -m "Create release fixture"
  git tag v1.2.2
  git tag v1.2.3
  git tag v1.2.4-rc.1

  GH_BIN="$mock_gh" \
    FAKE_RELEASE_EXISTS=true \
    FAKE_GH_LOG="$task_temp_dir/backfill.log" \
    FAKE_NOTES_COPY="$task_temp_dir/backfill-notes.md" \
    ./scripts/backfill-github-releases.sh > "$task_temp_dir/backfill-output.log"

  grep -Fq "release edit v1.2.2" "$task_temp_dir/backfill.log"
  grep -Fq "release edit v1.2.3" "$task_temp_dir/backfill.log"
  if grep -Fq "v1.2.4-rc.1" "$task_temp_dir/backfill.log"; then
    fail "prerelease tag was included in stable backfill"
  fi
  grep -Fq -- "--latest=false" "$task_temp_dir/backfill.log"
  grep -Fq "v1.2.3 is Latest" "$task_temp_dir/backfill-output.log"
) || fail "backfill path failed"

echo "GitHub Release helpers passed"
