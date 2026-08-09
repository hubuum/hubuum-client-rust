#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="${SCRIPT_DIR}/check-release-provenance.sh"
TEST_ROOT="$(mktemp -d)"
REPOSITORY="${TEST_ROOT}/repository"

cleanup() {
  rm -rf "${TEST_ROOT}"
}
trap cleanup EXIT

fail() {
  echo "error: $*" >&2
  exit 1
}

git init --quiet --initial-branch=main "${REPOSITORY}"
git -C "${REPOSITORY}" config user.email release-test@example.invalid
git -C "${REPOSITORY}" config user.name "Release provenance test"
git -C "${REPOSITORY}" config commit.gpgsign false
git -C "${REPOSITORY}" commit --quiet --allow-empty -m "main release commit"

main_sha="$(git -C "${REPOSITORY}" rev-parse HEAD)"
git -C "${REPOSITORY}" update-ref refs/remotes/origin/main "${main_sha}"

(
  cd "${REPOSITORY}"
  "${CHECKER}" "${main_sha}" origin/main >/dev/null
)

git -C "${REPOSITORY}" switch --quiet -c non-main
git -C "${REPOSITORY}" commit --quiet --allow-empty -m "non-main commit"
non_main_sha="$(git -C "${REPOSITORY}" rev-parse HEAD)"
failure_output="${TEST_ROOT}/non-main-error"

if (
  cd "${REPOSITORY}"
  "${CHECKER}" "${non_main_sha}" origin/main >"${failure_output}" 2>&1
); then
  fail "provenance guard accepted a non-main release commit"
fi

grep -Fq "does not match protected main head" "${failure_output}" ||
  fail "provenance guard returned an unexpected non-main error"

echo "Release provenance guard accepts main and rejects a non-main commit"
