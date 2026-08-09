# Releasing

This repository publishes one crate: `hubuum_client`. The workspace also contains
the unpublished `hubuum_reconcile` code generator and the unpublished
`e2e_client` integration consumer.

## First release bootstrap

Trusted publishing on crates.io only works after a crate has been published once
manually. Run this bootstrap only when introducing a new published crate, before
creating the release tag that should publish it.

1. Run the local release checks:

   ```bash
   ./scripts/check-release.sh vX.Y.Z
   ```

2. Publish the new crate manually from a clean checkout:

   ```bash
   cargo publish -p <new-crate> --locked
   ```

3. In crates.io, configure a trusted publisher for the new crate with:

   - owner: `terjekv`
   - repo: `hubuum-client-rust`
   - workflow: `release.yml`
   - environment: `release`

4. Optional but recommended: in GitHub, create a protected `release` environment so publishes can require approval.

## Regular releases

1. Confirm that the repository has no open pull requests. Merge or close every
   open pull request before continuing with the release.
2. Update every direct and transitive dependency to its latest version
   compatible with the declared MSRV and repository policies. Update manifest
   constraints where needed, regenerate `Cargo.lock`, and run `cargo audit`,
   `cargo deny check bans licenses sources`, and the required workspace checks.
   The MSRV check must cover every workspace target:

   ```bash
   cargo +1.88 check --workspace --all-targets --all-features --locked
   ```

   Do not defer a blocked dependency update until after the release.
3. Update the client manifest version to the next release number.
4. Reconcile generated resource code and commit any reviewed changes:

   ```bash
   cargo run -p hubuum_reconcile --locked -- update
   cargo run -p hubuum_reconcile --locked -- check
   ```

5. Set `[package.metadata.hubuum].server-version` and `server-image` to the
   targeted server release and its immutable image digest.
6. Update the required CI image and pinned OpenAPI source to the same server
   release. Keep scheduled forward-compatibility checks on server `main`.
7. Add the client/server pair and test evidence to `COMPATIBILITY.md`.
8. Add a dated `## [x.y.z] - YYYY-MM-DD` section to `CHANGELOG.md` that names
   the targeted server release.
9. Update the crates.io version and compatibility statements in `README.md`.
10. Run:

   ```bash
   ./scripts/check-release.sh vX.Y.Z
   ```

11. Fetch the protected branch and confirm the release commit is its exact
    current head:

    ```bash
    git fetch origin main
    ./scripts/check-release-provenance.sh HEAD origin/main
    ```

12. Push a tag like `vX.Y.Z` from that verified commit. Do not merge another
    commit to `main` until the release workflow has accepted the tag.

The `Release` GitHub Actions workflow fetches `origin/main` and rejects a tag
unless its commit is exactly the protected branch head. It validates release
metadata and package contents, then invokes the repository's reusable CI
workflow for the exact tagged commit. Formatting, lint, documentation, unit and
compile tests, every feature combination, MSRV, OpenAPI drift, supply-chain,
public API compatibility, and pinned library plus `e2e_client` integration
checks must all succeed before trusted publishing can start.

The publish job first checks the registry, so the workflow can be rerun safely
after a partial release or manual bootstrap. A rerun still repeats provenance
and required-check evidence before treating an existing crates.io version as a
successful no-op.
