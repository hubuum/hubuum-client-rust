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

11. Push a tag like `vX.Y.Z`.

The `Release` GitHub Actions workflow validates the release metadata and
generated resource code, checks the workspace, lists the packaged files, and
publishes `hubuum_client` to crates.io through trusted publishing. The publish
job first checks the registry, so the workflow can be rerun safely after a
partial release or manual bootstrap.
