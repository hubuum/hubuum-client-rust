# Releasing

This repository publishes two crates:

- `hubuum_client_derive`
- `hubuum_client`

`hubuum_client` depends on `hubuum_client_derive`, so releases always publish the proc-macro crate first.

## First release bootstrap (`v0.0.1`)

Trusted publishing on crates.io only works after each crate has been published once manually.

1. Run the local release checks:

   ```bash
   ./scripts/check-release.sh v0.0.1
   ```

2. Publish the crates manually from a clean checkout:

   ```bash
   cargo publish -p hubuum_client_derive --locked
   cargo publish -p hubuum_client --locked
   ```

3. In crates.io, configure a trusted publisher for both crates with:

   - owner: `terjekv`
   - repo: `hubuum-client-rust`
   - workflow: `release.yml`
   - environment: `release`

4. Optional but recommended: in GitHub, create a protected `release` environment so publishes can require approval.

## Regular releases

1. Update both manifest versions to the next release number.
2. Keep `hubuum_client_derive`'s dependency version in the root `Cargo.toml` in sync.
3. Add a dated `## [x.y.z] - YYYY-MM-DD` section to `CHANGELOG.md`.
4. Update the crates.io version snippet in `README.md`.
5. Run:

   ```bash
   ./scripts/check-release.sh vX.Y.Z
   ```

6. Push a tag like `vX.Y.Z`.

The `Release` GitHub Actions workflow validates the release metadata, checks the workspace, lists the packaged files for both crates, and then publishes to crates.io through trusted publishing.
