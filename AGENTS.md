# Repository Guidelines

These instructions apply to the entire repository. Rust and pull-request
conventions intentionally align with the Hubuum server repository where they
also make sense for this client library.

## Repository Scope And Sources Of Truth

- This workspace contains the public `hubuum_client` crate, the
  `hubuum_client_derive` procedural-macro crate, and the unpublished
  `e2e_client` consumer used for integration coverage.
- Treat the root `Cargo.toml` as the source of truth for the client version,
  minimum supported Rust version (MSRV), feature definitions, target Hubuum
  server version, and immutable target server image.
- Keep `src/lib.rs::TARGET_SERVER_VERSION`, `.github/workflows/ci.yml`, the
  pinned source in `scripts/openapi-contract.py`, `README.md`, `CHANGELOG.md`,
  and `COMPATIBILITY.md` synchronized with the root manifest.
- [`COMPATIBILITY.md`](COMPATIBILITY.md) defines what a declared server target
  means. Required CI uses the immutable image for that target; scheduled
  workflows against server `main` are forward-compatibility signals and do not
  redefine a release's declared compatibility.
- `RELEASING.md` is the authoritative release checklist. Update it when the
  publishing process changes.

## Verification

Before considering a Rust change complete, run the checks that match CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo test --workspace --all-features --locked
python3 scripts/openapi-contract.py validate
```

Check every supported public feature combination when client code, feature
gates, dependencies, or manifests change:

```bash
cargo check -p hubuum_client --locked --no-default-features
cargo check -p hubuum_client --locked --no-default-features --features async
cargo check -p hubuum_client --locked --no-default-features --features blocking
cargo check -p hubuum_client --locked --no-default-features --features async,typed-schemas
cargo check -p hubuum_client --locked --no-default-features --features blocking,typed-schemas
```

- Check the workspace with the `rust-version` declared in the manifests
  (currently Rust 1.88) when changing dependencies, language features, or public
  macros.
- For dependency changes, run `cargo audit` and
  `cargo deny check bans licenses sources`. Commit the resulting `Cargo.lock`
  changes and do not update only one workspace manifest when versions or the
  MSRV must stay aligned.
- Pull requests are also checked for public API compatibility. Treat semver
  findings as design feedback; do not suppress a real breaking change.
- Do not replace the full suite with a broad hand-selected subset. Focused
  tests are useful while iterating, but finish with the workspace command above.
- `cargo test --workspace --all-features --locked` is the complete
  non-container suite, but it intentionally leaves Docker-backed tests ignored.
  Do not describe that command alone as complete end-to-end verification.

## Docker-Backed Integration Tests

- Run the complete library and consumer integration suites with:

  ```bash
  ./scripts/run-integration-tests.sh --with-e2e-client -- --test-threads=1
  ```

  This is the canonical complete test setup. It must run both
  `tests/container_integration.rs` and the standalone `e2e_client` suite.

- The wrapper provisions PostgreSQL, Hubuum, and the pinned LDAP fixture. It
  generates temporary LDAPS certificates and tears the stack down unless keep
  mode is explicitly enabled.
- The `e2e_client` crate is a real downstream consumer of the public crate API.
  Keep it independent of crate-private implementation details and include its
  authentication, CRUD, permissions, relations, search, imports/exports/tasks,
  backups/computed fields, metrics, and remote-target scenarios in complete
  verification.
- Use `./scripts/run-integration-tests.sh --e2e-only` only when intentionally
  isolating the consumer suite during iteration. It is not a substitute for the
  canonical combined command before merging a client or server-contract change.
- Use the target server image from `[package.metadata.hubuum]` for release and
  compatibility evidence. Do not substitute the floating `main` image for the
  required pinned run.
- Use `HUBUUM_INTEGRATION_SERVER_IMAGE` and the other variables documented in
  `docs/integration-tests.md` when a focused run needs an override.
- Integration resources must use the shared unique naming helpers so tests
  remain safe under parallel execution.

## Client Architecture

- Keep transport-independent request construction, parsing, pagination,
  retries, URL safety, and other shared behavior in `src/client/shared.rs` or
  `src/client/transport.rs`.
- Keep async and blocking implementations in `src/client/async.rs` and
  `src/client/sync.rs`. Public capabilities should remain equivalent unless a
  documented runtime constraint makes parity impossible.
- Extend the compile-time parity contract in `src/client/mod.rs` whenever a new
  public client, scope, builder, or handle method should exist in both modes.
- Keep endpoint paths centralized in `src/endpoints.rs`. Dynamic path values
  are opaque segments and must use the shared path-segment encoder; do not
  bypass base-URL, origin, traversal, or authorization-header safeguards.
- Put API resource definitions and resource-specific handle behavior in
  `src/resources/*`. Put reusable wire/domain models in `src/types/*`.
- Keep procedural-macro behavior isolated in `hubuum_client_derive`. Generated
  request types and builders are public API and require compile-pass and, where
  appropriate, compile-fail coverage.
- Prefer the typed client surface over `raw()`. Keep `raw()` available as a
  constrained extension point for authenticated relative routes that do not yet
  have dedicated helpers.

## Rust Standards

- Follow Rust best practices and the conventions already present in this
  repository.
- Prefer newtypes and the existing typed resource IDs instead of passing raw
  primitives through public and domain APIs unchecked.
- Newtypes should usually have validating constructors, private fields, and
  explicit accessors or setters where mutation is part of the model.
- Accept typed IDs and validated types at API boundaries whenever practical so
  invalid states are rejected early with clear, actionable errors.
- Preserve typestate authentication: unauthenticated clients expose only public
  operations and login, while authenticated clients own secret-bearing state.
- Put behavior on types with `impl` blocks when it naturally belongs to the
  type. Prefer this over collections of bare functions operating on loosely
  related data.
- Keep invariants close to the data they protect. Constructors, setters, and
  terminal builder methods should reject invalid states rather than relying on
  callers to remember preconditions.
- Use small, explicit APIs. Keep representation details private unless they are
  an intentional interoperability surface.
- Use `ApiError` as the public error surface. Prefer structured, specific
  variants and preserve useful server error details.
- Secret-bearing types, headers, bodies, URLs, credentials, capabilities, and
  tokens must remain redacted from `Debug`, logs, and error messages.
- Prefer `use` imports over inline fully qualified paths. Fully qualify a path
  only to resolve genuine ambiguity or when a one-off import would mislead.
- Use conventional Rust module discovery (`foo.rs` or `foo/mod.rs`). Do not use
  `#[path = "..."]` overrides.
- Keep `rustfmt` mechanical and make Clippy pass with warnings denied. Do not add
  broad `allow` attributes or dead code merely to make a build pass.

## OpenAPI And Server Compatibility

- `openapi/operations.json` is the committed normalized snapshot for the server
  release named in `[package.metadata.hubuum]`.
- Validate snapshot integrity with
  `python3 scripts/openapi-contract.py validate`.
- Compare against the pinned authoritative server tag with
  `python3 scripts/openapi-contract.py check`.
- After reviewing intentional server drift, regenerate with
  `python3 scripts/openapi-contract.py update`, then implement or document every
  operation change. Keep intentional limitations in `openapi/known-gaps.md`.
- Endpoint changes are incomplete until endpoint constants, URL parameters,
  request/response models, async and blocking methods, parity checks, behavior
  tests, and compatibility evidence agree.
- Runtime routes omitted from OpenAPI still require explicit behavior and live
  integration coverage.

## Tests

Treat the test setup as a layered contract:

1. Unit tests cover shared parsing, builders, endpoint mappings, models, and
   procedural-macro behavior.
2. Behavior and foundation tests cover public async/blocking requests,
   transports, URL safety, redaction, pagination, and error handling.
3. Trybuild tests cover public compile-time guarantees for typed IDs, query
   operators, and generated checked builders.
4. Docker-backed library tests exercise the client against the pinned Hubuum
   server with PostgreSQL and the LDAP/LDAPS provider fixture.
5. `e2e_client` verifies that an independent consumer can use the complete
   public API in real workflows.

- A change affecting public APIs, authentication, server routes, models,
  feature gates, or compatibility is not fully tested until the relevant unit
  and behavior layers pass and the combined Docker-backed library plus
  `e2e_client` command has passed.
- Keep each test focused on one behavior. Use `rstest` or `yare`
  parameterization when the same behavior varies by input.
- Use `MockTransport` for deterministic request-plan, header, body, retry,
  redaction, and URL assertions. Use `httpmock` for HTTP-facing behavior where
  an actual local server boundary matters.
- Put public client behavior in `tests/client_behavior.rs`, foundational safety
  and transport behavior in `tests/foundations.rs`, shared async/blocking
  scenarios in `tests/shared_scenarios.rs`, and compile contracts under
  `tests/trybuild`.
- Add regression tests for bug fixes, including both async and blocking paths
  when shared behavior could diverge.
- Use Docker-backed tests for server-contract claims that mocks cannot prove.
  Add or update the corresponding `e2e_client/tests/*` scenario whenever a
  public workflow needs downstream-consumer coverage.
- Do not add unused fields, functions, imports, or `#[allow(dead_code)]` solely
  to make a test or build pass; remove what is unused.

## Pull Requests And Merges

- Keep each pull request scoped to one coherent change and explain the user or
  compatibility impact, important design decisions, and verification evidence.
- Treat changelog review as required for every pull request. Add user-facing
  additions, changes, fixes, and security notes to `[Unreleased]` in
  `CHANGELOG.md`. If a change has no changelog-worthy impact, say so explicitly
  in the pull-request description rather than adding an empty or internal-only
  entry.
- Call out every breaking change explicitly in both the pull-request
  description and the `[Unreleased]` changelog entry, including the upgrade or
  migration action users must take.
- Describe changes to the declared Hubuum server target, OpenAPI surface,
  feature availability, MSRV, or dependencies explicitly. Include pinned live
  integration evidence for compatibility claims.
- Do not merge until required formatting, lint, documentation, tests, feature
  combinations, MSRV, contract, supply-chain, semver, and pinned integration
  checks pass or an exceptional failure is understood and documented.
- When squash-merging, use the detailed pull-request description as the squash
  commit body. Preserve the substantive summary, rationale, behavior notes,
  compatibility notes, migration guidance, and issue references; remove
  verification-only sections such as command transcripts, checklists, and
  `## Testing` or `## Verification` sections.

## Releases

- This repository publishes `hubuum_client_derive` before `hubuum_client`; the
  client depends on the derive crate at the same release version.
- Every release must update [`COMPATIBILITY.md`](COMPATIBILITY.md). Add a row
  containing the client version, declared Hubuum server target, immutable
  tested server image digest, and concise test evidence. A release is not ready
  while that record is missing or disagrees with `Cargo.toml`.
- In the same release change, synchronize both crate versions, the derive
  dependency, root package metadata, `TARGET_SERVER_VERSION`, pinned OpenAPI
  source and snapshot, required CI image, `README.md`, and `CHANGELOG.md`.
- Record breaking changes and migration actions in the dated release section.
- Run `./scripts/check-release.sh vX.Y.Z` from a clean checkout before tagging.
- Tags matching `vX.Y.Z` drive the trusted-publishing workflow. Do not manually
  publish a regular release unless recovering from a documented workflow issue
  or bootstrapping a new crate as described in `RELEASING.md`.

## Security And Change Discipline

- Report suspected vulnerabilities through GitHub private vulnerability
  reporting as described in `SECURITY.md`; do not put undisclosed details in a
  public issue or pull request.
- Keep edits scoped to the task at hand and preserve unrelated work in a dirty
  checkout.
- Add or update tests whenever behavior changes or a bug fix would otherwise be
  easy to regress.
- Prefer clear, idiomatic code over cleverness.
