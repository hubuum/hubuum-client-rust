# Integration Tests

The repository includes an opt-in Docker-backed integration test suite in `tests/container_integration.rs`.

## Entrypoints

Recommended entrypoint:

```bash
./scripts/run-integration-tests.sh
```

Run both library integration tests and the consumer e2e client suite:

```bash
./scripts/run-integration-tests.sh --with-e2e-client
```

Run only the consumer e2e client suite. This still provisions the complete test stack:

```bash
./scripts/run-integration-tests.sh --e2e-only
```

The script pulls and reports the selected PostgreSQL, Hubuum, and LDAP images
before starting the stack. Their defaults are immutable multi-platform image
digests. It generates a short-lived test CA and hostname-verified LDAPS
certificate, configures the server with the scoped `planet-express` provider,
runs `hubuum-admin --migrate` before starting the server, starts a separate
`hubuum-admin --restore-executor`, waits for readiness, optionally applies SQL seed
data, and tears everything down in a shell `trap` unless keep mode is enabled.

Provider coverage discovers the unauthenticated provider list, rejects invalid LDAP credentials, logs in real directory users through both async and blocking clients, verifies synchronized user and group metadata, and exercises settings replace, merge-patch, get, and reset operations as an external user. The fixture configuration lives at `tests/container_integration/fixtures/auth-providers.toml`.

Mutating integration tests use unique `itest-<case>-<ts>` resource name prefixes, so they are safe to run with default parallel test threads.

## Seed Behavior

- Default seed file: `tests/container_integration/seed/init.sql`
- Custom seed file: `./scripts/run-integration-tests.sh --seed path/to/seed.sql`
- Disable seeding: `./scripts/run-integration-tests.sh --skip-seed`

## External Stack Mode

Tests can reuse an externally managed stack when both env vars are set:

- `HUBUUM_INTEGRATION_BASE_URL`
- `HUBUUM_INTEGRATION_ADMIN_PASSWORD`

This is what the wrapper script exports internally before running tests.
An external stack must expose the same `planet-express` provider and fixture users to run the provider-specific tests.

## Optional Environment Variables

- `HUBUUM_INTEGRATION_SERVER_IMAGE` overrides the server image. By default the
  wrapper reads the immutable `[package.metadata.hubuum].server-image` value
  from `Cargo.toml`.
- `HUBUUM_INTEGRATION_DB_IMAGE` overrides the database image. By default the
  wrapper and the self-provisioning Rust test stack read the immutable
  PostgreSQL 18 reference from
  `tests/container_integration/fixtures/postgres/Dockerfile`.
- `HUBUUM_INTEGRATION_LDAP_IMAGE` overrides the LDAP fixture image.
- `HUBUUM_INTEGRATION_AUTH_CONFIG` overrides the server auth-provider configuration file.
- `HUBUUM_INTEGRATION_CONTAINER_RUNTIME` forces `docker` or `podman`.
- `HUBUUM_INTEGRATION_STACK_TIMEOUT_SECS` overrides startup timeout. The default is `300`.
- `HUBUUM_INTEGRATION_KEEP_CONTAINERS=1` keeps containers running for debugging.
- `HUBUUM_INTEGRATION_SEED_SQL` overrides the default seed SQL file.

Required CI runs integration tests against an immutable server image digest.
For client 0.11.0, that image is Hubuum server v0.0.15 at
`sha256:36af667dbc9e221a40448496d4a87e168c999d0834df4b69177345ff3d36e821`.
A scheduled compatibility workflow separately runs against
`ghcr.io/hubuum/hubuum-server:main`, so upstream movement is visible without
making otherwise unrelated pull requests nondeterministic.

Dependabot checks the PostgreSQL fixture Dockerfile weekly. Review proposed
digest updates for supported `linux/amd64` and `linux/arm64` manifests and run
the canonical combined integration command before merging them. Intentional
experiments can still select another tag or digest with
`HUBUUM_INTEGRATION_DB_IMAGE` without changing the repository default.

See [the compatibility history](../COMPATIBILITY.md) for earlier releases and
the precise meaning of a declared server target.

If the server image is private in your environment, authenticate first:

```bash
docker login ghcr.io
```

## Full restore coverage

With `--with-e2e-client` or `--e2e-only`, the wrapper runs both blocking and async
full restore scenarios with and without history after all ordinary suites finish.
Each scenario activates an enforced schema, creates and downloads a format 6 backup, deletes an object, stages
and confirms the restore, polls with its capability until completion, verifies bearer-token
invalidation, and checks that the deleted object and its revision were restored
after a new login. Recovery also creates and stages default backups before and
after another mutation. Recovery also checks the restored schema revision and
object validation evidence, with and without history.
Because format 6 excludes password hashes, the wrapper resets the disposable
administrator password after each restore before running the recovery assertion.

The separate `e2e_client` restore test target requires `restore-tests` and the
wrapper-owned `HUBUUM_INTEGRATION_DISPOSABLE_BASE_URL` marker. It is never part
of ordinary tests against an externally managed stack; full restore replaces
all data and invalidates tokens. The complete non-container workspace suite
compiles these tests but leaves them ignored.
