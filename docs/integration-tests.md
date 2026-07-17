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

The script starts PostgreSQL, Hubuum, and a pinned LDAP fixture. It generates a short-lived test CA and hostname-verified LDAPS certificate, configures the server with the scoped `planet-express` provider, waits for readiness, optionally applies SQL seed data, and tears everything down in a shell `trap` unless keep mode is enabled.

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

- `HUBUUM_INTEGRATION_SERVER_IMAGE` overrides the server image.
- `HUBUUM_INTEGRATION_DB_IMAGE` overrides the database image.
- `HUBUUM_INTEGRATION_LDAP_IMAGE` overrides the LDAP fixture image.
- `HUBUUM_INTEGRATION_AUTH_CONFIG` overrides the server auth-provider configuration file.
- `HUBUUM_INTEGRATION_CONTAINER_RUNTIME` forces `docker` or `podman`.
- `HUBUUM_INTEGRATION_STACK_TIMEOUT_SECS` overrides startup timeout. The default is `300`.
- `HUBUUM_INTEGRATION_KEEP_CONTAINERS=1` keeps containers running for debugging.
- `HUBUUM_INTEGRATION_SEED_SQL` overrides the default seed SQL file.

Required CI runs integration tests against an immutable server image digest.
For client 0.5.1, that image is Hubuum server v0.0.2 at
`sha256:8f543383b422124546c8d337fd557e1b182b1b6c7078d7870d3c5cd4f955ef1f`.
A scheduled compatibility workflow separately runs against
`ghcr.io/hubuum/hubuum-server:main`, so upstream movement is visible without
making otherwise unrelated pull requests nondeterministic.

See [the compatibility history](../COMPATIBILITY.md) for earlier releases and
the precise meaning of a declared server target.

If the server image is private in your environment, authenticate first:

```bash
docker login ghcr.io
```
