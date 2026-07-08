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

Run only the consumer e2e client suite. This still provisions server and postgres containers:

```bash
./scripts/run-integration-tests.sh --e2e-only
```

The script starts one PostgreSQL container and one Hubuum server container, waits for readiness, optionally applies SQL seed data, runs integration tests, and tears everything down in a shell `trap` unless keep mode is enabled.

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

## Optional Environment Variables

- `HUBUUM_INTEGRATION_SERVER_IMAGE` overrides the server image.
- `HUBUUM_INTEGRATION_DB_IMAGE` overrides the database image.
- `HUBUUM_INTEGRATION_CONTAINER_RUNTIME` forces `docker` or `podman`.
- `HUBUUM_INTEGRATION_STACK_TIMEOUT_SECS` overrides startup timeout. The default is `300`.
- `HUBUUM_INTEGRATION_KEEP_CONTAINERS=1` keeps containers running for debugging.
- `HUBUUM_INTEGRATION_SEED_SQL` overrides the default seed SQL file.

CI runs integration tests against `ghcr.io/hubuum/hubuum-server:main` with `--with-e2e-client`, so the consumer e2e suite is validated with the library integration tests.

If the server image is private in your environment, authenticate first:

```bash
docker login ghcr.io
```
