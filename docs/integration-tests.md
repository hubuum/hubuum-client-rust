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
data, exercises native query-usage preparation and cleanup between consumer phases,
enables query observations with one sample per request, and tears everything down in a shell `trap` unless keep mode is enabled.

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
An external stack must enable `HUBUUM_QUERY_OBSERVATIONS_ENABLED=true` and
`HUBUUM_QUERY_OBSERVATIONS_SAMPLE_EVERY=1` for query-usage evidence tests.
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
- `HUBUUM_INTEGRATION_LDAP_CONTAINER` identifies the disposable LDAP container
  when using an external stack. The wrapper supplies it automatically. Provider
  login tests rotate fixture passwords before use instead of relying on the
  image's public example credentials.
- `HUBUUM_INTEGRATION_EXPECT_CREDENTIAL_APPROVALS=1` makes credential approval
  scenarios assert that the selected server enforces fresh authentication.
  Required CI and local release verification must set it. Focused legacy-server
  runs may omit it to verify the original credential operations; full restore
  scenarios adapt to either policy. A focused run does not replace the complete
  pinned library plus consumer suite.
- `HUBUUM_INTEGRATION_AUTH_CONFIG` overrides the server auth-provider configuration file.
- `HUBUUM_INTEGRATION_CONTAINER_RUNTIME` forces `docker` or `podman`.
- `HUBUUM_INTEGRATION_STACK_TIMEOUT_SECS` overrides startup timeout. The default is `300`.
- `HUBUUM_INTEGRATION_KEEP_CONTAINERS=1` keeps containers running for debugging.
- `HUBUUM_INTEGRATION_SEED_SQL` overrides the default seed SQL file.

The canonical suite includes delegated collection webhook setup in both async
and blocking modes. These cases are mandatory for the v0.0.20 target and need
no separate opt-in variable.

Required CI runs integration tests against an immutable server image digest.
For client 0.18.0, that image is Hubuum server v0.0.20 at
`sha256:eaf59f8a4b4793030a78bc1637a8e2b9fad2f810b8621ff9a874dca534b9a23a`.
Required CI sets `HUBUUM_INTEGRATION_EXPECT_CREDENTIAL_APPROVALS=1`; set the
same variable for local release verification so missing enforcement fails.
A scheduled compatibility workflow separately runs against
`ghcr.io/hubuum/hubuum-server:main`, so upstream movement is visible without
making otherwise unrelated pull requests nondeterministic. The forward suite
requires credential approval enforcement. User fixtures obtain operation-bound
approval only after `reauthentication_required`; other failures propagate without
retry. The fixtures retain compatibility paths for optional runs against older
server releases.

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
Each scenario activates an enforced schema, creates and downloads a format 10 backup, deletes an object, stages
and confirms the restore, polls with its capability until completion, verifies bearer-token
invalidation, and checks that the deleted object and its revision were restored
after a new login. Recovery also creates and stages default backups before and
after another mutation. Recovery also checks the restored schema revision and
object validation evidence, with and without history.
Because supported backup formats exclude password hashes, the wrapper resets the disposable
administrator password after each restore before running the recovery assertion.

The separate `e2e_client` restore test target requires `restore-tests` and the
wrapper-owned `HUBUUM_INTEGRATION_DISPOSABLE_BASE_URL` marker. It is never part
of ordinary tests against an externally managed stack; full restore replaces
all data and invalidates tokens. The complete non-container workspace suite
compiles these tests but leaves them ignored.

## Computed-history cleanup

Computed-field definition mutations enqueue asynchronous rebuilds, including
definition deletion. The history scenarios wait for all reindex tasks belonging
to their unique class before removing the object and class. Superseded rebuilds
may finish cancelled; other failures still fail the test. This avoids the
v0.0.20 class-deletion/rebuild deadlock without retrying or ignoring HTTP 500s.

## Rotating-session contract

The canonical combined suite provisions a disposable server with
`HUBUUM_SESSION_ACCESS_SECONDS=30` and requires both async and blocking session
checks. Both runtimes cross a real access deadline, rotate, retain the original
absolute deadline, and verify logout invalidates clones. The short deadline is
required by these tests; it does not change production defaults.

For focused iteration against a caller-managed disposable server with the same
short access lifetime, supply its address and administrator password through the
existing integration environment variables and run:

```bash
cargo test --locked -p e2e_client --features session-tests --test sessions \
  -- --ignored --test-threads=1
```

This focused command does not replace the canonical combined suite, which also
covers ordinary authenticated workflows and full restore recovery.
