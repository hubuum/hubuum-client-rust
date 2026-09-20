# Server compatibility

The client and server are versioned independently. A client release "targets"
a server release when its pinned OpenAPI contract comes from that server tag and
the complete Docker-backed library and consumer integration suites pass against
an immutable image for the same release.

Dedicated typed helpers do not necessarily exist for every server operation.
Authenticated relative routes remain available through `raw()` while typed
coverage evolves.

## Compatibility history

| Client version | Server target | Tested server image | Evidence |
| --- | --- | --- | --- |
| 0.11.0 | 0.0.15 | `ghcr.io/hubuum/hubuum-server@sha256:36af667dbc9e221a40448496d4a87e168c999d0834df4b69177345ff3d36e821` | Declared target; 218-operation pinned contract, 67 wire-model mappings, schema evolution, cancellation, format 6 backups, and refreshed Rust 1.88-compatible dependencies. 91 library and 26 consumer integration tests, plus four async/blocking full restores with and without history and schema-evidence-preserving recovery (2026-09-16). |
| 0.10.1 | 0.0.14 | `ghcr.io/hubuum/hubuum-server@sha256:6c1c8d7316a1f60a02e4505611a44e21030ba678b5b451f5b293a12f2bd87594` | Declared target; unchanged 204-operation OpenAPI contract, refreshed Rust 1.88-compatible dependencies, 89 library and 24 consumer integration tests, plus four async/blocking full restores with and without history and revision-preserving recovery with subsequent backup validation (2026-09-10) |
| 0.10.0 | 0.0.13 | `ghcr.io/hubuum/hubuum-server@sha256:512562e789d6430875c5075faf832a9669a4f266f7fe9fbf8c1524b49a6476c5` | Declared target; pinned OpenAPI, refreshed Rust 1.88-compatible dependencies, 89 library and 24 consumer integration tests, plus blocking and async full restore completion, token invalidation, and recovery after each restore (2026-09-09) |
| 0.9.1 | 0.0.9 | `ghcr.io/hubuum/hubuum-server@sha256:1f12baf882b6d3df5b4b2dbdf26aad0793274e57f86a2c186b8e1e68632db5db` | Declared target; JSON-path validation, advertised pagination limits, atomic export downloads, property-level OpenAPI model reconciliation, dependency and release-workflow security updates, with pinned Docker-backed library plus downstream-consumer integration coverage |
| 0.9.0 | 0.0.9 | `ghcr.io/hubuum/hubuum-server@sha256:1f12baf882b6d3df5b4b2dbdf26aad0793274e57f86a2c186b8e1e68632db5db` | Declared target; revision and ETag concurrency, import v2, settings JSON Patch, revision-owned permission and membership responses, computed-field points, token lifecycle state and renewal, with pinned Docker-backed library plus downstream-consumer integration coverage |
| 0.8.0 | 0.0.8 | `ghcr.io/hubuum/hubuum-server@sha256:850bfd95a2802485f93c1700fbff5a33465cbc7855cbc94962982c1074fd96f6` | Declared target; property-complete v0.0.8 cardinality, core-import timestamp, and export-timing models with pinned Docker-backed library plus downstream-consumer integration coverage |
| 0.7.3 | 0.0.8 | `ghcr.io/hubuum/hubuum-server@sha256:850bfd95a2802485f93c1700fbff5a33465cbc7855cbc94962982c1074fd96f6` | Declared target; pinned OpenAPI and complete Docker-backed library plus downstream-consumer integration suites |
| 0.7.2 | 0.0.5 | `ghcr.io/hubuum/hubuum-server@sha256:6f3e0f0debd418acd5cbc2b1399db9859a85ca1fa397525a5ef0e2f493a77c9b` | Declared target; pinned OpenAPI and full integration suites, including public default-token-lifetime discovery, authoritative login and token-mint expiry metadata, token retention configuration, scoped/unscoped token lifecycles, expiry enforcement, revocation, imports, exports, and downstream-consumer coverage |
| 0.7.1 | 0.0.4 | `ghcr.io/hubuum/hubuum-server@sha256:60142d605f423b1dc58d9dfe709164b0d5ec93befd2d702f9bdca7ee0654a583` | Declared target; pinned OpenAPI and full integration suites, including sensitive secret-header metadata plus blocking user and async service-account scoped/unscoped token lifecycles, expiry enforcement, revocation, and post-revocation rejection |
| 0.7.0 | 0.0.4 | `ghcr.io/hubuum/hubuum-server@sha256:60142d605f423b1dc58d9dfe709164b0d5ec93befd2d702f9bdca7ee0654a583` | Declared target; pinned OpenAPI and full integration suites, including blocking user and async service-account scoped/unscoped token lifecycles, expiry enforcement, revocation, and post-revocation rejection |
| 0.6.1 | 0.0.3 | `ghcr.io/hubuum/hubuum-server@sha256:f1f57a991f69005ee81f24e77533e61f75b5586949d98cccf1c40fc4329eb186` | Declared target; pinned OpenAPI and full integration suites, including async and blocking diagnostic redaction, custom-transport isolation, and redirect-confinement regressions |
| 0.6.0 | 0.0.3 | `ghcr.io/hubuum/hubuum-server@sha256:f1f57a991f69005ee81f24e77533e61f75b5586949d98cccf1c40fc4329eb186` | Declared target; pinned OpenAPI and full integration suites, including exact-name routing, aggregates, object-data patching, and public pagination configuration |
| 0.5.1 | 0.0.2 | `ghcr.io/hubuum/hubuum-server@sha256:8f543383b422124546c8d337fd557e1b182b1b6c7078d7870d3c5cd4f955ef1f` | Declared target; pinned OpenAPI and full integration suites, including the runtime-configurable metrics route |
| 0.5.0 | 0.0.2 | `ghcr.io/hubuum/hubuum-server@sha256:8f543383b422124546c8d337fd557e1b182b1b6c7078d7870d3c5cd4f955ef1f` | Declared target; pinned OpenAPI and full integration suites |
| 0.4.0 | `main@eed194f2339ce221ef251a14062e2a37850186b1` | `ghcr.io/hubuum/hubuum-server@sha256:9eb7d2eb83220ac6e38d9964df2e6f4268152a072b0cece3e81a63b52d7b8e19` | Reproducible pre-release snapshot, not a stable server release |
| 0.3.0 | `main@eed194f2339ce221ef251a14062e2a37850186b1` | `ghcr.io/hubuum/hubuum-server@sha256:9eb7d2eb83220ac6e38d9964df2e6f4268152a072b0cece3e81a63b52d7b8e19` | Reproducible pre-release snapshot, not a stable server release |
| 0.2.0 | `main` (floating) | Not recorded | No stable server target was declared |
| 0.1.0 | Not recorded | Not recorded | No stable server target was declared |
| 0.0.3 | `main` (floating) | Not recorded | No stable server target was declared |
| 0.0.2 | `no-tls-main` (floating) | Not recorded | No stable server target was declared |
| 0.0.1 | Not recorded | Not recorded | No stable server target was declared |

The client version 0.0.2 row predates and is unrelated to the independently
versioned Hubuum server v0.0.2 release.

## Forward compatibility

The optional fresh credential approval API supports servers incorporating
[PR 423](https://github.com/hubuum/hubuum/pull/423). This addition does not change
the declared v0.0.15 target, pinned image, or OpenAPI snapshot. Existing calls do
not require the approval endpoints. On an enforcing server, credential mutations
return `reauthentication_required` until the caller uses the explicit
[approval workflow](docs/credential-approvals.md).

Focused live verification on 2026-09-19 used the PR's merged source revision
`3a1c44c938cc9d06d665229612c0fb1b4f3c98c8` and immutable Linux amd64 image
`ghcr.io/hubuum/hubuum-server@sha256:62438f2473ee15f9699ccc904e79c4c20c27e06a1219986c04493d269127f3e0`.
With `HUBUUM_INTEGRATION_EXPECT_CREDENTIAL_APPROVALS=1`, async and blocking token
creation/renewal preserved approved expirations, and downstream user/password and
credential-import dry runs passed. Blocking and async full restore confirmation
and recovery passed with and without history. These focused checks supplement
the required complete pinned-server run; they do not declare compatibility with
all other changes on server `main`.

The canonical complete pinned-server command also passed on 2026-09-19 against
the v0.0.15 image declared in `Cargo.toml`, including library and downstream
consumer tests and all four restore/recovery scenarios. The new credential
scenarios passed through the original APIs without requiring approval support.

Required CI is deterministic and stays pinned to the declared target. Scheduled
jobs separately compare the contract and run the integration suites against the
server's `main` branch. Those scheduled checks are early-warning signals; they
do not change a published client's declared target.

## v0.0.13 target

The 0.10.0 release targets server v0.0.13, which fixes the restore drain-state
race and JSON-null insertion failure found during v0.0.12 verification. Its
204-operation OpenAPI contract is unchanged from v0.0.12 apart from the server
version. Backup format 5 is unchanged.

Install matching server, administrator, and template-worker binaries, including
any separately deployed `hubuum-admin --restore-executor`. See the
[server release notes](https://github.com/hubuum/hubuum/releases/tag/v0.0.13)
and the [backup and restore guide](docs/backups-and-computed-fields.md) for
migration and recovery steps.

The canonical combined integration command passed on 2026-09-09 against the
released immutable image above (Linux amd64). All 89 library and 24 ordinary
consumer tests passed, followed by blocking and async full restore completion
and recovery after each restore. Both modes reached `Succeeded`, rejected the
pre-restore bearer token, and recovered the deleted object after administrator
password reset and a fresh login.

The published image identifies source revision
`8ecefbf3e3147714014221598d9873ba92e0fdce`, matching the v0.0.13 release tag.
The manifest pins the multi-platform image index; this live run verifies its
Linux amd64 image.

## v0.0.14 target

The 0.10.1 patch release targets server v0.0.14. Its 204-operation OpenAPI
contract is unchanged from v0.0.13 apart from the server version. Public client
APIs, features, the Rust 1.88 MSRV, and backup format 5 are unchanged.

The server fixes backup and restore consistency, including preserving revisions
and establishing current temporal snapshots after history-free restores so later
backups remain restorable. Install matching server, administrator, and
template-worker binaries, including any separately deployed
`hubuum-admin --restore-executor`. Existing history-free format 5 artifacts can
be restored directly with the fixed executor. No database migration is added;
the server's certified upgrade and application rollback path is v0.0.13 to
v0.0.14. See the
[server release notes](https://github.com/hubuum/hubuum/releases/tag/v0.0.14)
and the [backup and restore guide](docs/backups-and-computed-fields.md).

The canonical combined integration command passed on 2026-09-10 against the
released immutable image above (Linux amd64). All 89 library and 24 ordinary
consumer tests passed, followed by all four combinations of blocking/async full
restore and history included/omitted. Every restore reached `Succeeded`, rejected
the pre-restore bearer token, and recovered the deleted object with its original
revision after administrator password reset and a fresh login. Recovery also
created and successfully staged default backups both before and after another
mutation, covering the history-free restore fix.

The published image identifies source revision
`0b0aa17f278496a32cc018cfcac56f34a408ccd6`, matching the v0.0.14 release tag.
The manifest pins the multi-platform image index; this live run verifies its
Linux amd64 image.

## v0.0.15 target

The 0.11.0 release targets server v0.0.15. The contract grows from
204 to 218 operations and from 280 to 315 schemas. All 14 new operations have
typed async and blocking helpers, covering the class schema lifecycle, retained
HTML repair reports, and task cancellation. Feature availability and Rust 1.88
remain unchanged.

`ImportClassInput` gains `schema_activation`; add `schema_activation: None` to
existing struct literals or provide an explicit activation request. Changing
schema policy on a nonempty class now requires staging, impact analysis, and
activation instead of direct PATCH or legacy import overwrite. Imports must
provide the exact staged policy. See the [schema guide](docs/schema-evolution.md).

Backup format 6 replaces format 5, adding schema revisions, state, evidence,
and history. Restore older artifacts using their matching older server before
migrating and creating new format 6 backups; no artifact converter is provided.
Drain old workers, apply the release's migrations, then deploy matching API,
worker, administrator, and restore-executor binaries. Existing enforced objects
start pending and need revalidation. See the
[backup guide](docs/backups-and-computed-fields.md) and
[server release notes](https://github.com/hubuum/hubuum/releases/tag/v0.0.15).

The server also tightens schema validation and resource budgets, changes string
cursor ordering to byte ordering on locale-collated databases, and requires the
`CancelTask` external authorization action. Restart in-progress string-sorted
pagination, review stored schema admission, and deploy consistent schema, task,
and backup limits across processes. Report assembly can return HTTP 413, and
external-authorization traversal is bounded at 10,000 candidates.

All direct dependencies already use constraints that select the latest
compatible releases. The lockfile refresh updates twelve packages, including
Rustls 0.23.45 for RUSTSEC-2026-0285. `generic-array` remains at 0.14.7 because
the current `crypto-common` 0.1.7 dependency requires that exact version.

The pinned multi-platform image identifies source revision
`4bb889c66a5e2a1dfc86d1b6beac7495912fd02e`, matching the annotated v0.0.15 tag.

The canonical combined integration command passed on 2026-09-16 against this
image's Linux amd64 build. All 91 library and 26 ordinary consumer tests passed,
including both modes of the schema lifecycle, diagnostic HTML, import activation,
and task cancellation. All four combinations of blocking/async full restore and
history included/omitted reached `Succeeded` and invalidated the old bearer token.
Recovery after each restore preserved the object's resource revision, the active
schema revision, and validation evidence. Subsequent backups before and after a
mutation also passed restore staging validation.
