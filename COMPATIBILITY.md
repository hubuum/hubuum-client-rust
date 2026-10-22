# Server compatibility

The client and server are versioned independently. A client release "targets"
a server release when its pinned OpenAPI contract comes from that server tag and
the complete Docker-backed library and consumer integration suites pass against
an immutable image for the same release.

Dedicated typed helpers do not necessarily exist for every server operation.
Authenticated relative routes remain available through `raw()` while typed
coverage evolves.

## Compatibility history

| Client version | Server target | Tested server image | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| --- | --- | --- | --- |
| 0.16.0 | 0.0.20 | `ghcr.io/hubuum/hubuum-server@sha256:eaf59f8a4b4793030a78bc1637a8e2b9fad2f810b8621ff9a874dca534b9a23a` | [Pinned session, library/consumer, native-resource, and restore/recovery verification](docs/compatibility-evidence.md#v0020-target) on 2026-10-22. |
| 0.15.1 | 0.0.19 | `ghcr.io/hubuum/hubuum-server@sha256:6fbe91693356b8885e6b1115cea4417dbf80747ba4af3eb0a15b855ffff47225` | Tracing release reverified on 2026-10-19: 99 library tests, 38 ordinary consumer cases, three native-resource phases, and four full restore/recovery pairs; unchanged 240-operation contract and 111 model mappings. |
| 0.15.0 | 0.0.19 | `ghcr.io/hubuum/hubuum-server@sha256:6fbe91693356b8885e6b1115cea4417dbf80747ba4af3eb0a15b855ffff47225` | Pinned combined suite reverified after the complete release dependency refresh (2026-10-19): 99 library tests, consumer workflows, native preparation/cleanup, and four restore/recovery pairs; see [0.0.19 evidence](docs/compatibility-evidence.md#v0019-target). |
| 0.14.1 | 0.0.18 | `ghcr.io/hubuum/hubuum-server@sha256:5b54248f19171200dfa497174d385a48f90666a415cb31732797043d5e182fc4` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.14.0 | 0.0.17 | `ghcr.io/hubuum/hubuum-server@sha256:cc0518167816bfddb38853b8b7217c4a347511318d51e1abca93ca418f31b302` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.13.0 | 0.0.17 | `ghcr.io/hubuum/hubuum-server@sha256:cc0518167816bfddb38853b8b7217c4a347511318d51e1abca93ca418f31b302` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.12.0 | 0.0.16 | `ghcr.io/hubuum/hubuum-server@sha256:37b3299edd845a0c2aa7772d7d68565233ac8c1802bc44be3fb4bbc6dfa8778e` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.11.2 | 0.0.16 | `ghcr.io/hubuum/hubuum-server@sha256:37b3299edd845a0c2aa7772d7d68565233ac8c1802bc44be3fb4bbc6dfa8778e` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.11.1 | 0.0.15 | `ghcr.io/hubuum/hubuum-server@sha256:36af667dbc9e221a40448496d4a87e168c999d0834df4b69177345ff3d36e821` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.11.0 | 0.0.15 | `ghcr.io/hubuum/hubuum-server@sha256:36af667dbc9e221a40448496d4a87e168c999d0834df4b69177345ff3d36e821` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.10.1 | 0.0.14 | `ghcr.io/hubuum/hubuum-server@sha256:6c1c8d7316a1f60a02e4505611a44e21030ba678b5b451f5b293a12f2bd87594` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.10.0 | 0.0.13 | `ghcr.io/hubuum/hubuum-server@sha256:512562e789d6430875c5075faf832a9669a4f266f7fe9fbf8c1524b49a6476c5` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.9.1 | 0.0.9 | `ghcr.io/hubuum/hubuum-server@sha256:1f12baf882b6d3df5b4b2dbdf26aad0793274e57f86a2c186b8e1e68632db5db` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.9.0 | 0.0.9 | `ghcr.io/hubuum/hubuum-server@sha256:1f12baf882b6d3df5b4b2dbdf26aad0793274e57f86a2c186b8e1e68632db5db` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.8.0 | 0.0.8 | `ghcr.io/hubuum/hubuum-server@sha256:850bfd95a2802485f93c1700fbff5a33465cbc7855cbc94962982c1074fd96f6` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.7.3 | 0.0.8 | `ghcr.io/hubuum/hubuum-server@sha256:850bfd95a2802485f93c1700fbff5a33465cbc7855cbc94962982c1074fd96f6` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.7.2 | 0.0.5 | `ghcr.io/hubuum/hubuum-server@sha256:6f3e0f0debd418acd5cbc2b1399db9859a85ca1fa397525a5ef0e2f493a77c9b` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.7.1 | 0.0.4 | `ghcr.io/hubuum/hubuum-server@sha256:60142d605f423b1dc58d9dfe709164b0d5ec93befd2d702f9bdca7ee0654a583` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.7.0 | 0.0.4 | `ghcr.io/hubuum/hubuum-server@sha256:60142d605f423b1dc58d9dfe709164b0d5ec93befd2d702f9bdca7ee0654a583` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.6.1 | 0.0.3 | `ghcr.io/hubuum/hubuum-server@sha256:f1f57a991f69005ee81f24e77533e61f75b5586949d98cccf1c40fc4329eb186` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.6.0 | 0.0.3 | `ghcr.io/hubuum/hubuum-server@sha256:f1f57a991f69005ee81f24e77533e61f75b5586949d98cccf1c40fc4329eb186` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.5.1 | 0.0.2 | `ghcr.io/hubuum/hubuum-server@sha256:8f543383b422124546c8d337fd557e1b182b1b6c7078d7870d3c5cd4f955ef1f` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.5.0 | 0.0.2 | `ghcr.io/hubuum/hubuum-server@sha256:8f543383b422124546c8d337fd557e1b182b1b6c7078d7870d3c5cd4f955ef1f` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.4.0 | `main@eed194f2339ce221ef251a14062e2a37850186b1` | `ghcr.io/hubuum/hubuum-server@sha256:9eb7d2eb83220ac6e38d9964df2e6f4268152a072b0cece3e81a63b52d7b8e19` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.3.0 | `main@eed194f2339ce221ef251a14062e2a37850186b1` | `ghcr.io/hubuum/hubuum-server@sha256:9eb7d2eb83220ac6e38d9964df2e6f4268152a072b0cece3e81a63b52d7b8e19` | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.2.0 | `main` (floating) | Not recorded | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.1.0 | Not recorded | Not recorded | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.0.3 | `main` (floating) | Not recorded | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.0.2 | `no-tls-main` (floating) | Not recorded | [Evidence](docs/compatibility-evidence.md#compatibility-history) |
| 0.0.1 | Not recorded | Not recorded | [Evidence](docs/compatibility-evidence.md#compatibility-history) |

The client version 0.0.2 row predates and is unrelated to the independently
versioned Hubuum server v0.0.2 release.

## Before upgrading

Client 0.16.0 targets server v0.0.20. Use fresh credential approvals for protected
mutations, and review [known typed API gaps](openapi/known-gaps.md). The client
accepts backup formats 6, 7, 8, 9, and 10; the server decides whether it can restore one.
For older Rust releases, check the linked migration notes before upgrading:
added fields can break exhaustive struct literals and patterns.

Server v0.0.18 requires an offline upgrade from v0.0.17 and emits backup format 8;
older servers cannot restore that format. Follow the canonical
[server upgrade and recovery instructions](https://hubuum.github.io/hubuum/v0.0.18/events/#upgrade-and-rollback)
and [backup compatibility](https://hubuum.github.io/hubuum/v0.0.18/backup-restore/).
Use the server guide for the actual version transition rather than copying
migration commands from an older client release.

## Verification evidence

[Detailed evidence and historical migrations](docs/compatibility-evidence.md) retain tested
image identities, dates, suite results, and earlier compatibility limits.

## Forward compatibility

See [forward compatibility](docs/compatibility-evidence.md#forward-compatibility) in the historical evidence.

## v0.0.20 target

See [v0.0.20 evidence](docs/compatibility-evidence.md#v0020-target) for source
provenance, session migration, typed API limits, and pinned integration results.

## v0.0.19 target

See [v0.0.19 target](docs/compatibility-evidence.md#v0019-target) for typed coverage,
backup compatibility, migration guidance, and pinned integration evidence.

## v0.0.18 target

See [v0.0.18 target](docs/compatibility-evidence.md#v0018-target) in the historical evidence.

## v0.0.17 target

See [v0.0.17 target](docs/compatibility-evidence.md#v0017-target) in the historical evidence.

## v0.0.16 target

See [v0.0.16 target](docs/compatibility-evidence.md#v0016-target) in the historical evidence.

## v0.0.13 target

See [v0.0.13 target](docs/compatibility-evidence.md#v0013-target) in the historical evidence.

## v0.0.14 target

See [v0.0.14 target](docs/compatibility-evidence.md#v0014-target) in the historical evidence.

## v0.0.15 target

See [v0.0.15 target](docs/compatibility-evidence.md#v0015-target) in the historical evidence.

## Collection integration APIs

See [collection integration apis](docs/compatibility-evidence.md#collection-integration-apis) in the historical evidence.

## v0.0.20 authentication migration

Use `login_session(credentials, client_id)` and `session_providers()` on the
supported server. Legacy `login()` is retained only for older servers; there is
no automatic authentication downgrade. Handle `client.token()?` as a short-lived,
owned snapshot. After refresh failure, sign in again instead of retrying an old
refresh credential. PAT injection remains supported and independent of sessions.

Upgrade the server and restore executor together using the
[offline upgrade guide](https://hubuum.github.io/hubuum/v0.0.20/deployment/).
Retain a pre-upgrade backup and matching binaries for rollback. See the
[typed API gaps](openapi/known-gaps.md#v0020-coverage) before relying on newly
introduced server fields or operations.
