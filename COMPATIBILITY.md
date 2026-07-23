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

Required CI is deterministic and stays pinned to the declared target. Scheduled
jobs separately compare the contract and run the integration suites against the
server's `main` branch. Those scheduled checks are early-warning signals; they
do not change a published client's declared target.
