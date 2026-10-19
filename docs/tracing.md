# Client tracing

The client emits structured `tracing` diagnostics for blocking and async requests,
including custom transports. The application installs its own subscriber and
chooses where to store or display diagnostics. The library does not install a
subscriber or change the application's logging configuration.

This support is additive to the existing `log` messages. It adds a direct
`tracing` 0.1 dependency, with no changes to feature flags, MSRV, server target,
HTTP behavior, retry policy, or public method signatures.

## Diagnostics contract, version 1

The stable target is `hubuum_client::diagnostics`. Every diagnostic below carries
`diagnostics.version = 1`. Consumers should select this target and version before
interpreting fields; other tracing emitted by dependencies is outside this
contract. Span names and fields may be extended without changing existing meaning.

| Span | Meaning | Additional fields |
| --- | --- | --- |
| `hubuum.request` | One endpoint-aware or raw request, including retries and buffered body processing | `operation`, `http.request.method`, `http.route` |
| `hubuum.http_attempt` | One invocation of the HTTP client or custom transport | `http.request.method`, `attempt`, `transport`, `http.response.status_code` |
| `hubuum.retry` | Backoff before the next attempt | `attempt`, `delay_ms` |
| `hubuum.stream` | Consumption of a streaming response body | None |

Every span records `outcome` (`ok`, `error`, or `cancelled`) and `duration_ms`.
The duration is elapsed wall time, including asynchronous waits. It is recorded
when the operation finishes or is dropped, so consumers should prefer it over
span-close timing: a stream or another child may keep a parent span alive longer
than its own operation. An unfinished span has no duration and initially carries
`cancelled`; do not interpret that outcome as final until its duration is recorded.

`attempt` starts at 1. `transport` is `reqwest` or `custom`. For `reqwest`, attempt
timing ends at response headers; the enclosing request includes buffered body
reading, size checks, and response processing. For `custom`, the transport returns
a buffered response, so attempt timing includes that work. Custom transport calls
are not necessarily individual network requests. Automatic redirects inside a
user-supplied HTTP client also remain internal to that client's send operation.
The status field is absent when no HTTP response was obtained. Non-success HTTP
statuses produce `error` even when the retry policy subsequently recovers.

`http.route` contains a constant endpoint template, never a populated URL. Raw
requests and configurable metrics paths use static placeholders. The library
records no credentials, headers, query or cursor values, request bodies, response
bodies, resource names, or error messages in these diagnostics.

The `hubuum.page` event records `page` (starting at 1) and `items` after a page is
received during automatic pagination. Events carry the same target and version.
No event is emitted just for exhausting an iterator.

## Span ancestry and command reports

Request spans inherit the caller's active span. Attempts and retry waits are
children of the request. A high-level operation may issue several requests, such
as when resolving a name or fetching more pages. Request counts, transport-attempt
counts, and public API-call counts therefore describe different work.

Streaming spans are created when the body becomes available and follow that body
until EOF, a read error, or drop. An empty read buffer is not EOF. Stream decoding
or application processing after reading bytes is outside the body span.

For async operations, instrument the calling future with `tracing::Instrument`;
propagate its span explicitly into blocking workers. Do not hold a span-enter
guard across an await. A CLI can create a new root span per command and collect
only its descendants, keeping startup, completion, and background activity out
of that command's report. Child timings overlap with parents and should not be
summed to calculate command time.
