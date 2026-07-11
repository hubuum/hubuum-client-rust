# Known server OpenAPI gaps

The client contract snapshot records these server-spec limitations explicitly:

- `info.version` is still `0.0.1` and does not identify the deployed API revision.
- `GET /api/v1/search/stream` describes SSE in prose but does not declare a
  `text/event-stream` response content type or event schema.
- Import and export submission support `Idempotency-Key` in the server and client,
  but the header is not represented as an operation parameter.

The scheduled drift job should remain strict about operation changes. These gaps
can be removed from this document when the server specification is corrected.
