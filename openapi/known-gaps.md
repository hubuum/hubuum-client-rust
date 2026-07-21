# Known Hubuum server v0.0.3 OpenAPI gaps

The pinned client contract records these limitations in the server v0.0.3
specification explicitly:

- `GET /api/v1/search/stream` describes SSE in prose but does not declare a
  `text/event-stream` response content type or event schema.
- Import and export submission support `Idempotency-Key` in the server and client,
  but the header is not represented as an operation parameter.

The scheduled drift job remains strict about changes on the server's `main`
branch. These gaps can be removed when a targeted server specification corrects
them.
