# Hubuum server v0.0.4 compatibility

The initial client preparation was based on
[Hubuum PR #172](https://github.com/hubuum/hubuum/pull/172) at commit
`705290559f3c8f255e551fe2e0662a92c44c8448`.
The authoritative `v0.0.4` server tag resolves to commit
`81ca7b575ce888415c97dd19c83bfddaca272b6e`.

CI run `30158997535` produced the `openapi-json` artifact
`8621308393`. Its `openapi.json` is byte-for-byte identical to the file
committed at the PR head and the released tag. The file has SHA-256
`4c1f6e06d39bafa76d17f3238724abdd60ff9b51eb6e35cf95e4b1d93c9957fb`.

The generated `docs/openapi.json` at that commit declares server v0.0.4. Its
normalized contract has 137 paths, 196 operations, and 244 schemas. Relative
to v0.0.3, paths and operation counts are unchanged; the relevant changes are:

- nested token `scope.permissions` and `scope.resources` request/response
  models, typed token/principal IDs, and hierarchical resource scopes;
- durable provenance on audit events, temporal history, and task events, plus
  initiator filters on event lists and subscriptions;
- repeated numeric `aggregate` measures and measure results on object
  aggregation;
- positive export-scope class/object IDs.

The contract adds ten schemas:

- `ObjectAggregateMeasureOperation`, `ObjectAggregateMeasureState`, and
  `ObjectAggregateMeasureValue`;
- `PrincipalID`, `TokenID`, `TokenResourceScope`, and `TokenScopeDetails`;
- `Provenance`, `ProvenanceActor`, and `ProvenancePrincipal`.

It also adds repeated `aggregate` query parameters to the two object-aggregate
routes and `initiator_user_id` to all nine event-list route variants.

The canonical specification hash produced by
`scripts/openapi-contract.py` is
`675d458cf7f140040571c05704780fff5b16a2e38d1ebd53c980f52a107657f2`.

## Client behavior

- `NewTokenRequest` emits only the singular nested `scope` wire shape. Omitting
  it (or sending `null` through a raw caller) means unscoped; a present scope
  must contain at least one non-empty permission or resource dimension.
- Token-list and current-token responses decode both the v0.0.3 flat metadata
  and v0.0.4 exact scope metadata during the transition.
- Async and blocking aggregate requests support ordered numeric measures and
  decode their value/skipped counts and states.
- Event, history, and task-event responses expose provenance, event lists
  support the root-task initiator filter, and subscription filters can narrow
  on initiators.
- Export requests validate kind-specific identifier requirements and positive
  IDs. Task idempotency keys enforce the 255-byte limit.
- Remote-target create/update requests reject the v0.0.4 transport-controlled
  header denylist in both templates and API-key authentication.
- `e2e_client/tests/v004.rs` covers scoped and unscoped token lifecycles,
  numeric aggregation, direct-actor provenance, task provenance, and initiator
  event filtering against the declared v0.0.4 target.

## Changelog-only compatibility effects

Some v0.0.4 changes do not alter the OpenAPI operation inventory but still
affect callers:

- history lists may omit versions the caller cannot read, and deleted-resource
  history requires an unscoped configured-backend administrator token;
- JSON filter and object-aggregate path segments must be non-empty and contain
  only ASCII letters, digits, `_`, or `$`;
- integer list/range filters expand to at most 1,024 unique values;
- unified search now decodes `+` and percent escapes with the shared form-query
  decoder.

## Release evidence

- The multi-platform v0.0.4 server image is pinned as
  `ghcr.io/hubuum/hubuum-server@sha256:60142d605f423b1dc58d9dfe709164b0d5ec93befd2d702f9bdca7ee0654a583`.
- `python3 scripts/openapi-contract.py check` succeeds against the
  authoritative tag specification.
- The canonical combined Docker-backed command passed against that exact
  digest: 89 library integration tests and 22 independent `e2e_client` tests.
- Token lifecycle coverage creates scoped and scope-omitted tokens, verifies
  their exact listed and current-token metadata, authenticates with both,
  permits an in-scope operation, rejects an operation outside the permission
  scope, confirms unscoped access, revokes both, and verifies both secrets are
  rejected afterward.

The root manifest, `TARGET_SERVER_VERSION`, required CI image, compatibility
table, pinned OpenAPI source and snapshot, README, and integration-test
documentation therefore declare Hubuum server v0.0.4 together.
