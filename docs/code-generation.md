# Resource Code Generation

The public resource models, request types, typed query fields, fluent mutation
methods, and checked-create builders are generated before publication and
committed to the repository. Downstream builds compile ordinary Rust source and
do not run a procedural macro or a build script.

## Sources And Outputs

- `hubuum_reconcile/specs/*.rs` is the source of truth for generated resource
  fields and their `#[api(...)]` behavior.
- `hubuum_reconcile/src/main.rs` owns command-line and filesystem
  reconciliation behavior.
- `hubuum_reconcile/src/generate.rs` contains the specification model,
  validation, and rendering rules.
- `openapi/operations.json` is the normalized operation and structural schema
  inventory generated from the pinned server specification.
- `openapi/model-contract.json` maps relevant OpenAPI schemas to generated and
  handwritten Rust wire structs. The reconciler parses the actual Rust source
  and verifies field names, Serde behavior, requiredness, and documented
  exceptions.
- `src/resources/generated/*.rs` is generated, reviewed, and committed.
- The handwritten files under `src/resources` include the generated output and
  continue to own resource-specific behavior.

The specifications intentionally use Rust field syntax so types remain easy to
review. They are generator inputs, not compiled modules. The generated files
preserve the public types and builder methods exposed by `hubuum_client`.

### Field Options

Fields use `#[api(...)]` options to describe how one server field maps onto the
resource and request types:

- `read_only` excludes the field from create and patch requests.
- `post_only` includes the field only in create requests.
- `optional` represents the resource value and create input as `Option<T>`.
- `post_optional` makes only the create input optional and omits it from the
  serialized request when unset.
- `as_id` keeps the resource type in responses while using its typed ID in
  request and query fields, whose generated name gains an `_id` suffix.
- `skip_patch` and `skip_query` omit the corresponding generated field and
  fluent methods.
- `default` adds Serde's standard default for a response field.
- `default_local` uses `default_local_identity_value` as that Serde default.

Every create field that is neither read-only nor optional becomes a required
state in the checked-create builder. The generator rejects unknown, duplicate,
malformed, or incompatible options instead of silently producing a partial API.

## Updating Resources

Edit the relevant specification, then run:

```bash
cargo run -p hubuum_reconcile --locked -- update
cargo run -p hubuum_reconcile --locked -- check
```

Review both the specification and generated diff. Changes to generated public
types or methods require the same compile-time, behavior, semver, and live
compatibility review as handwritten API changes. Update mode leaves already
current files untouched, avoiding unnecessary rebuilds and timestamp churn.

CI and the release preflight run `check`, which fails when committed output is
missing or stale. Generation uses the repository's `rustfmt`; it performs no
network access and is not part of `hubuum_client`'s crates.io package.

When the pinned server target changes, update `openapi/operations.json`, update
the affected Rust models and `openapi/model-contract.json`, and document every
intentional omission or projection difference in `openapi/known-gaps.md`. Run
`cargo run -p hubuum_reconcile --locked -- check` to verify both generated
resource files and property-level model reconciliation. Matching endpoint paths
alone is not sufficient evidence that the wire models still match the server.
