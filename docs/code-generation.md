# Resource Code Generation

The public resource models, request types, typed query fields, fluent mutation
methods, and checked-create builders are generated before publication and
committed to the repository. Downstream builds compile ordinary Rust source and
do not run a procedural macro or a build script.

## Sources And Outputs

- `hubuum_reconcile/specs/*.rs` is the source of truth for generated resource
  fields and their `#[api(...)]` behavior.
- `hubuum_reconcile/src/main.rs` contains the generation rules.
- `src/resources/generated/*.rs` is generated, reviewed, and committed.
- The handwritten files under `src/resources` include the generated output and
  continue to own resource-specific behavior.

The specifications intentionally use Rust field syntax so types remain easy to
review. They are generator inputs, not compiled modules. The generated files
preserve the public types and builder methods exposed by `hubuum_client`.

## Updating Resources

Edit the relevant specification, then run:

```bash
cargo run -p hubuum_reconcile --locked -- update
cargo run -p hubuum_reconcile --locked -- check
```

Review both the specification and generated diff. Changes to generated public
types or methods require the same compile-time, behavior, semver, and live
compatibility review as handwritten API changes.

CI and the release preflight run `check`, which fails when committed output is
missing or stale. Generation uses the repository's `rustfmt`; it performs no
network access and is not part of `hubuum_client`'s crates.io package.

OpenAPI operation reconciliation remains a separate contract check in
`scripts/openapi-contract.py`. The normalized OpenAPI snapshot does not contain
enough property-level detail to generate these resource models directly.
