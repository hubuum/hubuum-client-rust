# hubuum_reconcile

Repository-local generator for the checked-in Hubuum resource types and
builders. This crate is a workspace tool with `publish = false`; applications
using `hubuum_client` do not build or depend on it.

Run it from the repository root:

```bash
cargo run -p hubuum_reconcile --locked -- update
cargo run -p hubuum_reconcile --locked -- check
```

See [`../docs/code-generation.md`](../docs/code-generation.md) for the source and
review workflow.
