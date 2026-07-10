# Declarative Reconciliation

`hubuum_reconcile` is a separate workspace crate for treating a Hubuum import
graph as desired state. It uses the server's dry-run and task APIs rather than
maintaining a second diff engine in the client.

```toml
[dependencies]
hubuum_client = "0.3.0"
hubuum_reconcile = "0.1.0"
```

```rust
use hubuum_reconcile::{DesiredState, r#async::Reconciler};

let desired = DesiredState::new(graph);
let reconciler = Reconciler::new(&client).idempotency_key("inventory-2026-07-10");
let preview = reconciler.preview(&desired).await?;

if preview.failed() == 0 {
    let applied = reconciler.apply(&desired).await?;
    println!("{} changes applied", applied.succeeded());
}
```

`idempotency_key()` configures a namespace rather than one literal request key.
Preview uses `<key>:preview` and apply uses `<key>:apply`, preventing a dry-run
response from being replayed for a mutating import. Failed and cancelled tasks
return `ApiError::TaskUnsuccessful`; only successful or partially successful
tasks produce a `ReconcileResult`.

The blocking API is available as `hubuum_reconcile::blocking::Reconciler` when
the crate is built with `default-features = false, features = ["blocking"]`.
