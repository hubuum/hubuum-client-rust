# hubuum_reconcile

Declarative, task-backed reconciliation for Hubuum graphs.

The crate turns an `ImportGraph` into desired state, supports server-side dry-run
previews, applies changes through idempotent import tasks, waits for completion,
and returns the per-item results.

```rust,no_run
use hubuum_reconcile::{DesiredState, r#async::Reconciler};

# async fn run(
#     client: &hubuum_client::Client<hubuum_client::Authenticated>,
#     graph: hubuum_client::ImportGraph,
# ) -> Result<(), hubuum_client::ApiError> {
let desired = DesiredState::new(graph);
let reconciler = Reconciler::new(client).idempotency_key("inventory-2026-07-10");
let preview = reconciler.preview(&desired).await?;
if preview.failed() == 0 {
    reconciler.apply(&desired).await?;
}
# Ok(())
# }
```

Async support is enabled by default. Use the `blocking` feature with default
features disabled for synchronous applications.

The idempotency value is a namespace: preview and apply derive distinct phase
keys. Failed or cancelled terminal tasks return `ApiError::TaskUnsuccessful`
instead of an apparently successful result with no failed rows.
