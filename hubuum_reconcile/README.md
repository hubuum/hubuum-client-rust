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
let preview = Reconciler::new(client).preview(&desired).await?;
if preview.failed() == 0 {
    Reconciler::new(client).apply(&desired).await?;
}
# Ok(())
# }
```

Async support is enabled by default. Use the `blocking` feature with default
features disabled for synchronous applications.
