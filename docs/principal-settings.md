# Principal Settings

Principal settings are object-only JSON preferences stored separately for every
human user or service account. The authenticated principal can manage its own
document through `settings()`:

```rust
let current = client.settings().get().await?;

let replaced = client
    .settings()
    .replace(&serde_json::json!({
        "theme": "dark",
        "dashboard": { "columns": 3 }
    }))
    .await?;

let merged = client
    .settings()
    .patch(&serde_json::json!({
        "dashboard": { "columns": 4 },
        "theme": null
    }))
    .await?;

client.settings().reset().await?;
# Ok::<(), hubuum_client::ApiError>(())
```

`replace()` sends `PUT` and replaces the complete document. `patch()` uses JSON
Merge Patch object semantics: objects merge recursively, null removes a key, and
other values replace the existing value. `reset()` sends `DELETE` and restores
an empty object.

`PrincipalSettings` guarantees an object root while permitting any JSON value
below it. It supports map access and typed decoding:

```rust
#[derive(serde::Deserialize)]
struct Preferences {
    theme: Option<String>,
}

let settings = client.settings().get().await?;
let preferences: Preferences = settings.deserialize()?;
```

An unscoped human administrator can manage another principal through
`client.principal_settings(principal_id)`. User and service-account handles also
provide `handle.settings()`. The server deliberately returns `404` when a caller
is not permitted to discover or manage the target principal.

Settings values are redacted from client debug output. They are preferences, not
a credential store: server audit events include complete before and after
settings snapshots for each mutation.

The blocking client provides the same methods without `.await`.
