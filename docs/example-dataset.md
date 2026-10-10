# Explore the Atlas example inventory

Use the same small inventory as the server documentation and the other Hubuum
interfaces. Atlas demonstrates **classes, objects, relations, and access** with
four classes and ten connected objects.

## Load the shared dataset

Use the [server v0.0.18 Atlas guide](https://hubuum.github.io/hubuum/v0.0.18/getting-started/example-dataset/)
to load the inventory into an evaluation server and grant your account access.
This matches this release's server target. The server guide owns the downloads,
model, permissions, and expected data. Import adds the dataset atomically;
**restoring its backup replaces all application data**.

Use the case-sensitive names `Service`, `Server`, `Location`, and `Context`.
Resolve numeric IDs from responses; they vary between installations.

## Read classes and objects

With an authenticated [blocking client](client-setup.md), inspect the Service
class and its Atlas object:

```rust
let service_class = client.class_by_name("Service").get()?;
let atlas = client
    .class_by_name("Service")
    .objects()
    .by_name("Atlas")
    .get()?;
let server = client
    .class_by_name("Server")
    .objects()
    .by_name("web-01")
    .get()?;
```

Atlas's data has owner `Platform`; web-01's hostname is
`web-01.example.invalid`. Read Context/Research notes to compare schema-free
content with those schema-bound records. The client encodes names, including
spaces, as opaque path segments. Async callers await the terminal request:

```rust
let atlas = client
    .class_by_name("Service")
    .objects()
    .by_name("Atlas")
    .get()
    .await?;
```

Use [querying and pagination](querying.md) to list Server objects. The starting
inventory contains three: web-01, web-02, and worker-01. Keep returned IDs typed
when using ID-addressed methods; importing does not preserve database IDs.

## Relations and access

Use a non-admin account in `atlas-readers` to read the full inventory, or one
in `atlas-operators` to maintain Server/Location objects in the operations child.
Other memberships and token scopes affect the result. See the canonical
[relationships](https://hubuum.github.io/hubuum/v0.0.18/getting-started/example-dataset/#relations-connect-the-instances)
and [permission checks](https://hubuum.github.io/hubuum/v0.0.18/getting-started/example-dataset/#explore-collection-permissions)
for expected results and cleanup.
