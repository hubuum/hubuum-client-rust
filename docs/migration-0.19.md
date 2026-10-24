# Migrating to 0.19

Version 0.19 is an API cleanup targeting the same Hubuum server
v0.0.20 and pinned image as 0.18. It does not require a server data migration.

## Validated resource IDs

All integer resource IDs are strictly positive. Their fields remain private;
`new`, `TryFrom`, string parsing, and deserialization enforce the same invariant.

```rust
use hubuum_client::{ApiError, ClassId};

fn class_id_from_input(value: i32) -> Result<ClassId, ApiError> {
    ClassId::new(value)
}
```

Replace `ClassId::new(value)` with `ClassId::new(value)?`, and replace
`value.into()` or `ClassId::from(value)` with `ClassId::try_from(value)?`.
A validated ID can still be copied, borrowed, displayed, or read using `get()`.
Conversions from `UserId` and `ServiceAccountId` to `PrincipalId` remain infallible.

Resource APIs accept their matching ID type. Generated primary-ID query fields
and `Get` request models now use that ID too; for example, use
`client.classes().id().eq(class_id)`. Relation searches' `ignore_classes` accepts
an iterator of `ClassId` values. Bare integers and another resource's IDs are
rejected at compile time.

## Creation and low-level requests

ID-bearing response types and request bodies requiring IDs no longer implement
`Default`. Use `create_checked()` for generated resource creation, or provide
all fields of a raw request body. Optional fields can be `None`.
The deprecated unchecked creation builder now reports a missing required field
locally; it no longer supplies a zero ID from a default response model.

Low-level `request`, `get`, `post`, `patch`, and `delete` methods select the
resource with a type parameter. Remove the dummy resource argument and specify
the resource type; for example, replace
`client.get(Object::default(), url_params, filters)` with
`client.get::<Object, _>(url_params, filters)`. The higher-level resource handles
remain the preferred interface.

## Computed revisions and historical relations

`ClassComputationState::evaluation_revision` and `SharedComputedScope::revision`
are `ComputationRevision`. Pass them directly to typed computation APIs. Use
`get()` only when interacting with an interface that requires the underlying
integer. Computation revision zero remains valid.

Historical relations carry their endpoints inside the matching enum variant:

```rust
use hubuum_client::{HistoricalEndpointContext, HistoricalRelationValue};

fn endpoint_name(value: &HistoricalRelationValue) -> Option<&str> {
    match value {
        HistoricalRelationValue::Class {
            to: HistoricalEndpointContext::Available { snapshot }, ..
        } => Some(&snapshot.name),
        HistoricalRelationValue::Object {
            to: HistoricalEndpointContext::Available { snapshot }, ..
        } => Some(&snapshot.name),
        _ => None,
    }
}
```

The class variant contains `HistoricalEndpointContext<ClassId>` and the object
variant contains `HistoricalEndpointContext<ObjectId>`. Match the variant before
using its endpoints. The serialized server response shape is unchanged.

## Module paths

Existing client, scope, token, and permission type paths remain available through
re-exports. Implementation modules are organized by API responsibility. Both
async and blocking modes retain the same public capabilities.
