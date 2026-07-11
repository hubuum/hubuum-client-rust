# Scoped Authentication

Hubuum identity scopes allow the same principal name to exist in local identity
storage and in one or more configured providers. The client carries the scope
through login, queries, response models, create payloads, group membership
responses, and import group references.

This API depends on the scoped identity contract introduced by Hubuum server PR
[#112](https://github.com/hubuum/hubuum/pull/112).

## Login

Provider discovery is public, so a login screen or CLI prompt can build its
provider choices before asking for credentials:

```rust
use hubuum_client::{Client, Credentials};

let client = Client::from_url("https://hubuum.example")?;
let providers = client.auth_providers().await?;

for provider in providers.iter() {
    println!("Available login provider: {provider}");
}

let client = client
    .login(Credentials::scoped(selected_provider, username, password))
    .await?;
```

`AuthProvidersResponse` preserves server order and provides `contains()`,
`iter()`, `len()`, `is_empty()`, and `into_providers()` helpers. Provider names
come from deployment configuration; clients should display the returned values
rather than hard-code a directory list. The blocking client exposes the same
`auth_providers()` method without `.await`.

Local login remains unchanged. Omitting `identity_scope` lets the server use its
`local` default:

```rust
let client = hubuum_client::Client::from_url("https://hubuum.example")?
    .login(hubuum_client::Credentials::new("alice", password))
    .await?;
```

Select an advertised provider by passing its configured scope:

```rust
use hubuum_client::{Client, Credentials};

let client = Client::from_url("https://hubuum.example")?
    .login(Credentials::scoped("corp-directory", "alice", password))
    .await?;
```

`Credentials::new(...).in_scope(...)` is equivalent when credentials are built
incrementally. Passwords remain redacted from `Debug` output.

Provider configuration, TLS, synchronization intervals, and directory mapping
belong to the Hubuum server. The client does not configure or enumerate identity
providers.

## Querying Identities

Names are unique within an identity scope, not globally. Include
`identity_scope` whenever a name may be ambiguous:

```rust
let alice = client
    .users()
    .identity_scope()
    .eq("corp-directory")
    .name()
    .eq("alice")
    .one()
    .await?;

let operators = client
    .groups()
    .identity_scope()
    .eq("corp-directory")
    .groupname()
    .eq("operators")
    .one()
    .await?;
```

The same typed `identity_scope()` filter is available on service accounts. It
composes with pagination, sorting, and the other fluent field filters.

## Provider Metadata

Identity responses expose the server's scope and management state:

- `User::identity_scope`, `provider_kind`, and `provider_managed`
- `Group::identity_scope`, `managed_by`, and optional provider sync metadata
- `ServiceAccount::identity_scope`
- `PrincipalMember::identity_scope`, `created_at`, and `updated_at`

Users provide `is_local()` and `is_provider_managed()` helpers. Groups provide
the same helpers, with provider management derived from `managed_by`. Service
accounts provide `is_local()`.

```rust
let user = client.users().get(user_id).await?;

if user.is_provider_managed() {
    println!("{} is managed by {}", user.name, user.provider_kind);
}
```

Provider-managed users and groups are read-only through Hubuum's normal update
APIs. Change them in their source provider and let the server synchronize them.
Local records remain mutable as before.

The client decodes responses from older servers as local identities when the new
metadata is absent. It also omits `identity_scope` from local login and create
requests, preserving wire compatibility during a rolling server upgrade.

## Imports

Permission imports identify groups by both scope and name. Use `GroupKey::new`
for a local group and `GroupKey::in_scope` for a provider-backed group:

```rust
use hubuum_client::GroupKey;

let local_admins = GroupKey::new("admins");
let directory_operators = GroupKey::in_scope("corp-directory", "operators");
```

The scoped form serializes both values, preventing a local group and an external
group with the same name from being confused during preview or apply.

## Constants

The crate exports `LOCAL_IDENTITY_SCOPE`, `LOCAL_PROVIDER_KIND`, and
`LDAP_PROVIDER_KIND` for comparisons that should not depend on string literals.
Provider scope names themselves are deployment configuration and should remain
application settings.
