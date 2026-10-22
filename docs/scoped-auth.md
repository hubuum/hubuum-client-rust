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
let providers = client.session_providers().await?;

for provider in providers.iter() {
    println!("Available login provider: {provider}");
}

let client = client
    .login_session(Credentials::scoped(selected_provider, username, password), Default::default())
    .await?;
```

`AuthProvidersResponse` preserves server order and provides `contains()`,
`iter()`, `len()`, `is_empty()`, and `into_providers()` helpers. Provider names
come from deployment configuration; clients should display the returned values
rather than hard-code a directory list. The blocking client exposes the same
`session_providers()` method without `.await`.

Local login remains unchanged. Omitting `identity_scope` lets the server use its
`local` default:

```rust
let client = hubuum_client::Client::from_url("https://hubuum.example")?
    .login_session(hubuum_client::Credentials::new("alice", password), Default::default())
    .await?;
```

Select an advertised provider by passing its configured scope:

```rust
use hubuum_client::{Client, Credentials};

let client = Client::from_url("https://hubuum.example")?
    .login_session(Credentials::scoped("corp-directory", "alice", password), Default::default())
    .await?;
```

`Credentials::new(...).in_scope(...)` is equivalent when credentials are built
incrementally. Passwords remain redacted from `Debug` output.

Some servers also require [fresh credential approvals](credential-approvals.md)
for credential management. Approval uses the logged-in human's current password
and existing identity provider. It requires an unscoped bearer token, meaning a
token without permission/resource restrictions; provider-scoped login remains
supported. The approval guide covers both server policies and async/blocking
examples.

Provider configuration, TLS, synchronization intervals, and directory mapping
belong to the Hubuum server. The client does not configure or enumerate identity
providers.

## Credential activity

Server v0.0.20 exposes creation provenance and recent credential sources separately
from token metadata. Use the owning principal and retained token ID:

```rust,no_run
use hubuum_client::{Client, CredentialActivityPageOptions, PrincipalId, TokenId};

# async fn example(client: &Client<hubuum_client::Authenticated>, principal_id: PrincipalId, token_id: TokenId) -> Result<(), hubuum_client::ApiError> {
let mut options = CredentialActivityPageOptions::default().limit(25)?;
loop {
    let page = client.token_activity(principal_id, token_id, options).await?;
    // Inspect page.creation, page.sources, and the coverage fields together.
    // Source addresses are available explicitly but omitted from Debug output.
    let Some(next) = page.next_page_options()? else { break };
    options = next;
}
# Ok(())
# }
```

User and service-account handles also expose `token_activity(token_id, options)`.
Blocking clients use the same API without `.await`. The default page starts at
offset 0 with a limit of 50; limits accept 1–100 and offsets accept 0–256. The
next-page helper rejects non-advancing or out-of-range continuations.

The caller needs token-management authority: an unscoped human managing their own
credentials, an administrator, or an authorized service-account owner-group member.
An issuer can differ from the credential's owner. Historical credentials can have
`creation: None`, and an unavailable source has `address: None`. Method strings
preserve future server values. Rotating access tokens share the original session's
creation evidence and source history, identified by `session_id`.

Activity is best-effort evidence of successful credential validation, including
requests whose subsequent authorization or handler fails. It is not a complete
request ledger. Read `collection_enabled`, `best_effort`, `retention_days`,
`source_cap`, and `overflow_since` alongside the sources. A missing overflow marker
does not guarantee complete collection. Activity does not change the token's
revision or ETag; revocation preserves evidence until retention removes it.

`config().authentication` exposes session access, idle, absolute, and retention
durations in seconds. `admin_config().authentication` additionally exposes
`credential_activity_enabled`, `credential_activity_retention_days`, and
`credential_activity_source_cap`. These settings are `Option` values: `None`
means the server did not report the field, rather than zero or disabled.

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
accounts provide `is_local()`. For users and service accounts, `is_local()`
returns `Some(true)` or `Some(false)` when a list projection includes the scope
name, and `None` when a canonical point projection exposes only the server-owned
scope ID.

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
