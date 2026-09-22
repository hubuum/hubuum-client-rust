# Fresh credential approvals

Hubuum v0.0.16 requires fresh password authentication for token creation and renewal, local user
creation, password changes, credential-bearing imports (including dry runs), and
restore confirmation. Client 0.11.2 targets this release; the approval helpers
have been available since client 0.11.1.

## Authenticate the acting human

Use an authenticated client holding an **unscoped human bearer token**. Here,
unscoped means no token permission/resource restrictions; it does not mean the
human must belong to the `local` identity scope. Normal password login supplies
the human session used for approval:

```rust,no_run
use hubuum_client::{ApiError, Authenticated, Client, Credentials};

async fn login_human(
    base_url: &str,
    username: &str,
    password: String,
) -> Result<Client<Authenticated>, ApiError> {
    Client::from_url(base_url)?
        .login(Credentials::new(username, password))
        .await
}
```

For LDAP or another configured provider, use
`Credentials::scoped(provider, username, password)` instead. During approval,
the server rechecks the actor's password against that same identity scope; the
approval API cannot select a different account or provider. See
[scoped authentication](https://github.com/hubuum/hubuum-client-rust/blob/main/docs/scoped-auth.md)
for provider discovery and
[client setup](https://github.com/hubuum/hubuum-client-rust/blob/main/docs/client-setup.md)
for blocking login and attaching existing tokens.

An existing human token can be used if it is unscoped, valid, and authorized for
the operation. Token login does not supply the password needed for approval;
the application must collect it separately. Service accounts cannot obtain an
approval or password-login. To manage their credentials, use the human
administrator or authorized owner-group member's client and current password.
Approval proves fresh authentication and grants no additional permissions.
Credential-bearing imports require a human administrator.

## Support both server policies

Existing mutation methods retain their original behavior and send no approval
requests or headers. Applications can call them on older servers without any
change. When `error.is_reauthentication_required()` is true for a mutation
failure, ask for the acting human's current password and explicitly use the
approval flow.
This helper checks both HTTP 403 and the stable `reauthentication_required`
reason. Other failures must retain their normal handling.

The following functions mint a token for a user. Pass the same authenticated
client used for the original request. `prompt_password` is an application callback
that obtains the acting human's current password only when required; use a hidden
CLI prompt or password confirmation form. In async applications, the callback
should avoid blocking the runtime. Cancellation returns an error and stops the
operation. Present the target and requested token settings before confirmation.

### Async

The `async` feature is enabled by default.

```rust,no_run
use std::future::Future;

use hubuum_client::{
    ApiError, Authenticated, Client, CredentialOperation, NewTokenRequest, Token, UserId,
};

async fn mint_user_token<F, Fut>(
    client: &Client<Authenticated>,
    target: UserId,
    request: NewTokenRequest,
    prompt_password: F,
) -> Result<Token, ApiError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<String, ApiError>>,
{
    let user = client.users().get(target).await?;
    match user.tokens_create_token(request.clone()).await {
        Ok(token) => Ok(token),
        Err(error) if error.is_reauthentication_required() => {
            let password = prompt_password().await?;
            let approved = client
                .credential_approvals()
                .approve(password, CredentialOperation::create_token(target, request))
                .await?;
            // Retain this non-secret ID before sending, including on failure.
            eprintln!("Credential approval ID: {}", approved.record().id);
            approved.send().await
        }
        Err(error) => Err(error),
    }
}
```

### Blocking

Enable the `blocking` feature and use `hubuum_client::blocking::Client`:

```rust,no_run
use hubuum_client::{
    ApiError, Authenticated, CredentialOperation, NewTokenRequest, Token, UserId,
    blocking::Client,
};

fn mint_user_token(
    client: &Client<Authenticated>,
    target: UserId,
    request: NewTokenRequest,
    prompt_password: impl FnOnce() -> Result<String, ApiError>,
) -> Result<Token, ApiError> {
    let user = client.users().get(target)?;
    match user.tokens_create_token(request.clone()) {
        Ok(token) => Ok(token),
        Err(error) if error.is_reauthentication_required() => {
            let password = prompt_password()?;
            let approved = client
                .credential_approvals()
                .approve(password, CredentialOperation::create_token(target, request))?;
            // Retain this non-secret ID before sending, including on failure.
            eprintln!("Credential approval ID: {}", approved.record().id);
            approved.send()
        }
        Err(error) => Err(error),
    }
}
```

These examples report the approval ID to stderr. In an application, retain it
with the pending operation for recovery. The callback's error type can be
adapted to the application's own error type. Store the returned `Token` securely;
its bearer secret is issued only once. Do not log `token.as_str()`.

For service-account tokens, use `client.service_accounts().get(target)` for the
initial attempt and pass the `ServiceAccountId` to
`CredentialOperation::create_token`. The client still belongs to the acting human.
If a deployment is already known to require approvals, the application may go
directly to `approve` after confirmation.

## Approved operations

An approval keeps its original authenticated client, target, and request. Its
consuming `send()` uses that bearer and adds `X-Hubuum-Credential-Approval` only
to the approved mutation.
It automatically copies the server's resolved token expiry, including the full
microsecond precision, even if the original request supplied an explicit expiry.
Passwords, approval secrets, and request bodies are omitted from debug output.
The acting password is discarded after requesting approval.

| Operation constructor | Result from approved `send()` |
| --- | --- |
| `CredentialOperation::create_token(principal_id, NewTokenRequest)` | `Token` |
| `CredentialOperation::renew_token(principal_id, token_id, RenewTokenRequest)` | `Token` |
| `CredentialOperation::create_user(UserPost)` | `User` |
| `CredentialOperation::set_password(user_id, new_password)` | `User` |
| `CredentialOperation::update_user(user_id, UserPatch, new_password)` | `User` |
| `CredentialOperation::import_credentials(FullImportRequest)` | `TaskResponse` |
| `CredentialOperation::confirm_restore(restore_id, RestoreConfirmRequest)` | `RestoreStageResponse` |

For user updates, apply `.if_match(etag)` to the approved handle to retain the
normal revision precondition. The new user's password or replacement password
belongs in the operation; the separate `approve` password authenticates the actor.
Profile-only updates continue through the existing user update API.

For imports, apply `.idempotency_key(key)` before `send()`. Keep the complete
payload and array order unchanged. The key enables the normal transient retry
policy for that admission request with the same approval header and payload.
Use `tasks().wait(task.id)` and `imports().results(task.id)` to follow completion.
An already accepted import can finish after the approval expires. A changed
payload requires a new approval and idempotency key.

Restore confirmation still requires the staged restore capability, digest, and
confirmation phrase. After acceptance, poll the existing capability-authenticated
restore status endpoint until completion.

## Failures, expiry, and recovery

| Failure | Application behavior |
| --- | --- |
| `error.is_reauthentication_required()` | Obtain a fresh approval for the intended operation; do not loop on the unapproved request. |
| HTTP 401 during approval | The password or bearer authentication failed. Surface the failure; do not retry automatically. |
| Other HTTP 403 or 404 | Preserve permission and visibility failures. Another password prompt cannot grant missing authority. A missing approval endpoint can also mean an older server. |
| HTTP 429 | Respect authentication throttling; avoid repeated password prompts or automated retries. |
| Identity provider unavailable | Surface the failure. Cached LDAP membership cannot replace fresh password verification. |

An expired, consumed, invalidated, or mismatched approval can produce the same
`reauthentication_required` reason as a missing approval. If an approved send
returns it, obtain fresh confirmation before attempting a new approval; the
examples deliberately make only one approval attempt.

Approvals are single use and last at most 120 seconds, bounded by the originating
bearer token's expiry. Changing the operation or switching bearer tokens requires
a new approval, even for the same human. A failed or lost mutation response does
not establish whether the mutation committed. Save `record().id`
before sending and inspect `client.credential_approvals().get(id)` for
`consumed_at` and `invalidated_at`. Consumed evidence cannot recover an issued
token secret. Inspect token metadata, revoke unwanted tokens, and obtain a fresh
approval before creating a replacement. The client does not automatically retry
password authentication or non-idempotent approved mutations.

Approval endpoint failures, including 404 on older servers, are returned to the
caller. There is no automatic fallback from a failed approval to an unapproved
write. Applications decide when to collect a fresh password; the client does not
store login passwords or enable a session-wide elevated mode. Existing login,
ordinary access, listing, and revocation continue to use their current APIs.

Do not retain the login password for later approval requests or put passwords in
command-line arguments, logs, or telemetry. Automation holding only a bearer
token cannot mint or renew credentials on servers requiring approvals. Provision
its credentials through an interactive approved operation and place them in the
workload's secret store; existing tokens retain their normal resource access.
