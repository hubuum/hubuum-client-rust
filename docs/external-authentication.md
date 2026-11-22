# Project authentication APIs

These APIs belong to Project #6 on `project/auth-support` and require the
accepted server candidate in
[`authentication-project-source.json`](https://github.com/hubuum/hubuum-client-rust/blob/173e34edb50e14990a0d59abccd90fcde73bd45f/openapi/authentication-project-source.json).
The released compatibility target remains server **v0.0.22**. New project methods
do not establish support in that released image or authorize stable publication.

Hubuum owns OAuth/OIDC exchange, PKCE, callbacks, identity and authorization.
Applications use one protocol for local, LDAP, OIDC and OAuth. Interaction handles
keep redemption secrets private; upstream tokens never enter the SDK.

## Login and persistence

1. Call `authentication_methods()` and select a stable `provider_id`. Names are
   display metadata. Only a genuine unsupported/404 endpoint permits an explicit
   choice to use legacy password login; timeouts, temporary failures and malformed
   success responses must never cause a downgrade. The SDK never downgrades.
2. Begin with `AuthenticationInteractionRequest::new(client_id, provider_id)`.
   `AuthenticationNext::Credentials` permits one-attempt `submit_credentials`.
   `Browser` supplies a Hubuum verification URI and user code for explicit human
   approval. Use `hosted_browser()` for hosted local/LDAP password entry.
3. Wait for `poll_after()` before calling `poll()`. The handle honors Retry-After,
   increases backoff with bounded jitter and stops after terminal responses.
   Local expiry is at most ten minutes. Terminal errors require a new interaction.
4. Consume a ready flow with `complete()` for a normal rotating authenticated
   client, or `complete_with_store(Arc<dyn SessionStore>)` for durable credentials.
   The existing store lock, serialized refresh, uncertain-refresh invalidation,
   origin/client binding and logout implementation remain in use. Stores must
   isolate identities/providers and protect their serialized credentials.

Completion is never replayed. Ambiguous completion and persistence failures
attempt exact-family cleanup. Keep `issued_session_cleanup()` before consuming
the flow so the application can retry that idempotent cleanup if needed.
Cleanup first cancels to fence a racing completion, then revokes an issued family.
An uncertain cancellation cannot be reported as successful cleanup while no
session is visible. Cancellation consumes the handle. Passwords are discarded after submission;
browser-only flows reject direct password submission without sending it.

SDK-built HTTP clients disable redirects. Supplied HTTP clients must use
`redirect(reqwest::redirect::Policy::none())`; custom transports must preserve
the planned origin and sensitive-header handling. The SDK never follows browser
verification links. Handle, input and request-plan diagnostics are redacted.

## Fresh approvals

Pass an exact typed `CredentialOperation` to
`begin_credential_approval_interaction()`. Completion returns the existing
single-use `ApprovedCredentialOperation<T>`, not a login session or session-wide
elevation. `send()` submits the normalized approved body.

The originating bearer is captured once. Polling/completion use the private
interaction capability; the mutation uses that original bearer and approval.
Credential replacement, expiry or revocation requires a new approval. Password
approval handles follow the same rule rather than refreshing onto another bearer.
`ApiError::is_capability_unsupported()` identifies explicit `422` outcomes;
GitHub OAuth cannot supply fresh evidence. Never substitute a weaker proof or
another identity.

## Runtime administration

Local accounts stay on IAM and local password authentication stays available.
For external providers:

1. Inspect `runtime_settings_schema().security` and
   `effective_authentication_settings()`: supported kinds, credential availability,
   deployment locks, revision and this replica's application status. A commit is
   not a cluster acknowledgement.
2. Build the complete desired provider selection with
   `AuthenticationProviderUpdate` and `ProviderConfigurationInput`. Dynamic
   definition fields follow the server schema; full provider/admission/membership
   validation stays on Hubuum. Do not copy redacted status objects into writes.
3. Submit `SecurityCandidateRequest::authentication(revision, providers)` with
   `create_security_candidate()`. This creates non-live verification state once.
4. Use `verify_ldap_security_candidate()` for LDAP or
   `begin_provider_verification_interaction()` for browser providers. Completion
   binds the candidate/provider and rejects claimed provisioning/session effects.
   The preview is not a login or an activation.
5. Consume a fully verified report with `into_activation()`, then construct
   `CredentialOperation::activate_security_candidate(activation)`. Obtain fresh
   local-administrator approval and `send()` the exact candidate/revision/receipt.
   Candidate GET never rediscloses receipts. Receipts stay out of the approval
   operation description and appear only in the protected activation mutation.

Use `ProviderCredentialInput::replace(secret)` for encrypted runtime OIDC/OAuth
credentials; `keep()`, `clear()` and deployment-managed `reference()` are explicit
alternatives. LDAP bind passwords are separate write-only inputs: omission keeps
an encrypted password; `clear_ldap_bind_password()` explicitly sends null.
Supply a managed `bind_password_ref` explicitly when selecting that alternative.
Replacement needs no per-provider environment alias. Root encryption keys, trust/egress policy,
browser origin/return registrations and locks retain their bootstrap roles.

Keep immutable IDs when editing or disabling providers. Refetch and re-verify
after `412 stale_resource`, secret-version or lock conflicts. Changes invalidate
in-flight proofs; keep local recovery usable. Authorization candidates support
explicit local, runtime Treetop or deployment ownership and never fall back to
local policy after failure.

## BFF delivery and contract inputs

`request.bff(registered_target_id, nonce)` requires an application CSPRNG nonce
stored with the interaction in server-side state bound to the initiating HttpOnly
browser session. Compare returned ID/nonce before redemption, retain
`hubuum-frontend` as client ID, rotate the session and apply CSRF protection.
Bearer, refresh, approval and redemption secrets never belong in browser
JavaScript, URLs, logs or local storage.

The released `openapi/operations.json` stays unchanged. The project snapshot
records only authentication/security operations and reachable schemas. Regenerate
from its pinned server source:

```bash
python3 scripts/openapi-contract.py update \
  --spec /path/to/pinned-server/docs/openapi.json \
  --snapshot openapi/authentication-project.json \
  --path-prefix /api/v1/auth/ \
  --path-prefix /api/v1/admin/runtime-settings/security-candidates \
  --path-prefix /api/v1/admin/runtime-settings/schema \
  --path-prefix '/api/v1/admin/runtime-settings/{group}' \
  --path-prefix /api/v1/iam/credential-approvals
python3 scripts/openapi-contract.py validate
python3 scripts/openapi-contract.py validate --snapshot openapi/authentication-project.json
```

The copied 48-case corpus is SHA-256-pinned in the source manifest. Its public
placeholders and historical clock are test inputs, not live credentials. Client
tests materialize valid bounded identifiers/proofs and rebase that clock while
preserving response semantics. Provider-side browser, admission, membership and
persistence effects require the separate live server/consumer suites.

## Production-image consumer qualification

The independent `e2e_client` binary uses only public SDK APIs for runtime encrypted
provider setup, candidate preview, exact approved activation, browser login,
session rotation, fresh approvals, logout and local recovery. The standard-library
controller reuses the accepted server's hash-pinned Keycloak/synthetic OAuth
fixtures and checks that preview leaves six persistent identity/session tables
unchanged. Input secrets live in a disposable mode-0600 file; stdout contains
public browser instructions and sanitized check names only. Custom HTTP clients
trust the generated CA and disable redirects.

```bash
cargo build -p e2e_client --features project-authentication-tests \
  --bin authentication-project --locked
python3 -I -S tests/python/integration/authentication.py \
  --server-source /path/to/accepted-server-source \
  --image hubuum-server:qualified-project-candidate \
  --consumer target/debug/authentication-project \
  --profile id_token --evidence /path/to/private-evidence/id-token
```

Run `id_token`, `userinfo` and `oauth`. The OAuth fixture is synthetic; real GitHub
still needs separately authorized provider qualification. The required immutable
v0.0.22 combined library/consumer run remains a separate compatibility gate.
For manual browser login, see `browser_login` and `browser_login_blocking` examples;
they print public verification instructions, validate identity and log out.

The sanitized [qualification ledger](assets/authentication-qualification.json)
records the actual clean SDK source, consumer checksum, pinned production image,
three provider profiles, both client modes and all 60 successful checks.
Candidate acceptance additionally requires the complete PR CI run and retained
artifact verification; these live results alone do not close the ecosystem gate.
