use std::fmt;
use std::time::Duration;

use reqwest::Method;
use secrecy::SecretString;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::marker::PhantomData;
use std::sync::Arc;

use super::{Authenticated, Client, Unauthenticated, shared};
use crate::SessionStore;
use crate::client::interactions::{InteractionAccess, InteractionBinding, InteractionCredentials};
use crate::client::sessions;
use crate::endpoints::authentication::{self, InteractionAction};
use crate::{
    ApiError, AuthenticationInteractionId, AuthenticationInteractionRequest,
    AuthenticationInteractionStatus, AuthenticationMethods, AuthenticationNext,
    AuthenticationProviderId, CredentialOperation, HubuumDateTime, SecurityCandidateId,
    SecurityCandidateVerification, TransportResponse,
};

/// Completion of this interaction yields a normal rotating Hubuum session.
#[derive(Debug)]
pub struct LoginCompletion;

pub type LoginInteraction = AuthenticationInteraction<LoginCompletion>;

pub struct ApprovalCompletion<T> {
    client: Client<Authenticated>,
    operation: CredentialOperation<T>,
}

impl<T> fmt::Debug for ApprovalCompletion<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalCompletion")
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

pub type ApprovalInteraction<T> = AuthenticationInteraction<ApprovalCompletion<T>>;

#[derive(Debug)]
pub struct VerificationCompletion {
    candidate_id: SecurityCandidateId,
    provider_id: AuthenticationProviderId,
}

pub type ProviderVerificationInteraction = AuthenticationInteraction<VerificationCompletion>;

#[derive(Serialize)]
#[serde(tag = "purpose", rename_all = "snake_case")]
enum InteractionPurpose<'a> {
    Login,
    CredentialApproval {
        operation: serde_json::Value,
    },
    ProviderVerification {
        candidate_id: &'a SecurityCandidateId,
    },
}

#[derive(Serialize)]
struct Begin<'a> {
    #[serde(flatten)]
    request: &'a AuthenticationInteractionRequest,
    #[serde(flatten)]
    purpose: InteractionPurpose<'a>,
}

/// An origin-bound interaction. Secrets remain private and diagnostics redacted.
/// Polling is caller-driven and bounded by the server deadline (at most ten
/// minutes locally). Password submission and completion are never retried.
#[must_use = "complete or cancel the interaction; discard it on terminal errors"]
pub struct AuthenticationInteraction<C> {
    client: Client<Unauthenticated>,
    binding: InteractionBinding,
    completion: C,
}

impl<C: fmt::Debug> fmt::Debug for AuthenticationInteraction<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticationInteraction")
            .field("binding", &self.binding)
            .field("completion", &self.completion)
            .finish()
    }
}

/// Cleanup for an ambiguous completion result. Keep this before consuming an
/// interaction when the consumer must persist a session. It can only revoke the
/// session issued by that interaction, including its rotated descendants.
#[derive(Clone, Debug)]
pub struct IssuedSessionCleanup {
    client: Client<Unauthenticated>,
    access: InteractionAccess,
}

impl<S> Client<S> {
    // Dedicated single-attempt transport, with no automatic bearer injection,
    // refresh or mutation retries. SDK-built clients disable redirects; supplied
    // transports must preserve that policy. raw() keeps its existing
    // prohibition on Authorization overrides.
    pub(super) async fn authentication_http<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: &T,
        headers: &[(&str, String)],
    ) -> Result<TransportResponse, ApiError> {
        let url = shared::build_relative_url(self.base_url(), path, &[])?;
        let plan = if method == Method::GET {
            shared::build_unauthenticated_request_plan(&method, url.as_str(), headers)?
        } else {
            shared::build_unauthenticated_json_request_plan(&method, url.as_str(), body, headers)?
        };
        if let Some(transport) = self.transport() {
            return transport.execute(plan).await;
        }
        let response = plan
            .into_async_request(self.http_client())
            .timeout(self.options().authentication_request_timeout)
            .send()
            .await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = if status.is_success() {
            shared::read_async_body(response, self.options().max_response_body_bytes).await?
        } else {
            shared::read_async_body_preview(response, self.options().max_error_body_bytes).await
        };
        Ok(TransportResponse {
            status,
            headers,
            body: body.into_bytes(),
        })
    }

    pub(super) fn authentication_body(
        &self,
        method: &Method,
        path: &str,
        response: TransportResponse,
    ) -> Result<String, ApiError> {
        let url = shared::build_relative_url(self.base_url(), path, &[])?;
        Ok(
            shared::process_transport_response(method, url.as_str(), response, self.options())?
                .body,
        )
    }
}

impl Client<Unauthenticated> {
    /// Discover typed login methods. Only an actual unsupported/404 response
    /// permits the caller to select the existing password login API explicitly.
    pub async fn authentication_methods(&self) -> Result<AuthenticationMethods, ApiError> {
        let response = self
            .authentication_http(Method::GET, authentication::METHODS, &(), &[])
            .await?;
        let body = self.authentication_body(&Method::GET, authentication::METHODS, response)?;
        let methods: AuthenticationMethods =
            serde_json::from_str(&body).map_err(|_| ApiError::InvalidAuthenticationInteraction)?;
        if methods.interaction_version != 1 {
            return Err(ApiError::InvalidAuthenticationInteraction);
        }
        Ok(methods)
    }

    pub async fn begin_login_interaction(
        &self,
        request: AuthenticationInteractionRequest,
    ) -> Result<LoginInteraction, ApiError> {
        self.begin_interaction(request, InteractionPurpose::Login, &[], LoginCompletion)
            .await
    }

    async fn begin_interaction<C>(
        &self,
        request: AuthenticationInteractionRequest,
        purpose: InteractionPurpose<'_>,
        headers: &[(&str, String)],
        completion: C,
    ) -> Result<AuthenticationInteraction<C>, ApiError> {
        let response = self
            .authentication_http(
                Method::POST,
                authentication::BEGIN,
                &Begin {
                    request: &request,
                    purpose,
                },
                headers,
            )
            .await?;
        let body = self.authentication_body(&Method::POST, authentication::BEGIN, response)?;
        let binding = InteractionBinding::decode(
            body.as_bytes(),
            self.base_url(),
            request.client_id().clone(),
        )?;
        Ok(AuthenticationInteraction {
            client: self.clone(),
            binding,
            completion,
        })
    }
}

impl Client<Authenticated> {
    /// Capture the originating bearer once. Subsequent polling, completion and
    /// the approved mutation cannot refresh or silently rebind that credential.
    /// Unsupported provider capabilities remain explicit server errors.
    pub async fn begin_credential_approval_interaction<T: DeserializeOwned>(
        &self,
        request: AuthenticationInteractionRequest,
        operation: CredentialOperation<T>,
    ) -> Result<ApprovalInteraction<T>, ApiError> {
        operation.validate()?;
        let token = self.ready_token().await?;
        let operation_value = serde_json::to_value(&operation)?;
        let original = Client {
            runtime: self.runtime.clone(),
            state: Authenticated::new(token.clone()),
        };
        let public = Client {
            runtime: self.runtime.clone(),
            state: Unauthenticated,
        };
        public
            .begin_interaction(
                request,
                InteractionPurpose::CredentialApproval {
                    operation: operation_value,
                },
                &[("Authorization", format!("Bearer {}", token.as_str()))],
                ApprovalCompletion {
                    client: original,
                    operation,
                },
            )
            .await
    }

    pub async fn begin_provider_verification_interaction(
        &self,
        request: AuthenticationInteractionRequest,
        candidate_id: SecurityCandidateId,
    ) -> Result<ProviderVerificationInteraction, ApiError> {
        let token = self.ready_token().await?;
        let provider_id = request.provider_id().clone();
        let public = Client {
            runtime: self.runtime.clone(),
            state: Unauthenticated,
        };
        public
            .begin_interaction(
                request,
                InteractionPurpose::ProviderVerification {
                    candidate_id: &candidate_id,
                },
                &[("Authorization", format!("Bearer {}", token.as_str()))],
                VerificationCompletion {
                    candidate_id: candidate_id.clone(),
                    provider_id,
                },
            )
            .await
    }
}

impl<C> AuthenticationInteraction<C> {
    pub fn id(&self) -> &AuthenticationInteractionId {
        self.binding.access().id()
    }

    pub fn next(&self) -> &AuthenticationNext {
        self.binding.next()
    }

    pub fn expires_at(&self) -> &HubuumDateTime {
        self.binding.expires_at()
    }

    /// Wait at least this long before the next status request. A zero delay at
    /// expiry does not authorize another request; poll returns an expiry error.
    pub fn poll_after(&self) -> Duration {
        self.binding.poll_after()
    }

    pub fn issued_session_cleanup(&self) -> IssuedSessionCleanup {
        IssuedSessionCleanup {
            client: self.client.clone(),
            access: self.binding.access().clone(),
        }
    }

    pub async fn poll(&mut self) -> Result<AuthenticationInteractionStatus, ApiError> {
        self.binding.before_poll()?;
        let access = self.binding.access();
        let path = authentication::interaction(access.id(), InteractionAction::Status);
        let response = self
            .client
            .authentication_http(
                Method::POST,
                &path,
                &access.body(),
                &[("Authorization", access.authorization())],
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.binding.after_transport_failure();
                return Err(error);
            }
        };
        self.binding.after_poll(response.status, &response.headers);
        let body = self
            .client
            .authentication_body(&Method::POST, &path, response)?;
        self.binding.decode_status(body.as_bytes())
    }

    pub async fn submit_credentials(
        &mut self,
        name: &str,
        password: impl Into<String>,
    ) -> Result<AuthenticationInteractionStatus, ApiError> {
        self.binding.ensure_live()?;
        if !matches!(self.binding.next(), AuthenticationNext::Credentials) {
            return Err(ApiError::InvalidAuthenticationInteraction);
        }
        let password = password.into();
        if name.is_empty() || name.len() > 255 || password.is_empty() || password.len() > 4096 {
            return Err(ApiError::InvalidAuthenticationInteraction);
        }
        let access = self.binding.access();
        let path = authentication::interaction(access.id(), InteractionAction::Credentials);
        let credentials = InteractionCredentials {
            client_id: access.client_id(),
            name,
            password: SecretString::from(password),
        };
        let response = self
            .client
            .authentication_http(
                Method::POST,
                &path,
                &credentials,
                &[("Authorization", access.authorization())],
            )
            .await?;
        let body = self
            .client
            .authentication_body(&Method::POST, &path, response)?;
        self.binding.decode_status(body.as_bytes())
    }

    pub async fn cancel(self) -> Result<(), ApiError> {
        let access = self.binding.access();
        let path = authentication::interaction(access.id(), InteractionAction::Cancel);
        let response = self
            .client
            .authentication_http(
                Method::POST,
                &path,
                &access.body(),
                &[("Authorization", access.authorization())],
            )
            .await?;
        self.client
            .authentication_body(&Method::POST, &path, response)?;
        Ok(())
    }

    async fn redeem(&self) -> Result<String, ApiError> {
        self.binding.ensure_live()?;
        let access = self.binding.access();
        let path = authentication::interaction(access.id(), InteractionAction::Complete);
        let response = self
            .client
            .authentication_http(
                Method::POST,
                &path,
                &access.body(),
                &[("Authorization", access.authorization())],
            )
            .await?;
        self.client
            .authentication_body(&Method::POST, &path, response)
    }
}

impl LoginInteraction {
    async fn redeem_pair(&self) -> Result<sessions::SessionPair, ApiError> {
        let result = self
            .redeem()
            .await
            .and_then(|body| sessions::SessionPair::decode(body.as_bytes()));
        if result.as_ref().is_err_and(|error| {
            (!matches!(
                error,
                ApiError::AuthenticationInteractionExpired
                    | ApiError::AuthenticationInteractionTerminated
            ) && error.status().is_none())
                || error
                    .status()
                    .is_some_and(|status| status.is_server_error())
        }) {
            // Completion is never replayed; clean up any issued family instead.
            let _ = self.issued_session_cleanup().revoke().await;
        }
        result
    }

    /// Consume the interaction in one attempt and validate the normal session
    /// envelope before constructing an authenticated client. Preserve a cleanup
    /// handle when an ambiguous result or local persistence failure is possible.
    pub async fn complete(self) -> Result<Client<Authenticated>, ApiError> {
        let pair = self.redeem_pair().await?;
        Ok(Client {
            runtime: self.client.runtime.clone(),
            state: Authenticated::with_session(pair, self.binding.access().client_id().clone()),
        })
    }

    /// Persist the normal session under the application's existing store lock
    /// and retain coordinated rotation. Storage failure clears the slot when
    /// possible and attempts exact-family cleanup before returning the error.
    pub async fn complete_with_store(
        self,
        store: Arc<dyn SessionStore>,
    ) -> Result<Client<Authenticated>, ApiError> {
        let lock_store = store.clone();
        let mut guard = tokio::task::spawn_blocking(move || lock_store.lock())
            .await
            .map_err(|_| ApiError::SessionExpired)??;
        let pair = self.redeem_pair().await?;
        let client = Client {
            runtime: self.client.runtime.clone(),
            state: Authenticated::with_session_store(
                pair,
                self.binding.access().client_id().clone(),
                store,
            ),
        };
        let result = client
            .state
            .session()
            .ok_or(ApiError::SessionExpired)?
            .save(guard.as_mut(), self.client.base_url());
        if let Err(error) = result {
            let _ = guard.save(None);
            drop(guard);
            let _ = self.issued_session_cleanup().revoke().await;
            return Err(error);
        }
        Ok(client)
    }
}

impl<T: DeserializeOwned> ApprovalInteraction<T> {
    pub async fn complete(self) -> Result<super::ApprovedCredentialOperation<T>, ApiError> {
        let body = self.redeem().await?;
        let response = serde_json::from_str(&body)?;
        Ok(super::ApprovedCredentialOperation {
            client: self.completion.client,
            request: shared::ApprovedCredentialRequest::new(self.completion.operation, response)?,
            output: PhantomData,
        })
    }
}

impl ProviderVerificationInteraction {
    pub async fn complete(self) -> Result<SecurityCandidateVerification, ApiError> {
        let body = self.redeem().await?;
        let result: SecurityCandidateVerification = serde_json::from_str(&body)?;
        if result.candidate.id != self.completion.candidate_id
            || result.verification.candidate_id != self.completion.candidate_id
            || result.verification.provider_id != self.completion.provider_id
            || result.verification.issued_session
            || result.verification.provisioned
        {
            return Err(ApiError::InvalidAuthenticationInteraction);
        }
        Ok(result)
    }
}

impl IssuedSessionCleanup {
    /// Fence a racing completion through cancellation, then revoke any issued
    /// family. Each operation is sent once. Retain this handle after a network
    /// failure so an unknown cancellation/revocation outcome can be retried.
    pub async fn revoke(&self) -> Result<(), ApiError> {
        let cancel_path = authentication::interaction(self.access.id(), InteractionAction::Cancel);
        let cancelled = match self
            .client
            .authentication_http(
                Method::POST,
                &cancel_path,
                &self.access.body(),
                &[("Authorization", self.access.authorization())],
            )
            .await
        {
            Ok(response) => self
                .client
                .authentication_body(&Method::POST, &cancel_path, response)
                .map(|_| ()),
            Err(error) => Err(error),
        };
        let path =
            authentication::interaction(self.access.id(), InteractionAction::RevokeIssuedSession);
        let response = self
            .client
            .authentication_http(
                Method::POST,
                &path,
                &self.access.body(),
                &[("Authorization", self.access.authorization())],
            )
            .await?;
        match self
            .client
            .authentication_body(&Method::POST, &path, response)
        {
            Ok(_) => Ok(()),
            Err(error)
                if error.is_status(reqwest::StatusCode::CONFLICT)
                    && error.api_response().is_some_and(|response| {
                        response.reason.as_deref() == Some("interaction_pending")
                    }) =>
            {
                cancelled
            }
            Err(error) => Err(error),
        }
    }
}
