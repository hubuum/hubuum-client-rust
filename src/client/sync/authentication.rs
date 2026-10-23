use super::*;
use crate::client::shared::EndpointRequest;
use crate::client::{SessionStore, sessions};

impl Client<Unauthenticated> {
    pub fn builder(base_url: BaseUrl) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    /// Parse a URL string and create a configurable client builder.
    pub fn builder_from_url(base_url: impl AsRef<str>) -> Result<ClientBuilder, ApiError> {
        Ok(Self::builder(BaseUrl::new(base_url)?))
    }

    /// Build a client with secure defaults without panicking on setup errors.
    pub fn try_new(base_url: BaseUrl) -> Result<Self, ApiError> {
        Self::builder(base_url).build()
    }

    /// Parse a URL string and build a client with secure defaults.
    pub fn from_url(base_url: impl AsRef<str>) -> Result<Self, ApiError> {
        Self::try_new(BaseUrl::new(base_url)?)
    }

    #[deprecated(since = "0.3.0", note = "use Client::try_new or Client::from_url")]
    pub fn new(base_url: BaseUrl) -> Self {
        Self::try_new(base_url).expect("reqwest blocking client should build")
    }

    #[deprecated(
        since = "0.3.0",
        note = "use Client::builder(...).validate_certs(false)"
    )]
    pub fn new_without_certificate_validation(base_url: BaseUrl) -> Self {
        Self::builder(base_url)
            .validate_certs(false)
            .build()
            .expect("reqwest blocking client should build")
    }

    #[deprecated(since = "0.3.0", note = "use Client::builder(...).validate_certs(...)")]
    pub fn new_with_certificate_validation(
        base_url: BaseUrl,
        validate_server_certificate: bool,
    ) -> Self {
        Self::builder(base_url)
            .validate_certs(validate_server_certificate)
            .build()
            .expect("reqwest blocking client should build")
    }
}

impl Client<Unauthenticated> {
    pub(super) fn public_get<T: DeserializeOwned>(
        &self,
        endpoint: &Endpoint,
        empty_message: &str,
    ) -> Result<T, ApiError> {
        TraceSpan::request("public_get", &reqwest::Method::GET, endpoint.path()).run(|| {
            let url = self.build_url(endpoint, &UrlParams::default());
            let raw = if let Some(transport) = self.transport() {
                let plan =
                    shared::build_unauthenticated_request_plan(&reqwest::Method::GET, &url, &[])?;
                let response = self.execute_transport_with_retry(
                    &reqwest::Method::GET,
                    false,
                    transport.as_ref(),
                    plan,
                )?;
                shared::process_transport_response(
                    &reqwest::Method::GET,
                    &url,
                    response,
                    self.options(),
                )?
            } else {
                let response = self.send_with_retry(
                    &reqwest::Method::GET,
                    false,
                    self.http_client().get(&url),
                )?;
                let response = self.check_success(&reqwest::Method::GET, &url, response)?;
                let status = response.status();
                let body =
                    shared::read_blocking_body(response, self.options().max_response_body_bytes)?;
                shared::RawResponse {
                    status,
                    body,
                    etag: None,
                    next_cursor: None,
                    total_count: None,
                    page_limit: None,
                    content_type: None,
                }
            };

            shared::parse_response(&reqwest::Method::GET, raw.status, raw.body)?
                .ok_or_else(|| ApiError::EmptyResult(empty_message.into()))
        })
    }

    /// List authentication providers available for login without authenticating.
    pub fn auth_providers(&self) -> Result<AuthProvidersResponse, ApiError> {
        self.public_get(
            &Endpoint::AuthProviders,
            "Authentication provider discovery returned no response",
        )
    }

    /// Start a rotating interactive session on servers implementing `/api/v1/auth`.
    /// Passwords are discarded after this exchange. Clones share refresh state.
    pub fn login_session(
        &self,
        credentials: Credentials,
        client_id: crate::SessionClientId,
    ) -> Result<Client<Authenticated>, ApiError> {
        let request = sessions::SessionLogin {
            credentials: &credentials,
            client_id: &client_id,
        };
        let pair = self
            .exchange_session(&Endpoint::SessionLogin, &request)
            .map_err(sessions::login_error)?;
        Ok(Client {
            runtime: self.runtime.clone(),
            state: Authenticated::with_session(pair, client_id),
        })
    }

    /// Resume a persisted session without a password. Returns `None` when the
    /// store is empty or the refresh lifetime has expired. Refresh is coordinated
    /// with other clients/processes and the access token is validated before
    /// returning; rejected or uncertain
    /// refreshes return `SessionExpired` and leave the store empty.
    pub fn resume_session(
        &self,
        client_id: crate::SessionClientId,
        store: Arc<dyn SessionStore>,
    ) -> Result<Option<Client<Authenticated>>, ApiError> {
        let mut guard = store.lock()?;
        let Some(stored) = guard.load()? else {
            return Ok(None);
        };
        let pair = stored.restore(self.base_url(), &client_id)?;
        if stored.expired() {
            guard.save(None)?;
            return Ok(None);
        }
        let client = Client {
            runtime: self.runtime.clone(),
            state: Authenticated::with_session_store(pair, client_id, store),
        };
        drop(guard);
        client.ready_token()?;
        let session = client.state.session().ok_or(ApiError::SessionExpired)?;
        let store = session.store.clone().ok_or(ApiError::SessionExpired)?;
        let mut guard = store.lock()?;
        session.reload(guard.as_ref(), self.base_url())?;
        // Keep the store locked while validating this exact credential, so a
        // concurrent rotation cannot make us discard its valid successor.
        let validation = self
            .authenticate(session.token()?)
            .request_with_endpoint::<EmptyPostParams, serde_json::Value>(
                reqwest::Method::GET,
                &Endpoint::SessionValidate,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            );
        if let Err(error) = validation {
            if error.is_status(reqwest::StatusCode::UNAUTHORIZED) {
                session.forget(guard.as_mut())?;
            }
            return Err(error);
        }
        drop(guard);
        Ok(Some(client))
    }

    /// Log in and persist rotating credentials in an application-owned store.
    /// Ordinary requests reload the latest state under the store's lock and
    /// durably save refresh successors. Passwords are never stored.
    pub fn login_session_with_store(
        &self,
        credentials: Credentials,
        client_id: crate::SessionClientId,
        store: Arc<dyn SessionStore>,
    ) -> Result<Client<Authenticated>, ApiError> {
        let mut guard = store.lock()?;
        let request = sessions::SessionLogin {
            credentials: &credentials,
            client_id: &client_id,
        };
        let pair = self
            .exchange_session(&Endpoint::SessionLogin, &request)
            .map_err(sessions::login_error)?;
        let client = Client {
            runtime: self.runtime.clone(),
            state: Authenticated::with_session_store(pair, client_id, store),
        };
        client
            .state
            .session()
            .ok_or(ApiError::SessionExpired)?
            .save(guard.as_mut(), self.base_url())?;
        Ok(client)
    }

    /// Discover login providers on the versioned session API.
    pub fn session_providers(&self) -> Result<AuthProvidersResponse, ApiError> {
        self.public_get(
            &Endpoint::SessionProviders,
            "Provider discovery returned no response",
        )
    }

    pub fn login(&self, credentials: Credentials) -> Result<Client<Authenticated>, ApiError> {
        TraceSpan::request("login", &reqwest::Method::POST, Endpoint::Login.path()).run(|| {
            let login_url = self.build_url(&Endpoint::Login, &UrlParams::default());
            let raw = if let Some(transport) = self.transport() {
                let plan = shared::build_unauthenticated_json_request_plan(
                    &reqwest::Method::POST,
                    &login_url,
                    &credentials,
                    &[],
                )?;
                let response = self.execute_transport_with_retry(
                    &reqwest::Method::POST,
                    false,
                    transport.as_ref(),
                    plan,
                )?;
                shared::process_transport_response(
                    &reqwest::Method::POST,
                    &login_url,
                    response,
                    self.options(),
                )?
            } else {
                let response =
                    TraceSpan::attempt(&reqwest::Method::POST, 1, "reqwest").send(|| {
                        self.http_client()
                            .post(&login_url)
                            .json(&credentials)
                            .send()
                    })?;
                let response = self.check_success(&reqwest::Method::POST, &login_url, response)?;
                let status = response.status();
                let body =
                    shared::read_blocking_body(response, self.options().max_response_body_bytes)?;
                shared::RawResponse {
                    status,
                    body,
                    etag: None,
                    next_cursor: None,
                    total_count: None,
                    page_limit: None,
                    content_type: None,
                }
            };
            let token: Token =
                shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?
                    .ok_or_else(|| ApiError::EmptyResult("Login returned no token".into()))?;

            Ok(Client {
                runtime: self.runtime.clone(),
                state: Authenticated::new(token),
            })
        })
    }

    pub fn login_with_token(&self, token: Token) -> Result<Client<Authenticated>, ApiError> {
        let client = self.authenticate(token);
        let result = client.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::GET,
            &Endpoint::LoginWithToken,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        );
        if result
            .as_ref()
            .is_err_and(|error| error.is_status(reqwest::StatusCode::NOT_FOUND))
        {
            client.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
                reqwest::Method::GET,
                &Endpoint::SessionValidate,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            )?;
        } else {
            result?;
        }
        Ok(client)
    }

    /// Attach a token without making a validation request. This is useful with
    /// rotating credentials and custom transports; the first API request still
    /// verifies the token at the server boundary.
    pub fn authenticate(&self, token: Token) -> Client<Authenticated> {
        Client {
            runtime: self.runtime.clone(),
            state: Authenticated::new(token),
        }
    }

    /// Liveness probe (`GET /healthz`). Requires no authentication.
    pub fn healthz(&self) -> Result<ProbeResponse, ApiError> {
        self.public_get(&Endpoint::Healthz, "Health probe returned no response")
    }

    /// Readiness probe (`GET /readyz`). Requires no authentication; a not-ready
    /// server responds with `503`, surfaced here as an error.
    pub fn readyz(&self) -> Result<ProbeResponse, ApiError> {
        self.public_get(&Endpoint::Readyz, "Readiness probe returned no response")
    }
}

impl Client<Authenticated> {
    pub(super) fn ready_token(&self) -> Result<Token, ApiError> {
        let Some(session) = self.state.session() else {
            return self.state.token();
        };
        let _guard = session
            .blocking_lock
            .lock()
            .map_err(|_| ApiError::SessionExpired)?;
        let mut storage = if let Some(store) = session.store.clone() {
            let guard = store.lock()?;
            session.reload(guard.as_ref(), self.base_url())?;
            Some(guard)
        } else {
            None
        };
        let previous = match session.take_if_due() {
            Ok(previous) => previous,
            Err(error) => {
                if let Some(guard) = storage.as_mut() {
                    guard.save(None)?;
                }
                return Err(error);
            }
        };
        if let Some(previous) = previous {
            if let Some(guard) = storage.as_mut() {
                guard.save(None)?;
            }

            let pair = self
                .exchange_session(
                    &Endpoint::SessionRefresh,
                    &previous.request(&session.client_id),
                )
                .map_err(|_| ApiError::SessionExpired)?;
            pair.validate_successor(&previous)
                .map_err(|_| ApiError::SessionExpired)?;
            if let Some(guard) = storage.as_mut() {
                guard.save(Some(&pair.snapshot(self.base_url(), &session.client_id)))?;
            }
            session.install(pair)?;
        }
        session.token()
    }

    /// Non-secret metadata for the current interactive session, if available.
    pub fn session_info(&self) -> Option<crate::SessionInfo> {
        self.state.session()?.info()
    }

    /// Snapshot of the current bearer credential, with redacted `Debug` output.
    ///
    /// A session that has failed or is currently rotating returns `SessionExpired`.
    /// Ordinary requests coordinate refresh automatically; this accessor does not.
    pub fn token(&self) -> Result<Token, ApiError> {
        self.state.token()
    }

    /// Authoritative expiry returned when this client logged in.
    ///
    /// This is `None` when the client was authenticated from a caller-supplied
    /// [`Token`] that does not carry issuance metadata.
    pub fn token_expires_at(&self) -> Option<HubuumDateTime> {
        self.state.token_expires_at()
    }

    #[deprecated(since = "0.3.0", note = "use token()")]
    pub fn get_token(&self) -> Result<Token, ApiError> {
        self.token()
    }

    pub(super) fn auth_mutation<T: Serialize>(
        &self,
        legacy: Endpoint,
        versioned: Endpoint,
        url_params: UrlParams,
        params: T,
    ) -> Result<(), ApiError> {
        let endpoint = if self.state.session().is_some() {
            &versioned
        } else {
            &legacy
        };
        let result = self.request_with_endpoint::<&T, serde_json::Value>(
            reqwest::Method::POST,
            endpoint,
            url_params.clone(),
            vec![],
            &params,
        );
        if self.state.session().is_none()
            && result
                .as_ref()
                .is_err_and(|error| error.is_status(reqwest::StatusCode::NOT_FOUND))
        {
            self.request_with_endpoint::<T, serde_json::Value>(
                reqwest::Method::POST,
                &versioned,
                url_params,
                vec![],
                params,
            )
            .map(|_| ())
        } else {
            result.map(|_| ())
        }
    }

    pub fn logout(self) -> Result<Client<Unauthenticated>, ApiError> {
        let result = self.auth_mutation(
            Endpoint::Logout,
            Endpoint::SessionLogout,
            UrlParams::default(),
            EmptyPostParams,
        );
        if let Some(session) = self.state.session() {
            if let Some(store) = session.store.clone() {
                let mut guard = store.lock()?;
                session.forget(guard.as_mut())?;
            } else {
                session.clear();
            }
        }
        result?;
        Ok(Client {
            runtime: self.runtime,
            state: Unauthenticated,
        })
    }

    pub fn logout_token(&self, token: &str) -> Result<(), ApiError> {
        self.auth_mutation(
            Endpoint::LogoutToken,
            Endpoint::SessionLogoutToken,
            UrlParams::default(),
            LogoutTokenRequest::new(token),
        )
    }

    pub fn logout_user<I: Into<UserId>>(&self, user_id: I) -> Result<(), ApiError> {
        let user_id = user_id.into();
        self.auth_mutation(
            Endpoint::LogoutUser,
            Endpoint::SessionLogoutUser,
            vec![(Cow::Borrowed("user_id"), user_id.to_string().into())],
            EmptyPostParams,
        )
    }

    pub fn logout_all(&self) -> Result<(), ApiError> {
        let result = self.auth_mutation(
            Endpoint::LogoutAll,
            Endpoint::SessionLogoutAll,
            UrlParams::default(),
            EmptyPostParams,
        );
        if let Some(session) = self.state.session() {
            if let Some(store) = session.store.clone() {
                let mut guard = store.lock()?;
                session.forget(guard.as_mut())?;
            } else {
                session.clear();
            }
        }
        result
    }

    /// Creation provenance and a page of recent credential sources.
    /// Requires the server's token-management authority for the owning principal.
    /// Activity is best-effort and does not change token revisions or ETags.
    pub fn token_activity(
        &self,
        principal_id: impl Into<PrincipalId>,
        token_id: impl Into<TokenId>,
        options: CredentialActivityPageOptions,
    ) -> Result<CredentialActivityResponse, ApiError> {
        let (url_params, query) =
            shared::credential_activity_request(principal_id.into(), token_id.into(), options);
        self.request_with_endpoint::<EmptyPostParams, CredentialActivityResponse>(
            reqwest::Method::GET,
            &Endpoint::PrincipalTokenActivity,
            url_params,
            query,
            EmptyPostParams,
        )?
        .ok_or_else(|| ApiError::EmptyResult("Credential activity returned no response".into()))
    }

    /// The authenticated caller's own identity and current-token metadata.
    pub fn me(&self) -> Result<MeResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, MeResponse>(
            reqwest::Method::GET,
            &Endpoint::Me,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("me returned empty result".into())))
    }

    /// The authenticated caller's own groups.
    pub fn me_groups(&self) -> Result<Vec<Handle<Group>>, ApiError> {
        Ok(self
            .me_groups_request()
            .all()?
            .into_iter()
            .map(|group| Handle::new(self.clone(), group))
            .collect())
    }

    pub fn me_groups_request(&self) -> CursorRequest<Group> {
        CursorRequest::new(self.clone(), Endpoint::MeGroups, UrlParams::default())
    }

    /// The authenticated caller's own active tokens.
    pub fn me_tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        self.me_tokens_request().all()
    }

    pub fn me_tokens_request(&self) -> CursorRequest<PrincipalTokenMetadata> {
        CursorRequest::new(self.clone(), Endpoint::MeTokens, UrlParams::default())
    }

    pub fn me_tokens_request_state(
        &self,
        state: crate::types::TokenListState,
    ) -> CursorRequest<PrincipalTokenMetadata> {
        self.me_tokens_request().query_param("state", state)
    }

    /// The authenticated caller's own effective permissions, per collection.
    pub fn me_permissions(&self) -> Result<Vec<PrincipalCollectionPermissions>, ApiError> {
        let res = self
            .request_with_endpoint::<EmptyPostParams, Vec<PrincipalCollectionPermissions>>(
                reqwest::Method::GET,
                &Endpoint::MePermissions,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            )?;
        Ok(res.unwrap_or_default())
    }

    pub fn me_permissions_request(&self) -> CursorRequest<PrincipalCollectionPermissions> {
        CursorRequest::new(self.clone(), Endpoint::MePermissions, UrlParams::default())
    }

    /// Settings belonging to the authenticated principal.
    pub fn settings(&self) -> PrincipalSettingsScope {
        PrincipalSettingsScope::new(self.clone(), Endpoint::MeSettings.path().to_string())
    }

    /// Settings belonging to an explicit principal. Cross-principal access is
    /// restricted by the server to unscoped human administrators.
    pub fn principal_settings<I>(&self, principal_id: I) -> PrincipalSettingsScope
    where
        I: Into<PrincipalId>,
    {
        let principal_id = principal_id.into();
        PrincipalSettingsScope::new(
            self.clone(),
            Endpoint::PrincipalSettings
                .path()
                .replace("{principal_id}", &principal_id.to_string()),
        )
    }

    /// Effective permissions for an explicit principal, grouped by collection
    /// and granting group.
    pub fn principal_permissions<I>(
        &self,
        principal_id: I,
    ) -> Result<Vec<PrincipalCollectionPermissions>, ApiError>
    where
        I: Into<PrincipalId>,
    {
        let principal_id = principal_id.into();
        let response = self
            .request_with_endpoint::<EmptyPostParams, Vec<PrincipalCollectionPermissions>>(
                reqwest::Method::GET,
                &Endpoint::PrincipalPermissions,
                vec![(
                    Cow::Borrowed("principal_id"),
                    principal_id.to_string().into(),
                )],
                vec![],
                EmptyPostParams,
            )?;
        Ok(response.unwrap_or_default())
    }
}

/// Fluent operations for one principal settings document.
#[derive(Debug, Clone)]
#[must_use]
pub struct PrincipalSettingsScope {
    pub(super) client: Client<Authenticated>,
    pub(super) path: String,
}

impl PrincipalSettingsScope {
    pub(super) fn new(client: Client<Authenticated>, path: String) -> Self {
        Self { client, path }
    }

    pub fn get(&self) -> Result<PrincipalSettingsResponse, ApiError> {
        Ok(self.get_revisioned()?.into_inner())
    }

    pub fn get_revisioned(&self) -> Result<Revisioned<PrincipalSettingsResponse>, ApiError> {
        let raw = self
            .client
            .raw(reqwest::Method::GET, &self.path)
            .execute()?;
        shared::decode_revisioned(raw)
    }

    /// Replace the complete settings document (`PUT`).
    pub fn replace<T>(&self, settings: &T) -> Result<PrincipalSettingsResponse, ApiError>
    where
        T: Serialize + ?Sized,
    {
        let settings = PrincipalSettings::from_serializable(settings)?;
        self.client
            .raw(reqwest::Method::PUT, &self.path)
            .json(&settings)?
            .send()
    }

    /// Apply recursive JSON Merge Patch semantics (`PATCH`). Null values remove
    /// keys, object values merge, and all other values replace existing values.
    pub fn patch<T>(&self, patch: &T) -> Result<PrincipalSettingsResponse, ApiError>
    where
        T: Serialize + ?Sized,
    {
        let patch = PrincipalSettings::from_serializable(patch)?;
        self.client
            .raw(reqwest::Method::PATCH, &self.path)
            .json(&patch)?
            .send()
    }

    /// Apply a bounded RFC 6902 JSON Patch document atomically.
    pub fn json_patch(
        &self,
        patch: &PrincipalSettingsPatchDocument,
    ) -> Result<PrincipalSettingsResponse, ApiError> {
        self.client
            .raw(reqwest::Method::PATCH, &self.path)
            .header(
                reqwest::header::CONTENT_TYPE.as_str(),
                "application/json-patch+json",
            )
            .json(patch)?
            .send()
    }

    pub fn replace_if_match<T>(
        &self,
        settings: &T,
        etag: &crate::types::EntityTag,
    ) -> Result<PrincipalSettingsResponse, ApiError>
    where
        T: Serialize + ?Sized,
    {
        let settings = PrincipalSettings::from_serializable(settings)?;
        self.client
            .raw(reqwest::Method::PUT, &self.path)
            .header(reqwest::header::IF_MATCH.as_str(), etag.as_str())
            .json(&settings)?
            .send()
    }

    pub fn patch_if_match<T>(
        &self,
        patch: &T,
        etag: &crate::types::EntityTag,
    ) -> Result<PrincipalSettingsResponse, ApiError>
    where
        T: Serialize + ?Sized,
    {
        let patch = PrincipalSettings::from_serializable(patch)?;
        self.client
            .raw(reqwest::Method::PATCH, &self.path)
            .header(reqwest::header::IF_MATCH.as_str(), etag.as_str())
            .json(&patch)?
            .send()
    }

    pub fn json_patch_if_match(
        &self,
        patch: &PrincipalSettingsPatchDocument,
        etag: &crate::types::EntityTag,
    ) -> Result<PrincipalSettingsResponse, ApiError> {
        self.client
            .raw(reqwest::Method::PATCH, &self.path)
            .header(
                reqwest::header::CONTENT_TYPE.as_str(),
                "application/json-patch+json",
            )
            .header(reqwest::header::IF_MATCH.as_str(), etag.as_str())
            .json(patch)?
            .send()
    }

    /// Reset the settings document to an empty object (`DELETE`).
    pub fn reset(&self) -> Result<(), ApiError> {
        self.client
            .raw(reqwest::Method::DELETE, &self.path)
            .send_optional::<serde_json::Value>()?;
        Ok(())
    }

    pub fn reset_if_match(&self, etag: &crate::types::EntityTag) -> Result<(), ApiError> {
        self.client
            .raw(reqwest::Method::DELETE, &self.path)
            .header(reqwest::header::IF_MATCH.as_str(), etag.as_str())
            .send_optional::<serde_json::Value>()?;
        Ok(())
    }
}

/// Explicit support for servers that require fresh credential approvals.
/// Calling ordinary mutation methods never probes this endpoint.
#[derive(Debug)]
pub struct CredentialApprovals {
    pub(super) client: Client<Authenticated>,
}

impl CredentialApprovals {
    /// Reauthenticate the acting human and bind approval to this exact operation.
    ///
    /// Requires an unscoped human bearer token and that human's current password,
    /// verified through their existing identity provider. A service-account token
    /// or a human token with scope restrictions cannot obtain approval. Existing
    /// permissions still apply, including when managing another principal.
    /// See [`CredentialOperation`] for the consumer guide and supported operations.
    ///
    /// The password is discarded after this request. Errors are never downgraded
    /// to an unapproved mutation, including an unsupported endpoint on old servers.
    pub fn approve<T: DeserializeOwned>(
        &self,
        password: impl Into<String>,
        operation: CredentialOperation<T>,
    ) -> Result<ApprovedCredentialOperation<T>, ApiError> {
        operation.validate()?;
        let request = CredentialApprovalRequest {
            password: SecretString::from(password.into()),
            operation: &operation,
        };
        let response = self
            .client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::CredentialApprovals,
                UrlParams::default(),
                vec![],
                request,
            )?
            .ok_or_else(|| {
                ApiError::EmptyResult("Credential approval returned empty result".into())
            })?;
        Ok(ApprovedCredentialOperation {
            client: self.client.clone(),
            request: shared::ApprovedCredentialRequest::new(operation, response)?,
            output: PhantomData,
        })
    }

    /// Inspect retained evidence after success or an ambiguous submission failure.
    pub fn get(
        &self,
        approval_id: impl Into<CredentialApprovalId>,
    ) -> Result<CredentialApprovalRecord, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::GET,
                &Endpoint::CredentialApprovalById,
                vec![(
                    Cow::Borrowed("approval_id"),
                    approval_id.into().to_string().into(),
                )],
                vec![],
                EmptyPostParams,
            )?
            .ok_or_else(|| {
                ApiError::EmptyResult("Credential approval record returned empty result".into())
            })
    }
}

/// A single-use approval retaining its original client, target, and exact request.
///
/// Sending consumes the handle. Token expiry is copied from the approval response
/// at full server precision, even when the original request specified an expiry.
/// Save `record().id` before sending to inspect consumption after an ambiguous error.
#[must_use = "an approved operation must be sent to perform the mutation"]
pub struct ApprovedCredentialOperation<T> {
    pub(super) client: Client<Authenticated>,
    pub(super) request: shared::ApprovedCredentialRequest,
    pub(super) output: PhantomData<fn() -> T>,
}

impl<T> std::fmt::Debug for ApprovedCredentialOperation<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovedCredentialOperation")
            .field("request", &self.request)
            .finish()
    }
}

impl<T> ApprovedCredentialOperation<T> {
    pub fn record(&self) -> &CredentialApprovalRecord {
        &self.request.response.record
    }

    /// Exact normalized token expiry selected by the server, in UTC.
    pub fn token_expires_at(&self) -> Option<HubuumDateTime> {
        self.request
            .response
            .token_expires_at
            .map(|expiry| HubuumDateTime(expiry.and_utc()))
    }
}

impl<T: DeserializeOwned> ApprovedCredentialOperation<T> {
    /// Submit once using the original bearer and approved body.
    /// Only imports with an idempotency key participate in automatic write retries.
    pub fn send(self) -> Result<T, ApiError> {
        let headers = self.request.headers();
        let raw = self.client.request_endpoint(EndpointRequest {
            method: self.request.method.clone(),
            endpoint: &self.request.endpoint,
            url_params: self.request.url_params,
            query_params: vec![],
            body: self.request.body,
            headers: &headers,
        })?;
        shared::parse_response(&self.request.method, raw.status, raw.body)?.ok_or_else(|| {
            ApiError::EmptyResult("Approved credential operation returned empty result".into())
        })
    }
}

impl ApprovedCredentialOperation<User> {
    /// Preserve the normal revision precondition when changing a user's password.
    pub fn if_match(mut self, etag: impl Into<EntityTag>) -> Self {
        self.request.headers = shared::if_match_headers(&etag.into()).into();
        self
    }
}

impl ApprovedCredentialOperation<TaskResponse> {
    /// Use the same key for retries of this exact import. A new payload requires
    /// a new approval and key. Poll the admitted task to resolve ambiguous results.
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.request.headers = vec![("Idempotency-Key", key.into())];
        self
    }
}
