use super::*;

pub(crate) fn credential_activity_request(
    principal_id: PrincipalId,
    token_id: TokenId,
    options: CredentialActivityPageOptions,
) -> (UrlParams, Vec<QueryFilter>) {
    (
        vec![
            (
                Cow::Borrowed("principal_id"),
                principal_id.to_string().into(),
            ),
            (Cow::Borrowed("token_id"), token_id.to_string().into()),
        ],
        vec![
            QueryFilter::raw("offset", options.offset_value().to_string()),
            QueryFilter::raw("limit", options.limit_value().to_string()),
        ],
    )
}

pub(crate) struct ApprovedCredentialRequest {
    pub method: Method,
    pub endpoint: Endpoint,
    pub url_params: UrlParams,
    pub body: Value,
    pub response: CredentialApprovalResponse,
    pub headers: Vec<(&'static str, String)>,
}

impl std::fmt::Debug for ApprovedCredentialRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovedCredentialRequest")
            .field("record", &self.response.record)
            .field("request", &"[REDACTED]")
            .finish()
    }
}

impl ApprovedCredentialRequest {
    pub(crate) fn new<T>(
        operation: CredentialOperation<T>,
        response: CredentialApprovalResponse,
    ) -> Result<Self, ApiError> {
        let secret = response.approval.expose_secret();
        if secret.len() != 69
            || !secret.starts_with("hca1.")
            || !secret.as_bytes()[5..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(ApiError::DeserializationError(
                "Invalid credential approval secret".into(),
            ));
        }
        let token_expiry = || {
            response
                .token_expires_at
                .map(|expiry| HubuumDateTime(expiry.and_utc()))
                .ok_or_else(|| {
                    ApiError::DeserializationError(
                        "Credential approval omitted token_expires_at".into(),
                    )
                })
        };
        let param = |name: &'static str, id: String| (Cow::Borrowed(name), Cow::Owned(id));
        let (method, endpoint, url_params, body) = match operation.payload {
            CredentialOperationPayload::CreateToken {
                principal_id,
                mut token,
            } => {
                token.expires_at = Some(token_expiry()?);
                (
                    Method::POST,
                    Endpoint::PrincipalTokens,
                    vec![param("principal_id", principal_id.to_string())],
                    serde_json::to_value(token)?,
                )
            }
            CredentialOperationPayload::RenewToken {
                principal_id,
                token_id,
                mut token,
            } => {
                token.expires_at = Some(token_expiry()?);
                (
                    Method::POST,
                    Endpoint::PrincipalTokenRenew,
                    vec![
                        param("principal_id", principal_id.to_string()),
                        param("token_id", token_id.to_string()),
                    ],
                    serde_json::to_value(token)?,
                )
            }
            CredentialOperationPayload::CreateUser { user } => (
                Method::POST,
                Endpoint::Users,
                vec![],
                serde_json::to_value(user)?,
            ),
            CredentialOperationPayload::UpdateUser { user_id, user } => (
                Method::PATCH,
                Endpoint::Users,
                vec![param("patch_id", user_id.to_string())],
                serde_json::to_value(user)?,
            ),
            CredentialOperationPayload::ImportCredentials { import } => (
                Method::POST,
                Endpoint::Imports,
                vec![],
                serde_json::to_value(import)?,
            ),
            CredentialOperationPayload::ConfirmRestore {
                restore_id,
                confirmation,
            } => (
                Method::POST,
                Endpoint::RestoreConfirm,
                vec![param("restore_id", restore_id.to_string())],
                serde_json::to_value(confirmation)?,
            ),
        };
        Ok(Self {
            method,
            endpoint,
            url_params,
            body,
            response,
            headers: Vec::new(),
        })
    }

    pub(crate) fn headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = self.headers.clone();
        headers.push((
            "X-Hubuum-Credential-Approval",
            self.response.approval.expose_secret().to_owned(),
        ));
        headers
    }
}
