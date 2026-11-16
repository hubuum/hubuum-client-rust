use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{Authenticated, Client, shared};
use crate::endpoints::authentication;
use crate::{
    ApiError, EffectiveAuthenticationSettings, LdapCandidateVerificationRequest,
    SecurityCandidateId, SecurityCandidateReport, SecurityCandidateRequest,
    SecurityCandidateVerification,
};

impl Client<Authenticated> {
    async fn security_request<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: &B,
    ) -> Result<R, ApiError> {
        let token = self.ready_token().await?;
        let response = self
            .authentication_http(
                method.clone(),
                path,
                body,
                &[("Authorization", format!("Bearer {}", token.as_str()))],
            )
            .await?;
        let body = self.authentication_body(&method, path, response)?;
        shared::decode_json_body(&body)
    }

    /// Create a non-live candidate using the exact current group revision.
    /// All schema, deployment-lock, egress and credential checks remain on Hubuum.
    /// This mutation is sent once; errors never activate or downgrade policy.
    pub async fn create_security_candidate(
        &self,
        request: SecurityCandidateRequest,
    ) -> Result<SecurityCandidateReport, ApiError> {
        self.security_request(Method::POST, authentication::CANDIDATES, &request)
            .await
    }

    /// Read sanitized state. The server does not redisclose activation receipts.
    pub async fn security_candidate(
        &self,
        id: &SecurityCandidateId,
    ) -> Result<SecurityCandidateReport, ApiError> {
        self.security_request(Method::GET, &authentication::candidate(id), &())
            .await
    }

    pub async fn verify_ldap_security_candidate(
        &self,
        id: &SecurityCandidateId,
        request: LdapCandidateVerificationRequest,
    ) -> Result<SecurityCandidateVerification, ApiError> {
        let result: SecurityCandidateVerification = self
            .security_request(Method::POST, &authentication::verify_ldap(id), &request)
            .await?;
        if &result.candidate.id != id
            || &result.verification.candidate_id != id
            || &result.verification.provider_id != request.provider_id()
            || result.verification.issued_session
            || result.verification.provisioned
        {
            return Err(ApiError::InvalidAuthenticationInteraction);
        }
        Ok(result)
    }

    pub async fn effective_authentication_settings(
        &self,
    ) -> Result<EffectiveAuthenticationSettings, ApiError> {
        EffectiveAuthenticationSettings::from_state(
            self.runtime_settings_group("authentication").await?,
        )
    }
}
