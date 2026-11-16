//! Runtime administration follows the server's discovered configuration schema.
//! Provider definitions are proposed inputs, not locally verified identity proofs.
use std::fmt;

use secrecy::SecretString;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{
    AuthenticationProviderId, AuthenticationProviderKind, HubuumDateTime, ResourceRevision,
    SecurityCandidateId, SecurityVerificationReceipt,
};
use crate::ApiError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecuritySettingsGroup {
    Authentication,
    Authorization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityConfigurationSource {
    Runtime,
    Deployment,
}

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum CredentialInput {
    Keep,
    Clear,
    Reference {
        alias: String,
    },
    Replace {
        #[serde(serialize_with = "super::auth::serialize_secret")]
        value: SecretString,
    },
}

/// Write-only credential action. Debug never returns a secret or its alias.
#[derive(Serialize)]
#[serde(transparent)]
pub struct ProviderCredentialInput(CredentialInput);

impl ProviderCredentialInput {
    pub fn keep() -> Self {
        Self(CredentialInput::Keep)
    }
    pub fn clear() -> Self {
        Self(CredentialInput::Clear)
    }
    pub fn reference(alias: impl Into<String>) -> Result<Self, ApiError> {
        let alias = alias.into();
        if alias.is_empty()
            || alias.len() > 128
            || !alias
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
        {
            return Err(ApiError::InvalidSecurityConfiguration);
        }
        Ok(Self(CredentialInput::Reference { alias }))
    }
    pub fn replace(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ApiError::InvalidSecurityConfiguration);
        }
        Ok(Self(CredentialInput::Replace {
            value: SecretString::from(value),
        }))
    }
}

impl fmt::Debug for ProviderCredentialInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderCredentialInput(<redacted>)")
    }
}

enum ConfigurationInput {
    Ldap {
        fields: Map<String, Value>,
        password: LdapPasswordInput,
    },
    Oidc {
        fields: Map<String, Value>,
        credential: ProviderCredentialInput,
    },
    Oauth {
        fields: Map<String, Value>,
        credential: ProviderCredentialInput,
    },
}

/// Dynamic definition fields follow the server's JSON Schema. The provider kind
/// and write-only credential action remain typed. Full configuration, endpoint
/// policy, admission and membership validation belongs to candidate creation and
/// real server-owned verification; construction does not activate a provider.
pub struct ProviderConfigurationInput(ConfigurationInput);

enum LdapPasswordInput {
    Keep,
    Clear,
    Replace(SecretString),
}

fn fields(value: Value) -> Result<Map<String, Value>, ApiError> {
    let Value::Object(fields) = value else {
        return Err(ApiError::InvalidSecurityConfiguration);
    };
    if [
        "credential",
        "protected_credential",
        "bind_password",
        "runtime_bind_password_envelope",
    ]
    .iter()
    .any(|key| fields.contains_key(*key))
    {
        return Err(ApiError::InvalidSecurityConfiguration);
    }
    Ok(fields)
}

fn https_endpoint(value: Option<&Value>) -> Result<(), ApiError> {
    endpoint(value, &["https"])
}

fn endpoint(value: Option<&Value>, schemes: &[&str]) -> Result<(), ApiError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or(ApiError::InvalidSecurityConfiguration)?;
    let uri = url::Url::parse(value).map_err(|_| ApiError::InvalidSecurityConfiguration)?;
    if value.len() > 2048
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
        || !schemes.contains(&uri.scheme())
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.query().is_some()
        || uri.fragment().is_some()
    {
        return Err(ApiError::InvalidSecurityConfiguration);
    }
    Ok(())
}

impl ProviderConfigurationInput {
    /// LDAP definition fields omit bind_password; supply it separately so its
    /// representation stays redacted. A deployment secret reference may instead
    /// be supplied in the schema-owned bind_password_ref field.
    pub fn ldap(definition: Value, bind_password: Option<String>) -> Result<Self, ApiError> {
        let fields = fields(definition)?;
        endpoint(fields.get("url"), &["ldap", "ldaps"])?;
        if bind_password.as_ref().is_some_and(String::is_empty)
            || (bind_password.is_some()
                && fields
                    .get("bind_password_ref")
                    .is_some_and(|v| !v.is_null()))
        {
            return Err(ApiError::InvalidSecurityConfiguration);
        }
        Ok(Self(ConfigurationInput::Ldap {
            fields,
            password: bind_password.map_or(LdapPasswordInput::Keep, |value| {
                LdapPasswordInput::Replace(SecretString::from(value))
            }),
        }))
    }

    /// Omission preserves an existing encrypted LDAP password. Explicit clearing
    /// sends null, including when switching to a supplied bind_password_ref.
    pub fn clear_ldap_bind_password(mut self) -> Result<Self, ApiError> {
        let ConfigurationInput::Ldap { password, .. } = &mut self.0 else {
            return Err(ApiError::InvalidSecurityConfiguration);
        };
        *password = LdapPasswordInput::Clear;
        Ok(self)
    }

    pub fn oidc(definition: Value, credential: ProviderCredentialInput) -> Result<Self, ApiError> {
        let fields = fields(definition)?;
        https_endpoint(fields.get("issuer"))?;
        Ok(Self(ConfigurationInput::Oidc { fields, credential }))
    }

    pub fn oauth(definition: Value, credential: ProviderCredentialInput) -> Result<Self, ApiError> {
        let fields = fields(definition)?;
        for key in [
            "authorization_endpoint",
            "token_endpoint",
            "profile_endpoint",
        ] {
            https_endpoint(fields.get(key))?;
        }
        Ok(Self(ConfigurationInput::Oauth { fields, credential }))
    }

    fn kind(&self) -> AuthenticationProviderKind {
        match self.0 {
            ConfigurationInput::Ldap { .. } => AuthenticationProviderKind::Ldap,
            ConfigurationInput::Oidc { .. } => AuthenticationProviderKind::Oidc,
            ConfigurationInput::Oauth { .. } => AuthenticationProviderKind::Oauth,
        }
    }
}

impl fmt::Debug for ProviderConfigurationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderConfigurationInput")
            .field("kind", &self.kind())
            .field("definition", &"<redacted>")
            .finish()
    }
}

impl Serialize for ProviderConfigurationInput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (fields, password, credential) = match &self.0 {
            ConfigurationInput::Ldap { fields, password } => (fields, Some(password), None),
            ConfigurationInput::Oidc { fields, credential }
            | ConfigurationInput::Oauth { fields, credential } => (fields, None, Some(credential)),
        };
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in fields {
            map.serialize_entry(key, value)?;
        }
        if let Some(LdapPasswordInput::Replace(password)) = password {
            #[derive(Serialize)]
            #[serde(transparent)]
            struct Password<'a>(
                #[serde(serialize_with = "super::auth::serialize_secret")] &'a SecretString,
            );
            map.serialize_entry("bind_password", &Password(password))?;
        }
        if matches!(password, Some(LdapPasswordInput::Clear)) {
            map.serialize_entry("bind_password", &Value::Null)?;
        }
        if let Some(credential) = credential {
            map.serialize_entry("credential", credential)?;
        }
        map.end()
    }
}

/// A complete desired provider selection is submitted in each candidate. Omitted
/// providers are not silently retained. Existing IDs and namespaces are immutable.
#[derive(Debug, Serialize)]
pub struct AuthenticationProviderUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_id: Option<AuthenticationProviderId>,
    name: String,
    source: SecurityConfigurationSource,
    kind: AuthenticationProviderKind,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    configuration: Option<ProviderConfigurationInput>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    adopt_deployment: bool,
}

impl AuthenticationProviderUpdate {
    pub fn runtime(
        name: impl Into<String>,
        configuration: ProviderConfigurationInput,
    ) -> Result<Self, ApiError> {
        let name = provider_name(name.into())?;
        Ok(Self {
            provider_id: None,
            name,
            source: SecurityConfigurationSource::Runtime,
            kind: configuration.kind(),
            enabled: true,
            configuration: Some(configuration),
            adopt_deployment: false,
        })
    }

    pub fn deployment_ldap(name: impl Into<String>) -> Result<Self, ApiError> {
        Ok(Self {
            provider_id: None,
            name: provider_name(name.into())?,
            source: SecurityConfigurationSource::Deployment,
            kind: AuthenticationProviderKind::Ldap,
            enabled: true,
            configuration: None,
            adopt_deployment: false,
        })
    }

    pub fn existing(mut self, id: AuthenticationProviderId) -> Result<Self, ApiError> {
        if id == AuthenticationProviderId::local() {
            return Err(ApiError::InvalidSecurityConfiguration);
        }
        self.provider_id = Some(id);
        Ok(self)
    }
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
    pub fn adopt_deployment(mut self) -> Result<Self, ApiError> {
        if self.kind != AuthenticationProviderKind::Ldap
            || self.source != SecurityConfigurationSource::Runtime
        {
            return Err(ApiError::InvalidSecurityConfiguration);
        }
        self.adopt_deployment = true;
        Ok(self)
    }
}

fn provider_name(name: String) -> Result<String, ApiError> {
    if name.trim().is_empty()
        || name.len() > 255
        || name == "local"
        || name.chars().any(char::is_control)
    {
        return Err(ApiError::InvalidSecurityConfiguration);
    }
    Ok(name)
}

#[derive(Debug, Serialize)]
#[serde(tag = "group", rename_all = "snake_case")]
enum CandidateRequest {
    Authentication {
        expected_revision: ResourceRevision,
        providers: Vec<AuthenticationProviderUpdate>,
        release_ownership: bool,
    },
    Authorization {
        expected_revision: ResourceRevision,
        backend: RuntimeAuthorizationBackend,
        source: SecurityConfigurationSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        connection: Option<RuntimeAuthorizationConnection>,
        release_ownership: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct SecurityCandidateRequest(CandidateRequest);

impl SecurityCandidateRequest {
    pub fn authentication(
        expected_revision: ResourceRevision,
        providers: Vec<AuthenticationProviderUpdate>,
    ) -> Self {
        Self(CandidateRequest::Authentication {
            expected_revision,
            providers,
            release_ownership: false,
        })
    }
    pub fn local_authorization(expected_revision: ResourceRevision) -> Self {
        Self(CandidateRequest::Authorization {
            expected_revision,
            backend: RuntimeAuthorizationBackend::Local,
            source: SecurityConfigurationSource::Runtime,
            connection: None,
            release_ownership: false,
        })
    }
    pub fn runtime_authorization(
        expected_revision: ResourceRevision,
        connection: RuntimeAuthorizationConnection,
    ) -> Self {
        Self(CandidateRequest::Authorization {
            expected_revision,
            backend: RuntimeAuthorizationBackend::Treetop,
            source: SecurityConfigurationSource::Runtime,
            connection: Some(connection),
            release_ownership: false,
        })
    }
    pub fn deployment_authorization(
        expected_revision: ResourceRevision,
        backend: RuntimeAuthorizationBackend,
    ) -> Self {
        Self(CandidateRequest::Authorization {
            expected_revision,
            backend,
            source: SecurityConfigurationSource::Deployment,
            connection: None,
            release_ownership: false,
        })
    }
    pub fn release_ownership(mut self) -> Self {
        match &mut self.0 {
            CandidateRequest::Authentication {
                release_ownership, ..
            }
            | CandidateRequest::Authorization {
                release_ownership, ..
            } => *release_ownership = true,
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAuthorizationBackend {
    Local,
    Treetop,
}

#[derive(Debug, Serialize)]
pub struct RuntimeAuthorizationConnection {
    url: String,
    connect_timeout_ms: u64,
    request_timeout_ms: u64,
    trust_profile_id: String,
}

impl RuntimeAuthorizationConnection {
    pub fn new(
        url: impl Into<String>,
        trust_profile_id: impl Into<String>,
    ) -> Result<Self, ApiError> {
        let url = url.into();
        https_endpoint(Some(&Value::String(url.clone())))?;
        let trust_profile_id = trust_profile_id.into();
        if !["system", "deployment"].contains(&trust_profile_id.as_str()) {
            return Err(ApiError::InvalidSecurityConfiguration);
        }
        Ok(Self {
            url,
            trust_profile_id,
            connect_timeout_ms: 1000,
            request_timeout_ms: 1000,
        })
    }
    pub fn timeouts(mut self, connect_ms: u64, request_ms: u64) -> Result<Self, ApiError> {
        if connect_ms == 0 || request_ms < connect_ms || request_ms > 30_000 {
            return Err(ApiError::InvalidSecurityConfiguration);
        }
        self.connect_timeout_ms = connect_ms;
        self.request_timeout_ms = request_ms;
        Ok(self)
    }
}

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct SecurityCandidateReport {
    pub id: SecurityCandidateId,
    pub group: SecuritySettingsGroup,
    pub base_revision: ResourceRevision,
    pub expires_at: HubuumDateTime,
    pub checks: Vec<SecurityCandidateCheck>,
    pub state: SecurityCandidateState,
    pub verification_receipt: Option<SecurityVerificationReceipt>,
    pub providers: Vec<SecurityCandidateProvider>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityCandidateState {
    Unverified,
    Verified,
    Failed,
    Expired,
    Activated,
}

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct SecurityCandidateCheck {
    pub kind: String,
    pub status: String,
    pub provider_id: Option<AuthenticationProviderId>,
    pub reason: String,
}

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct SecurityCandidateProvider {
    pub provider_id: AuthenticationProviderId,
    pub name: String,
    pub kind: AuthenticationProviderKind,
}

/// Exact revision/candidate/receipt binding. Obtain it from a verified report;
/// ordinary candidate GET responses never redisclose the activation receipt.
#[derive(Debug, Serialize)]
pub struct SecurityCandidateActivation {
    #[serde(skip)]
    pub(crate) candidate_id: SecurityCandidateId,
    #[serde(skip)]
    pub(crate) group: SecuritySettingsGroup,
    pub(crate) expected_revision: ResourceRevision,
    pub(crate) verification_receipt: SecurityVerificationReceipt,
}

impl SecurityCandidateReport {
    pub fn into_activation(self) -> Result<SecurityCandidateActivation, ApiError> {
        if self.state != SecurityCandidateState::Verified || self.expires_at.0 <= chrono::Utc::now()
        {
            return Err(ApiError::SecurityCandidateNotVerified);
        }
        Ok(SecurityCandidateActivation {
            candidate_id: self.id,
            group: self.group,
            expected_revision: self.base_revision,
            verification_receipt: self
                .verification_receipt
                .ok_or(ApiError::SecurityCandidateNotVerified)?,
        })
    }
}

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct SecurityCandidateActivated {
    pub group: SecuritySettingsGroup,
    pub revision: ResourceRevision,
    pub changed: bool,
}

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct SecurityCandidateVerification {
    pub candidate: SecurityCandidateReport,
    pub verification: SecurityCandidateVerificationPreview,
}

#[non_exhaustive]
#[derive(Deserialize)]
pub struct SecurityCandidateVerificationPreview {
    pub candidate_id: SecurityCandidateId,
    pub provider_id: AuthenticationProviderId,
    pub subject: String,
    pub admitted: bool,
    pub membership: String,
    pub groups: Vec<SecurityCandidateGroupPreview>,
    pub issued_session: bool,
    pub provisioned: bool,
}

impl fmt::Debug for SecurityCandidateVerificationPreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityCandidateVerificationPreview")
            .field("candidate_id", &self.candidate_id)
            .field("provider_id", &self.provider_id)
            .field("identity", &"<redacted>")
            .field("admitted", &self.admitted)
            .field("issued_session", &self.issued_session)
            .field("provisioned", &self.provisioned)
            .finish_non_exhaustive()
    }
}

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct SecurityCandidateGroupPreview {
    pub key: String,
    pub name: String,
}

#[derive(Serialize)]
pub struct LdapCandidateVerificationRequest {
    provider_id: AuthenticationProviderId,
    username: String,
    #[serde(serialize_with = "super::auth::serialize_secret")]
    password: SecretString,
}

impl LdapCandidateVerificationRequest {
    pub fn provider_id(&self) -> &AuthenticationProviderId {
        &self.provider_id
    }
    pub fn new(
        provider_id: AuthenticationProviderId,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ApiError> {
        let username = username.into();
        let password = password.into();
        if provider_id == AuthenticationProviderId::local()
            || username.is_empty()
            || username.len() > 255
            || password.is_empty()
            || password.len() > 4096
        {
            return Err(ApiError::InvalidSecurityConfiguration);
        }
        Ok(Self {
            provider_id,
            username,
            password: SecretString::from(password),
        })
    }
}

impl fmt::Debug for LdapCandidateVerificationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapCandidateVerificationRequest")
            .field("provider_id", &self.provider_id)
            .field("credentials", &"<redacted>")
            .finish()
    }
}
