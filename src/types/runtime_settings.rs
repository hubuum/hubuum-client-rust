//! Discovered runtime configuration on Hubuum server 0.0.22 and newer.
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{
    AuthenticationProviderId, AuthenticationProviderKind, HubuumDateTime, PrincipalId,
    ResourceRevision, SecurityConfigurationSource,
};
use crate::ApiError;

/// The catalogue version describes the discovery protocol, not server releases.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSettingsCatalogue {
    pub schema_version: u32,
    pub groups: Vec<RuntimeSettingsDescriptor>,
    /// Absent on the declared released-server baseline. Its presence describes
    /// external-authentication support on the accepted project candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<RuntimeSecurityCapabilities>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSecurityCapabilities {
    pub candidate_endpoint: String,
    pub configurable_provider_kinds: Vec<AuthenticationProviderKind>,
    pub activatable_provider_kinds: Vec<AuthenticationProviderKind>,
    pub deployment_locked_providers: Vec<String>,
    pub private_targets_allowed: bool,
    pub replacement_credentials_available: bool,
    pub candidate_lifetime_seconds: i64,
    pub ldap_verification_timeout_seconds: u64,
    pub treetop_connect_timeout_ceiling_ms: u64,
    pub treetop_request_timeout_ceiling_ms: u64,
    pub trust_profiles: Vec<String>,
}

#[non_exhaustive]
#[derive(Clone, Deserialize)]
pub struct RuntimeAuthenticationProviderState {
    pub provider_id: Option<AuthenticationProviderId>,
    pub kind: AuthenticationProviderKind,
    pub name: String,
    pub source: SecurityConfigurationSource,
    pub enabled: bool,
    pub definition_mutable: bool,
    pub runtime_definition: Option<Map<String, Value>>,
    pub credential_configured: bool,
    pub available: bool,
}

impl fmt::Debug for RuntimeAuthenticationProviderState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeAuthenticationProviderState")
            .field("provider_id", &self.provider_id)
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("source", &self.source)
            .field("enabled", &self.enabled)
            .field("definition_mutable", &self.definition_mutable)
            .field("credential_configured", &self.credential_configured)
            .field("runtime_definition", &"<redacted>")
            .field("available", &self.available)
            .finish()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeSettingsReplicaStatus {
    pub status: RuntimeSettingsApplicationStatus,
    pub reconcile_interval_seconds: u64,
    pub applied_at: Option<HubuumDateTime>,
    pub last_refresh_attempt_at: Option<HubuumDateTime>,
    pub last_refresh_failure_at: Option<HubuumDateTime>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSettingsApplicationStatus {
    NotLoaded,
    Current,
    Stale,
}

/// Effective provider state, optimistic revision, deployment ownership and this
/// replica's application status. Definitions are read-only, redacted reports;
/// construct explicit provider updates for writes instead of copying this state.
pub struct EffectiveAuthenticationSettings {
    group: RuntimeSettingsGroupState,
    providers: Vec<RuntimeAuthenticationProviderState>,
    replica: RuntimeSettingsReplicaStatus,
}

impl EffectiveAuthenticationSettings {
    #[cfg(any(feature = "async", feature = "blocking"))]
    pub(crate) fn from_state(group: RuntimeSettingsGroupState) -> Result<Self, ApiError> {
        if group.group != "authentication" {
            return Err(ApiError::InvalidAuthenticationInteraction);
        }
        let providers = serde_json::from_value(
            group
                .effective
                .get("providers")
                .cloned()
                .ok_or(ApiError::InvalidAuthenticationInteraction)?,
        )
        .map_err(|_| ApiError::InvalidAuthenticationInteraction)?;
        let replica = serde_json::from_value(group.replica.clone())
            .map_err(|_| ApiError::InvalidAuthenticationInteraction)?;
        Ok(Self {
            group,
            providers,
            replica,
        })
    }
    pub fn group(&self) -> &RuntimeSettingsGroupState {
        &self.group
    }
    pub fn providers(&self) -> &[RuntimeAuthenticationProviderState] {
        &self.providers
    }
    pub fn replica(&self) -> &RuntimeSettingsReplicaStatus {
        &self.replica
    }
    pub fn expected_revision(&self) -> ResourceRevision {
        self.group.revision.unwrap_or(ResourceRevision::INITIAL)
    }
}

impl fmt::Debug for EffectiveAuthenticationSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EffectiveAuthenticationSettings")
            .field("revision", &self.group.revision)
            .field("source", &self.group.source)
            .field("providers", &self.providers)
            .field("replica", &self.replica)
            .finish_non_exhaustive()
    }
}

/// Group names and JSON Schema fields are intentionally open-ended.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSettingsDescriptor {
    pub key: String,
    pub title: String,
    pub description: String,
    pub schema: Value,
    pub patch_supported: bool,
    pub requires_local_admin: bool,
    pub takes_effect: String,
    pub read_only_reason: Option<String>,
}

/// Requested and applied values of one group. Application status belongs to
/// the responding replica; a successful commit is not a cluster acknowledgement.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSettingsGroupState {
    pub group: String,
    pub source: String,
    pub revision: Option<ResourceRevision>,
    pub changed_at: Option<HubuumDateTime>,
    pub changed_by: Option<PrincipalId>,
    pub mutable: bool,
    pub restart_required: bool,
    pub takes_effect: String,
    pub replica: Value,
    pub effective: Map<String, Value>,
    pub runtime: Option<Map<String, Value>>,
    pub deployment: Option<Map<String, Value>>,
    pub constrained_by_ceiling: bool,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSettingsUpdateResponse {
    pub group: String,
    pub committed_revision: ResourceRevision,
    pub changed: bool,
    pub applied_by_responding_replica: bool,
    pub settings: Map<String, Value>,
}

/// Only explicitly edited fields are sent. Server validation remains authoritative.
#[derive(Clone, Serialize)]
pub struct RuntimeSettingsPatch {
    expected_revision: ResourceRevision,
    changes: Map<String, Value>,
}

impl RuntimeSettingsPatch {
    pub fn new(
        expected_revision: ResourceRevision,
        changes: Map<String, Value>,
    ) -> Result<Self, ApiError> {
        if changes.is_empty()
            || changes.values().any(Value::is_null)
            || changes.contains_key("expected_revision")
        {
            return Err(ApiError::InvalidRuntimeSettingsPatch);
        }
        Ok(Self {
            expected_revision,
            changes,
        })
    }

    pub fn expected_revision(&self) -> ResourceRevision {
        self.expected_revision
    }
    pub fn changes(&self) -> &Map<String, Value> {
        &self.changes
    }
}

impl fmt::Debug for RuntimeSettingsPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeSettingsPatch")
            .field("expected_revision", &self.expected_revision)
            .field("changes", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[rstest::rstest]
    #[case(json!({}))]
    #[case(json!({"field": null}))]
    #[case(json!({"expected_revision": 2}))]
    fn invalid_changes_are_rejected(#[case] value: Value) {
        assert!(
            RuntimeSettingsPatch::new(
                ResourceRevision::INITIAL,
                serde_json::from_value(value).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn patch_debug_hides_setting_values() {
        let patch = RuntimeSettingsPatch::new(
            ResourceRevision::INITIAL,
            serde_json::from_value(json!({"future_secret": "private-value"})).unwrap(),
        )
        .unwrap();
        assert!(!format!("{patch:?}").contains("private-value"));
    }
}
