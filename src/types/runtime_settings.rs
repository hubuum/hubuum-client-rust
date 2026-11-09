//! Discovered runtime configuration on Hubuum server 0.0.22 and newer.
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{HubuumDateTime, PrincipalId, ResourceRevision};
use crate::ApiError;

/// The catalogue version describes the discovery protocol, not server releases.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSettingsCatalogue {
    pub schema_version: u32,
    pub groups: Vec<RuntimeSettingsDescriptor>,
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
