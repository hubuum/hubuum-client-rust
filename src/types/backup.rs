use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};

use super::{HubuumDateTime, PrincipalId, RestoreId};

/// Backup document version produced and accepted by Hubuum server v0.0.2.
pub const CURRENT_BACKUP_VERSION: i32 = 3;

/// Exact phrase required to confirm a destructive full-system restore.
pub const RESTORE_CONFIRMATION_PHRASE: &str = "REPLACE ALL HUBUUM DATA";

const fn include_history_by_default() -> bool {
    true
}

/// Options for starting a full-system backup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupRequest {
    #[serde(default = "include_history_by_default")]
    pub include_history: bool,
}

impl BackupRequest {
    pub const fn new() -> Self {
        Self {
            include_history: true,
        }
    }

    pub const fn include_history(mut self, include_history: bool) -> Self {
        self.include_history = include_history;
        self
    }
}

impl Default for BackupRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BackupState {
    pub sections: BTreeMap<String, Vec<serde_json::Value>>,
}

impl std::fmt::Debug for BackupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupState")
            .field("section_names", &self.sections.keys().collect::<Vec<_>>())
            .field(
                "row_count",
                &self.sections.values().map(Vec::len).sum::<usize>(),
            )
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BackupHistory {
    pub sections: BTreeMap<String, Vec<serde_json::Value>>,
}

impl std::fmt::Debug for BackupHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupHistory")
            .field("section_names", &self.sections.keys().collect::<Vec<_>>())
            .field(
                "row_count",
                &self.sections.values().map(Vec::len).sum::<usize>(),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BackupManifest {
    pub item_counts: BTreeMap<String, i64>,
    pub exclusions: Vec<String>,
}

/// A privileged full-system backup artifact.
///
/// Its custom `Debug` implementation never prints row contents because those
/// can contain credentials and other sensitive administrative data.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackupDocument {
    pub backup_version: i32,
    #[serde(serialize_with = "serialize_backup_datetime")]
    pub created_at: HubuumDateTime,
    pub source_version: String,
    pub state: BackupState,
    pub history: Option<BackupHistory>,
    pub manifest: BackupManifest,
}

fn serialize_backup_datetime<S>(value: &HubuumDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(
        &value
            .0
            .naive_utc()
            .format("%Y-%m-%dT%H:%M:%S%.f")
            .to_string(),
    )
}

impl std::fmt::Debug for BackupDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupDocument")
            .field("backup_version", &self.backup_version)
            .field("created_at", &self.created_at)
            .field("source_version", &self.source_version)
            .field("state", &self.state)
            .field("history", &self.history)
            .field("manifest", &self.manifest)
            .finish()
    }
}

impl BackupDocument {
    pub const fn has_supported_version(&self) -> bool {
        self.backup_version == CURRENT_BACKUP_VERSION
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestoreJobStatus {
    Validated,
    Confirmed,
    Succeeded,
    Failed,
    Expired,
    #[serde(other)]
    Unknown,
}

impl RestoreJobStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Expired)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreValidationSummary {
    pub backup_version: i32,
    pub source_version: String,
    pub includes_history: bool,
    pub total_items: i64,
}

/// One-time restore capability returned when a document is staged.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RestoreCapability(
    #[serde(serialize_with = "super::auth::serialize_secret")] SecretString,
);

impl RestoreCapability {
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::from(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }
}

impl AsRef<str> for RestoreCapability {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for RestoreCapability {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for RestoreCapability {}

impl std::fmt::Debug for RestoreCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RestoreCapability")
            .field(&"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreStageResponse {
    pub id: RestoreId,
    pub status: RestoreJobStatus,
    pub requested_by: Option<PrincipalId>,
    pub requested_by_identity_scope: String,
    pub requested_by_name: String,
    pub sha256: String,
    pub byte_size: i64,
    pub expires_at: HubuumDateTime,
    pub error: Option<String>,
    pub confirmed_at: Option<HubuumDateTime>,
    pub started_at: Option<HubuumDateTime>,
    pub finished_at: Option<HubuumDateTime>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    pub validation: RestoreValidationSummary,
    pub restore_capability: Option<RestoreCapability>,
}

impl std::fmt::Debug for RestoreStageResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreStageResponse")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("requested_by", &self.requested_by)
            .field(
                "requested_by_identity_scope",
                &self.requested_by_identity_scope,
            )
            .field("requested_by_name", &self.requested_by_name)
            .field("sha256", &self.sha256)
            .field("byte_size", &self.byte_size)
            .field("expires_at", &self.expires_at)
            .field("error", &self.error)
            .field("confirmed_at", &self.confirmed_at)
            .field("started_at", &self.started_at)
            .field("finished_at", &self.finished_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("validation", &self.validation)
            .field(
                "restore_capability",
                &self.restore_capability.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Confirmation input for the destructive restore operation.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreConfirmRequest {
    pub restore_capability: RestoreCapability,
    pub sha256: String,
    pub confirmation: String,
}

impl RestoreConfirmRequest {
    pub fn new(restore_capability: RestoreCapability, sha256: impl Into<String>) -> Self {
        Self {
            restore_capability,
            sha256: sha256.into(),
            confirmation: RESTORE_CONFIRMATION_PHRASE.to_string(),
        }
    }
}

impl std::fmt::Debug for RestoreConfirmRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreConfirmRequest")
            .field("restore_capability", &"[REDACTED]")
            .field("sha256", &self.sha256)
            .field("confirmation", &self.confirmation)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_request_defaults_to_history() {
        let request: BackupRequest = serde_json::from_str("{}").unwrap();
        assert!(request.include_history);
        assert!(BackupRequest::default().include_history);
    }

    #[test]
    fn restore_secrets_and_backup_rows_are_redacted() {
        let capability = RestoreCapability::new("one-time-secret");
        assert!(!format!("{capability:?}").contains("one-time-secret"));

        let request = RestoreConfirmRequest::new(capability, "abc123");
        assert!(!format!("{request:?}").contains("one-time-secret"));

        let state = BackupState {
            sections: BTreeMap::from([(
                "principals".to_string(),
                vec![serde_json::json!({"password_hash": "sensitive-value"})],
            )]),
        };
        assert!(!format!("{state:?}").contains("sensitive-value"));
    }

    #[test]
    fn restore_confirmation_uses_server_phrase() {
        let request = RestoreConfirmRequest::new(RestoreCapability::new("secret"), "abc123");
        assert_eq!(request.confirmation, RESTORE_CONFIRMATION_PHRASE);
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "restore_capability": "secret",
                "sha256": "abc123",
                "confirmation": "REPLACE ALL HUBUUM DATA"
            })
        );
    }

    #[test]
    fn backup_document_serializes_a_restore_compatible_naive_timestamp() {
        let document: BackupDocument = serde_json::from_value(serde_json::json!({
            "backup_version": 3,
            "created_at": "2024-01-01T01:02:03.456789",
            "source_version": "0.0.2",
            "state": { "sections": {} },
            "history": null,
            "manifest": { "item_counts": {}, "exclusions": [] }
        }))
        .unwrap();

        assert_eq!(
            serde_json::to_value(document).unwrap()["created_at"],
            "2024-01-01T01:02:03.456789"
        );
    }
}
