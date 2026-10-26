//! Sampled schema suggestions are proposals, not whole-class compatibility evidence.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::{Display, EnumString};

use crate::{ApiError, ClassId, FieldDiscoveryTruncation, FieldSampleLimit, SchemaStageRequest};

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SchemaProfilePreset {
    Strict,
    #[default]
    Balanced,
    Expansive,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaProfileRequest {
    #[serde(default)]
    preset: SchemaProfilePreset,
    #[serde(default)]
    sample_limit: FieldSampleLimit,
}

impl SchemaProfileRequest {
    pub const fn new(preset: SchemaProfilePreset, sample_limit: FieldSampleLimit) -> Self {
        Self {
            preset,
            sample_limit,
        }
    }
    pub const fn preset(&self) -> SchemaProfilePreset {
        self.preset
    }
    pub const fn sample_limit(&self) -> FieldSampleLimit {
        self.sample_limit
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ProfileSuggestionStatus {
    Candidate,
    Blocked,
    Insufficient,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaProfileReport {
    pub class_id: ClassId,
    pub sampled: bool,
    pub sampled_objects: u64,
    pub effective_sample_limit: usize,
    pub truncation: Option<FieldDiscoveryTruncation>,
    pub options: SchemaProfileRequest,
    pub status: ProfileSuggestionStatus,
    pub schema: Option<Value>,
    pub profile: Option<Value>,
    pub findings: Vec<Value>,
    pub replay: Option<Value>,
    pub sample_valid: Option<bool>,
}

impl SchemaProfileReport {
    /// Copy a reviewed, sample-valid candidate into an explicit staging request.
    /// Staging does not activate it; run whole-class impact analysis before activation.
    pub fn stage_request(&self, validate_schema: bool) -> Result<SchemaStageRequest, ApiError> {
        if self.status != ProfileSuggestionStatus::Candidate || self.sample_valid != Some(true) {
            return Err(ApiError::InvalidSchemaSuggestion {
                reason: "report has no sample-valid candidate; inspect its findings or request a new suggestion",
            });
        }
        let schema = self
            .schema
            .clone()
            .ok_or(ApiError::InvalidSchemaSuggestion {
                reason: "candidate report is missing its schema",
            })?;
        Ok(SchemaStageRequest {
            json_schema: Some(schema),
            validate_schema,
        })
    }
}

impl fmt::Debug for SchemaProfileReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaProfileReport")
            .field("class_id", &self.class_id)
            .field("sampled_objects", &self.sampled_objects)
            .field("effective_sample_limit", &self.effective_sample_limit)
            .field("truncation", &self.truncation)
            .field("options", &self.options)
            .field("status", &self.status)
            .field("sample_valid", &self.sample_valid)
            .field("schema", &"[REDACTED]")
            .field("profile", &"[REDACTED]")
            .field("findings", &"[REDACTED]")
            .field("replay", &"[REDACTED]")
            .finish()
    }
}
