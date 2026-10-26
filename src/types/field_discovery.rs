//! Bounded observations of authorized object data and computed selectors.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::ApiError;

/// Maximum authorized objects inspected by discovery or schema profiling (1–250).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "usize", into = "usize")]
pub struct FieldSampleLimit(usize);

impl FieldSampleLimit {
    pub const fn new(value: usize) -> Result<Self, ApiError> {
        if value >= 1 && value <= 250 {
            Ok(Self(value))
        } else {
            Err(ApiError::InvalidFieldDiscovery {
                reason: "sample limit must be between 1 and 250",
            })
        }
    }

    pub const fn get(self) -> usize {
        self.0
    }
}

impl Default for FieldSampleLimit {
    fn default() -> Self {
        Self(100)
    }
}

impl TryFrom<usize> for FieldSampleLimit {
    type Error = ApiError;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FieldSampleLimit> for usize {
    fn from(value: FieldSampleLimit) -> Self {
        value.get()
    }
}

/// Validated discovery controls. Counts always describe a bounded sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FieldDiscoveryOptions {
    limit: FieldSampleLimit,
    depth: usize,
    containers: bool,
}

impl Default for FieldDiscoveryOptions {
    fn default() -> Self {
        Self {
            limit: FieldSampleLimit::default(),
            depth: 6,
            containers: false,
        }
    }
}

impl FieldDiscoveryOptions {
    pub const fn with_sample_limit(mut self, limit: FieldSampleLimit) -> Self {
        self.limit = limit;
        self
    }

    pub const fn with_depth(mut self, depth: usize) -> Result<Self, ApiError> {
        if depth > 32 {
            return Err(ApiError::InvalidFieldDiscovery {
                reason: "depth must be between 0 and 32",
            });
        }
        self.depth = depth;
        Ok(self)
    }

    pub const fn with_containers(mut self, containers: bool) -> Self {
        self.containers = containers;
        self
    }

    pub const fn sample_limit(self) -> FieldSampleLimit {
        self.limit
    }
    pub const fn depth(self) -> usize {
        self.depth
    }
    pub const fn containers(self) -> bool {
        self.containers
    }
}

/// A property name stays distinct from traversal of every array item.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum FieldPathSegment {
    Property(String),
    ArrayItem,
    #[serde(other)]
    Unknown,
}

impl fmt::Debug for FieldPathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Property(_) => f.write_str("Property([REDACTED])"),
            Self::ArrayItem => f.write_str("ArrayItem"),
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum FieldSource {
    Data,
    SharedComputed,
    PersonalComputed,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, EnumString, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ObservedFieldType {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum FieldDiscoveryTruncation {
    SampleLimit,
    CandidateLimit,
    Depth,
    WorkLimit,
    FieldLimit,
    PathLimit,
    ResponseLimit,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredField {
    pub field: String,
    pub source: FieldSource,
    pub path: Vec<FieldPathSegment>,
    /// Repeated array items count separately.
    pub observation_count: u64,
    pub object_count: u64,
    pub types: BTreeMap<ObservedFieldType, u64>,
    /// A bounded display preview, not the original JSON value.
    pub example: Option<String>,
    pub example_truncated: bool,
    pub error_count: u64,
}

impl fmt::Debug for DiscoveredField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveredField")
            .field("field", &"[REDACTED]")
            .field("source", &self.source)
            .field("path", &"[REDACTED]")
            .field("observation_count", &self.observation_count)
            .field("object_count", &self.object_count)
            .field("types", &self.types)
            .field("example", &"[REDACTED]")
            .field("example_truncated", &self.example_truncated)
            .field("error_count", &self.error_count)
            .finish()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassFieldInventory {
    pub sampled: bool,
    pub sampled_objects: u64,
    pub effective_sample_limit: usize,
    pub max_depth: usize,
    pub include_containers: bool,
    pub truncation: Vec<FieldDiscoveryTruncation>,
    pub fields: Vec<DiscoveredField>,
}
