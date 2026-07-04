//! Types for the remote-target subsystem (hardened outbound HTTP invocation).

use serde::{Deserialize, Serialize};

use super::HubuumDateTime;

/// HTTP method a remote target issues against its upstream.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RemoteHttpMethod {
    #[default]
    Get,
    Post,
    Patch,
    Delete,
}

/// Kinds of Hubuum subject a remote target may be invoked against.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTargetSubjectType {
    Namespace,
    Class,
    Object,
    ClassRelation,
    ObjectRelation,
}

/// How a remote target authenticates to its upstream. Secrets are write-only on
/// the wire; the server never echoes them back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteAuthConfig {
    #[default]
    None,
    BearerSecret {
        secret: String,
    },
    BasicSecret {
        username: String,
        secret: String,
    },
    ApiKeySecret {
        header: String,
        secret: String,
    },
}

/// The subject a remote target is invoked against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteInvocationSubject {
    Namespace { namespace_id: i32 },
    Class { class_id: i32 },
    Object { class_id: i32, object_id: i32 },
    ClassRelation { relation_id: i32 },
    ObjectRelation { relation_id: i32 },
}

/// A configured remote target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RemoteTarget {
    pub id: i32,
    pub namespace_id: i32,
    pub name: String,
    pub description: String,
    pub method: RemoteHttpMethod,
    pub url_template: String,
    #[serde(default)]
    pub headers_template: Option<serde_json::Value>,
    pub auth_config: RemoteAuthConfig,
    pub allowed_subject_types: Vec<RemoteTargetSubjectType>,
    pub timeout_ms: i32,
    pub enabled: bool,
    #[serde(default)]
    pub body_template: Option<String>,
    #[serde(default)]
    pub class_id: Option<i32>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

/// Request body to create a remote target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NewRemoteTarget {
    pub namespace_id: i32,
    pub name: String,
    pub description: String,
    pub method: RemoteHttpMethod,
    pub url_template: String,
    pub allowed_subject_types: Vec<RemoteTargetSubjectType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_config: Option<RemoteAuthConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_template: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<i32>,
}

/// Mutable fields on a remote target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UpdateRemoteTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<RemoteHttpMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_template: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_config: Option<RemoteAuthConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_subject_types: Option<Vec<RemoteTargetSubjectType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<i32>,
}

/// Query parameters for listing remote targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RemoteTargetGet {
    pub id: Option<i32>,
    pub name: Option<String>,
    pub namespace_id: Option<i32>,
    pub enabled: Option<bool>,
}

/// Request body to invoke a remote target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteTargetInvokeRequest {
    pub subject: RemoteInvocationSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_override: Option<serde_json::Value>,
}

impl RemoteTargetInvokeRequest {
    pub fn new(subject: RemoteInvocationSubject) -> Self {
        Self {
            subject,
            parameters: None,
            body_override: None,
        }
    }

    pub fn parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = Some(parameters);
        self
    }

    pub fn body_override(mut self, body_override: serde_json::Value) -> Self {
        self.body_override = Some(body_override);
        self
    }
}

/// The recorded outcome of a single remote invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteCallResult {
    pub id: i32,
    pub task_id: i32,
    #[serde(default)]
    pub target_id: Option<i32>,
    pub subject_type: String,
    pub subject_id: i32,
    pub method: String,
    pub rendered_url: String,
    #[serde(default)]
    pub response_status: Option<i32>,
    #[serde(default)]
    pub response_headers: Option<serde_json::Value>,
    #[serde(default)]
    pub response_body_preview: Option<String>,
    pub duration_ms: i32,
    pub success: bool,
    #[serde(default)]
    pub error: Option<String>,
    pub created_at: HubuumDateTime,
}
