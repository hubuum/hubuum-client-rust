//! Types for the remote-target subsystem (hardened outbound HTTP invocation).

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{RemoteCallResultId, TaskId};
use crate::resources::{
    ClassId, ClassRelationId, CollectionId, ObjectId, ObjectRelationId, RemoteTargetId,
};

use super::HubuumDateTime;

/// HTTP method a remote target issues against its upstream.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RemoteHttpMethod {
    #[default]
    Get,
    Post,
    Patch,
    Delete,
    #[serde(other)]
    Unknown,
}

/// Kinds of Hubuum subject a remote target may be invoked against.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTargetSubjectType {
    Collection,
    Class,
    Object,
    ClassRelation,
    ObjectRelation,
    #[serde(other)]
    Unknown,
}

/// How a remote target authenticates to its upstream. Secrets are write-only on
/// the wire; the server never echoes them back.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteAuthConfig {
    #[default]
    None,
    BearerSecret {
        #[serde(serialize_with = "super::auth::serialize_secret")]
        secret: SecretString,
    },
    BasicSecret {
        username: String,
        #[serde(serialize_with = "super::auth::serialize_secret")]
        secret: SecretString,
    },
    ApiKeySecret {
        header: String,
        #[serde(serialize_with = "super::auth::serialize_secret")]
        secret: SecretString,
    },
    #[serde(other)]
    Unknown,
}

impl RemoteAuthConfig {
    pub fn bearer(secret: impl Into<String>) -> Self {
        Self::BearerSecret {
            secret: SecretString::from(secret.into()),
        }
    }

    pub fn basic(username: impl Into<String>, secret: impl Into<String>) -> Self {
        Self::BasicSecret {
            username: username.into(),
            secret: SecretString::from(secret.into()),
        }
    }

    pub fn api_key(header: impl Into<String>, secret: impl Into<String>) -> Self {
        Self::ApiKeySecret {
            header: header.into(),
            secret: SecretString::from(secret.into()),
        }
    }
}

impl PartialEq for RemoteAuthConfig {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None) => true,
            (Self::Unknown, Self::Unknown) => true,
            (Self::BearerSecret { secret: left }, Self::BearerSecret { secret: right }) => {
                left.expose_secret() == right.expose_secret()
            }
            (
                Self::BasicSecret {
                    username: left_user,
                    secret: left_secret,
                },
                Self::BasicSecret {
                    username: right_user,
                    secret: right_secret,
                },
            ) => {
                left_user == right_user
                    && left_secret.expose_secret() == right_secret.expose_secret()
            }
            (
                Self::ApiKeySecret {
                    header: left_header,
                    secret: left_secret,
                },
                Self::ApiKeySecret {
                    header: right_header,
                    secret: right_secret,
                },
            ) => {
                left_header == right_header
                    && left_secret.expose_secret() == right_secret.expose_secret()
            }
            _ => false,
        }
    }
}

impl Eq for RemoteAuthConfig {}

impl std::fmt::Debug for RemoteAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::BearerSecret { .. } => f
                .debug_struct("BearerSecret")
                .field("secret", &"[REDACTED]")
                .finish(),
            Self::BasicSecret { username, .. } => f
                .debug_struct("BasicSecret")
                .field("username", username)
                .field("secret", &"[REDACTED]")
                .finish(),
            Self::ApiKeySecret { header, .. } => f
                .debug_struct("ApiKeySecret")
                .field("header", header)
                .field("secret", &"[REDACTED]")
                .finish(),
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}

/// The subject a remote target is invoked against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteInvocationSubject {
    Collection {
        collection_id: CollectionId,
    },
    Class {
        class_id: ClassId,
    },
    Object {
        class_id: ClassId,
        object_id: ObjectId,
    },
    ClassRelation {
        relation_id: ClassRelationId,
    },
    ObjectRelation {
        relation_id: ObjectRelationId,
    },
}

/// A configured remote target.
#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
#[non_exhaustive]
pub struct RemoteTarget {
    pub id: RemoteTargetId,
    pub collection_id: CollectionId,
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
    pub class_id: Option<ClassId>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

/// Request body to create a remote target.
#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NewRemoteTarget {
    pub collection_id: CollectionId,
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
    pub class_id: Option<ClassId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_template: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<i32>,
}

/// Mutable fields on a remote target.
#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UpdateRemoteTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<CollectionId>,
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
    pub class_id: Option<ClassId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<i32>,
}

/// Query parameters for listing remote targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RemoteTargetGet {
    pub id: Option<RemoteTargetId>,
    pub name: Option<String>,
    pub collection_id: Option<CollectionId>,
    pub enabled: Option<bool>,
}

/// Request body to invoke a remote target.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct RemoteCallResult {
    pub id: RemoteCallResultId,
    pub task_id: TaskId,
    #[serde(default)]
    pub target_id: Option<RemoteTargetId>,
    pub subject_type: String,
    pub subject_id: i32,
    pub method: RemoteHttpMethod,
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

fn redacted_if_present<T>(value: &Option<T>) -> Option<&'static str> {
    value.as_ref().map(|_| "[REDACTED]")
}

impl std::fmt::Debug for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteTarget")
            .field("id", &self.id)
            .field("collection_id", &self.collection_id)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("method", &self.method)
            .field("url_template", &"[REDACTED]")
            .field(
                "headers_template",
                &redacted_if_present(&self.headers_template),
            )
            .field("auth_config", &self.auth_config)
            .field("allowed_subject_types", &self.allowed_subject_types)
            .field("timeout_ms", &self.timeout_ms)
            .field("enabled", &self.enabled)
            .field("body_template", &redacted_if_present(&self.body_template))
            .field("class_id", &self.class_id)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl std::fmt::Debug for NewRemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewRemoteTarget")
            .field("collection_id", &self.collection_id)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("method", &self.method)
            .field("url_template", &"[REDACTED]")
            .field("allowed_subject_types", &self.allowed_subject_types)
            .field("auth_config", &self.auth_config)
            .field("body_template", &redacted_if_present(&self.body_template))
            .field("class_id", &self.class_id)
            .field("enabled", &self.enabled)
            .field(
                "headers_template",
                &redacted_if_present(&self.headers_template),
            )
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl std::fmt::Debug for UpdateRemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateRemoteTarget")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("collection_id", &self.collection_id)
            .field("method", &self.method)
            .field("url_template", &redacted_if_present(&self.url_template))
            .field(
                "headers_template",
                &redacted_if_present(&self.headers_template),
            )
            .field("auth_config", &self.auth_config)
            .field("allowed_subject_types", &self.allowed_subject_types)
            .field("body_template", &redacted_if_present(&self.body_template))
            .field("class_id", &self.class_id)
            .field("enabled", &self.enabled)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl std::fmt::Debug for RemoteTargetInvokeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteTargetInvokeRequest")
            .field("subject", &self.subject)
            .field("parameters", &redacted_if_present(&self.parameters))
            .field("body_override", &redacted_if_present(&self.body_override))
            .finish()
    }
}

impl std::fmt::Debug for RemoteCallResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteCallResult")
            .field("id", &self.id)
            .field("task_id", &self.task_id)
            .field("target_id", &self.target_id)
            .field("subject_type", &self.subject_type)
            .field("subject_id", &self.subject_id)
            .field("method", &self.method)
            .field("rendered_url", &"[REDACTED]")
            .field("response_status", &self.response_status)
            .field(
                "response_headers",
                &redacted_if_present(&self.response_headers),
            )
            .field(
                "response_body_preview",
                &redacted_if_present(&self.response_body_preview),
            )
            .field("duration_ms", &self.duration_ms)
            .field("success", &self.success)
            .field("error", &redacted_if_present(&self.error))
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn remote_call_result_preserves_the_target_id_type() {
        let result: RemoteCallResult = serde_json::from_value(json!({
            "id": 11,
            "task_id": 12,
            "target_id": 13,
            "subject_type": "object",
            "subject_id": 14,
            "method": "GET",
            "rendered_url": "https://example.invalid/resource/14",
            "response_status": 200,
            "response_headers": null,
            "response_body_preview": null,
            "duration_ms": 5,
            "success": true,
            "error": null,
            "created_at": "2026-07-11T10:00:00Z"
        }))
        .unwrap();

        assert_eq!(result.target_id, Some(RemoteTargetId::new(13)));
        assert_eq!(result.subject_id, 14);
    }

    #[test]
    fn remote_auth_debug_redacts_secrets() {
        let config = RemoteAuthConfig::basic("alice", "password");
        let debug = format!("{config:?}");

        assert!(debug.contains("alice"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("password"));
    }

    #[test]
    fn remote_request_debug_redacts_templates_and_overrides() {
        let request = NewRemoteTarget {
            url_template: "https://example.invalid?token=url-secret".into(),
            headers_template: Some(serde_json::json!({"authorization": "header-secret"})),
            body_template: Some("body-secret".into()),
            auth_config: Some(RemoteAuthConfig::bearer("auth-secret")),
            ..Default::default()
        };
        let invocation = RemoteTargetInvokeRequest::new(RemoteInvocationSubject::Collection {
            collection_id: CollectionId::new(1),
        })
        .parameters(serde_json::json!({"secret": "parameter-secret"}))
        .body_override(serde_json::json!({"secret": "override-secret"}));
        let debug = format!("{request:?} {invocation:?}");

        for secret in [
            "url-secret",
            "header-secret",
            "body-secret",
            "auth-secret",
            "parameter-secret",
            "override-secret",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn remote_result_debug_redacts_response_and_error_details() {
        let result: RemoteCallResult = serde_json::from_value(json!({
            "id": 11,
            "task_id": 12,
            "target_id": 13,
            "subject_type": "object",
            "subject_id": 14,
            "method": "GET",
            "rendered_url": "https://example.invalid/resource/14?token=url-secret",
            "response_status": 502,
            "response_headers": {"authorization": "header-secret"},
            "response_body_preview": "body-secret",
            "duration_ms": 5,
            "success": false,
            "error": "upstream rejected bearer error-secret",
            "created_at": "2026-07-11T10:00:00Z"
        }))
        .unwrap();

        let debug = format!("{result:?}");
        for secret in ["url-secret", "header-secret", "body-secret", "error-secret"] {
            assert!(!debug.contains(secret));
        }
        assert_eq!(
            result.error.as_deref(),
            Some("upstream rejected bearer error-secret")
        );
    }
}
