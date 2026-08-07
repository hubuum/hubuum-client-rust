use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::ResourceRevision;
use crate::ApiError;

/// An object-only JSON document containing a principal's local preferences.
///
/// Values below the root may be any JSON type. Construction and deserialization
/// reject scalar, array, and null roots before a request is sent.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
#[cfg_attr(feature = "typed-schemas", derive(schemars::JsonSchema))]
pub struct PrincipalSettings(Map<String, Value>);

impl PrincipalSettings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_value(value: Value) -> Result<Self, ApiError> {
        match value {
            Value::Object(settings) => Ok(Self(settings)),
            _ => Err(ApiError::InvalidPrincipalSettings),
        }
    }

    pub fn from_serializable<T>(value: &T) -> Result<Self, ApiError>
    where
        T: Serialize + ?Sized,
    {
        Self::from_value(serde_json::to_value(value)?)
    }

    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    pub fn as_map_mut(&mut self) -> &mut Map<String, Value> {
        &mut self.0
    }

    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }

    pub fn deserialize<'de, T>(&'de self) -> Result<T, ApiError>
    where
        T: Deserialize<'de>,
    {
        Ok(T::deserialize(&self.0)?)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Option<Value> {
        self.0.insert(key.into(), value)
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.0.remove(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for PrincipalSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrincipalSettings")
            .field("document", &"[REDACTED]")
            .field("entry_count", &self.0.len())
            .finish()
    }
}

impl From<Map<String, Value>> for PrincipalSettings {
    fn from(value: Map<String, Value>) -> Self {
        Self(value)
    }
}

impl From<PrincipalSettings> for Value {
    fn from(value: PrincipalSettings) -> Self {
        value.into_value()
    }
}

impl TryFrom<Value> for PrincipalSettings {
    type Error = ApiError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::from_value(value)
    }
}

/// Revisioned response envelope used by principal-settings endpoints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "typed-schemas", derive(schemars::JsonSchema))]
pub struct PrincipalSettingsResponse {
    pub revision: ResourceRevision,
    pub settings: PrincipalSettings,
}

impl std::ops::Deref for PrincipalSettingsResponse {
    type Target = PrincipalSettings;

    fn deref(&self) -> &Self::Target {
        &self.settings
    }
}

/// One RFC 6902 operation for a principal-settings document.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "lowercase")]
#[cfg_attr(feature = "typed-schemas", derive(schemars::JsonSchema))]
pub enum PrincipalSettingsPatchOperation {
    Add { path: String, value: Value },
    Remove { path: String },
    Replace { path: String, value: Value },
    Move { from: String, path: String },
    Copy { from: String, path: String },
    Test { path: String, value: Value },
}

/// Bounded RFC 6902 patch document for principal settings.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(transparent)]
#[cfg_attr(feature = "typed-schemas", derive(schemars::JsonSchema))]
pub struct PrincipalSettingsPatchDocument(Vec<PrincipalSettingsPatchOperation>);

impl PrincipalSettingsPatchDocument {
    pub const MAX_OPERATIONS: usize = 1_000;

    pub fn new(
        operations: impl IntoIterator<Item = PrincipalSettingsPatchOperation>,
    ) -> Result<Self, ApiError> {
        let document = Self(operations.into_iter().collect());
        if document.0.len() > Self::MAX_OPERATIONS {
            return Err(ApiError::PrincipalSettingsPatchLimit {
                operations: document.0.len(),
                limit: Self::MAX_OPERATIONS,
            });
        }
        Ok(document)
    }

    pub fn as_slice(&self) -> &[PrincipalSettingsPatchOperation] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PrincipalSettingsPatchDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let operations = Vec::<PrincipalSettingsPatchOperation>::deserialize(deserializer)?;
        Self::new(operations).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<Vec<PrincipalSettingsPatchOperation>> for PrincipalSettingsPatchDocument {
    type Error = ApiError;

    fn try_from(value: Vec<PrincipalSettingsPatchOperation>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_object_roots_and_supports_typed_decoding() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Preferences {
            theme: String,
        }

        let settings = PrincipalSettings::from_value(json!({ "theme": "dark" })).unwrap();

        assert_eq!(
            settings.deserialize::<Preferences>().unwrap(),
            Preferences {
                theme: "dark".into()
            }
        );
    }

    #[test]
    fn supports_borrowed_typed_decoding() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct BorrowedPreferences<'a> {
            theme: &'a str,
        }

        let settings = PrincipalSettings::from_value(json!({ "theme": "dark" })).unwrap();

        assert_eq!(
            settings.deserialize::<BorrowedPreferences<'_>>().unwrap(),
            BorrowedPreferences { theme: "dark" }
        );
    }

    #[test]
    fn rejects_non_object_roots() {
        for value in [
            json!(null),
            json!(true),
            json!(1),
            json!("value"),
            json!([]),
        ] {
            assert!(matches!(
                PrincipalSettings::from_value(value),
                Err(ApiError::InvalidPrincipalSettings)
            ));
        }
    }

    #[test]
    fn debug_redacts_document_values() {
        let settings =
            PrincipalSettings::from_value(json!({ "token": "settings-secret" })).unwrap();
        let diagnostic = format!("{settings:?}");

        assert!(diagnostic.contains("entry_count: 1"));
        assert!(!diagnostic.contains("settings-secret"));
    }
}
