use serde::{Serialize, de::DeserializeOwned};

use crate::{ApiError, ClassId, CollectionId, HubuumDateTime, Object, ObjectId};

/// A Hubuum object whose `data` payload has been decoded into a consumer type.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedObject<T> {
    pub id: ObjectId,
    pub name: String,
    pub collection_id: CollectionId,
    pub class_id: ClassId,
    pub description: String,
    pub data: T,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

impl<T: DeserializeOwned> TryFrom<Object> for TypedObject<T> {
    type Error = ApiError;

    fn try_from(value: Object) -> Result<Self, Self::Error> {
        let raw_data = value.data.ok_or_else(|| {
            ApiError::EmptyResult(format!("object {} has no data payload", value.id))
        })?;
        let data = serde_json::from_value(raw_data).map_err(|error| {
            ApiError::DeserializationError(format!(
                "failed to decode object {} data as {}: {error}",
                value.id,
                std::any::type_name::<T>()
            ))
        })?;
        Ok(Self {
            id: value.id,
            name: value.name,
            collection_id: value.collection_id,
            class_id: value.hubuum_class_id,
            description: value.description,
            data,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

impl<T: Serialize> TypedObject<T> {
    pub fn try_into_untyped(self) -> Result<Object, ApiError> {
        Ok(Object {
            id: self.id,
            name: self.name,
            collection_id: self.collection_id,
            hubuum_class_id: self.class_id,
            description: self.description,
            data: Some(serde_json::to_value(self.data)?),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[cfg(feature = "typed-schemas")]
pub fn schema_for<T: schemars::JsonSchema>() -> Result<serde_json::Value, ApiError> {
    Ok(serde_json::to_value(schemars::schema_for!(T))?)
}
