use crate::{types::Permissions, ApiError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ClassParams {
    pub id: Option<i32>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserParams {
    pub id: Option<i32>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NamespacePermissionsGrantParams(pub Vec<Permissions>);

impl NamespacePermissionsGrantParams {
    pub fn from_strings(strings: Vec<String>) -> Result<Self, ApiError> {
        let mut perms = Vec::with_capacity(strings.len());
        for s in strings {
            let p = s.parse::<Permissions>()?;
            perms.push(p);
        }
        Ok(NamespacePermissionsGrantParams(perms))
    }
}
