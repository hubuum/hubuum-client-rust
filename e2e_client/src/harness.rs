use crate::naming::unique_case_prefix;
use hubuum_client::{
    ApiError, Authenticated, BaseUrl, ClassId, Client, CollectionId, GroupId, ObjectId, ObjectPost,
    UserId, blocking,
};
use integration_support::clients;
pub use integration_support::clients::{async_admin_context, sync_admin_context as admin_context};
pub use integration_support::connection::integration_connection;

pub struct E2EHarness {
    pub base_url: BaseUrl,
    pub admin_password: String,
    pub client: blocking::Client<Authenticated>,
}

pub struct AsyncE2EHarness {
    pub base_url: BaseUrl,
    pub client: Client<Authenticated>,
}

pub struct E2EUser {
    pub id: UserId,
    pub username: String,
    pub password: String,
}

impl E2EUser {
    pub fn login(&self, base_url: BaseUrl) -> Result<blocking::Client<Authenticated>, ApiError> {
        clients::TestUserCredentials {
            user_id: self.id,
            username: self.username.clone(),
            password: self.password.clone(),
        }
        .login_sync(base_url)
    }
}

impl E2EHarness {
    pub fn from_env() -> Result<Self, String> {
        let (base_url, admin_password) = integration_connection()?;
        let client = clients::login_sync(base_url.clone(), &admin_password)
            .map_err(|e| format!("admin login failed: {e}"))?;
        Ok(Self {
            base_url,
            admin_password,
            client,
        })
    }

    pub fn create_collection_class_object(
        &self,
        case: &str,
        admin_group_id: GroupId,
    ) -> Result<(CollectionId, ClassId, ObjectId), ApiError> {
        let (collection_id, class_id) =
            clients::create_sync_permission_sandbox(&self.client, admin_group_id, case)?;
        let prefix = unique_case_prefix(case);
        let object = self.client.objects(class_id).create_raw(ObjectPost {
            name: format!("{prefix}-object"),
            collection_id: Some(collection_id),
            hubuum_class_id: Some(class_id),
            description: "e2e object".into(),
            data: Some(serde_json::json!({ "source": "e2e-client" })),
        })?;
        Ok((collection_id, class_id, object.id))
    }

    pub fn create_user(&self, case: &str) -> Result<E2EUser, ApiError> {
        let user = clients::create_sync_loginable_user(&self.client, &self.admin_password, case)?;
        Ok(E2EUser {
            id: user.user_id,
            username: user.username,
            password: user.password,
        })
    }

    pub fn create_group(&self, case: &str) -> Result<(String, GroupId), ApiError> {
        clients::create_sync_group(&self.client, case)
    }
}

impl AsyncE2EHarness {
    pub async fn from_env() -> Result<Self, String> {
        let (base_url, admin_password) = integration_connection()?;
        let client = clients::login_async(base_url.clone(), &admin_password)
            .await
            .map_err(|e| format!("admin login failed: {e}"))?;
        Ok(Self { base_url, client })
    }

    pub async fn create_collection_class_object(
        &self,
        case: &str,
        admin_group_id: GroupId,
    ) -> Result<(CollectionId, ClassId, ObjectId), ApiError> {
        let (collection_id, class_id) =
            clients::create_async_permission_sandbox(&self.client, admin_group_id, case).await?;
        let prefix = unique_case_prefix(case);
        let object = self
            .client
            .objects(class_id)
            .create_raw(ObjectPost {
                name: format!("{prefix}-object"),
                collection_id: Some(collection_id),
                hubuum_class_id: Some(class_id),
                description: "e2e object".into(),
                data: Some(serde_json::json!({ "source": "e2e-client" })),
            })
            .await?;
        Ok((collection_id, class_id, object.id))
    }
}
