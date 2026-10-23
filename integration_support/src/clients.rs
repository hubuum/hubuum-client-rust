use hubuum_client::{
    ApiError, Authenticated, BaseUrl, ClassId, ClassPost, Client, CollectionId, CollectionPost,
    CredentialOperation, Credentials, GroupId, GroupPost, ObjectId, ObjectPost, UserId, UserPost,
    blocking,
};

use crate::connection::ADMIN_USERNAME;
use crate::naming::unique_case_prefix;

#[derive(Clone)]
pub struct TestUserCredentials {
    pub user_id: UserId,
    pub username: String,
    pub password: String,
}

impl TestUserCredentials {
    pub fn login_sync(
        &self,
        base_url: BaseUrl,
    ) -> Result<blocking::Client<Authenticated>, ApiError> {
        blocking::Client::try_new(base_url)?.login_session(
            Credentials::new(self.username.clone(), self.password.clone()),
            Default::default(),
        )
    }

    pub async fn login_async(&self, base_url: BaseUrl) -> Result<Client<Authenticated>, ApiError> {
        Client::try_new(base_url)?
            .login_session(
                Credentials::new(self.username.clone(), self.password.clone()),
                Default::default(),
            )
            .await
    }
}

pub fn login_sync(
    base_url: BaseUrl,
    admin_password: &str,
) -> Result<blocking::Client<Authenticated>, ApiError> {
    blocking::Client::try_new(base_url)?.login_session(
        Credentials::new(ADMIN_USERNAME.to_string(), admin_password.to_string()),
        Default::default(),
    )
}

pub fn is_unsupported_query_operator(err: &ApiError, operator: &str) -> bool {
    matches!(
        err,
        ApiError::HttpWithBody { status, message, .. }
            if status.as_u16() == 400
                && message.contains("not implemented")
                && message.contains(operator)
    )
}

pub async fn login_async(
    base_url: BaseUrl,
    admin_password: &str,
) -> Result<Client<Authenticated>, ApiError> {
    Client::try_new(base_url)?
        .login_session(
            Credentials::new(ADMIN_USERNAME.to_string(), admin_password.to_string()),
            Default::default(),
        )
        .await
}

pub fn sync_admin_context(
    client: &blocking::Client<Authenticated>,
) -> Result<(UserId, GroupId), ApiError> {
    let admin = client.users().get_by_name(ADMIN_USERNAME)?;
    let admin_id = admin.id();

    let admin_group_id = match admin.groups() {
        Ok(admin_groups) => {
            if let Some(group) = admin_groups.first() {
                group.id()
            } else {
                client.groups().get_by_name(ADMIN_USERNAME)?.id()
            }
        }
        Err(ApiError::HttpWithBody { status, .. }) if status.as_u16() == 404 => {
            client.groups().get_by_name(ADMIN_USERNAME)?.id()
        }
        Err(err) => return Err(err),
    };

    Ok((admin_id, admin_group_id))
}

pub fn create_sync_user(
    client: &blocking::Client<Authenticated>,
    admin_password: &str,
    case: &str,
) -> Result<(String, UserId), ApiError> {
    let user = create_sync_loginable_user(client, admin_password, case)?;
    Ok((user.username, user.user_id))
}

pub fn create_sync_loginable_user(
    client: &blocking::Client<Authenticated>,
    admin_password: &str,
    case: &str,
) -> Result<TestUserCredentials, ApiError> {
    let prefix = unique_case_prefix(case);
    let username = format!("{prefix}-user");
    let password = fixture_password();
    let request = UserPost {
        identity_scope: None,
        name: username.clone(),
        password: password.clone(),
        email: Some(format!("{prefix}@example.test")),
        proper_name: None,
    };
    let user = match client.users().create_raw(request.clone()) {
        Err(error) if error.is_reauthentication_required() => client
            .credential_approvals()
            .approve(admin_password, CredentialOperation::create_user(request))?
            .send()?,
        result => result?,
    };

    Ok(TestUserCredentials {
        user_id: user.id,
        username,
        password,
    })
}

pub fn create_sync_group(
    client: &blocking::Client<Authenticated>,
    case: &str,
) -> Result<(String, GroupId), ApiError> {
    let prefix = unique_case_prefix(case);
    let groupname = format!("{prefix}-group");
    let group = client.groups().create_raw(GroupPost {
        identity_scope: None,
        groupname: groupname.clone(),
        description: Some("integration group".to_string()),
    })?;

    Ok((groupname, group.id))
}

pub async fn async_admin_context(
    client: &Client<Authenticated>,
) -> Result<(UserId, GroupId), ApiError> {
    let admin = client.users().get_by_name(ADMIN_USERNAME).await?;
    let admin_id = admin.id();

    let admin_group_id = match admin.groups().await {
        Ok(admin_groups) => {
            if let Some(group) = admin_groups.first() {
                group.id()
            } else {
                client.groups().get_by_name(ADMIN_USERNAME).await?.id()
            }
        }
        Err(ApiError::HttpWithBody { status, .. }) if status.as_u16() == 404 => {
            client.groups().get_by_name(ADMIN_USERNAME).await?.id()
        }
        Err(err) => return Err(err),
    };

    Ok((admin_id, admin_group_id))
}

pub async fn create_async_user(
    client: &Client<Authenticated>,
    admin_password: &str,
    case: &str,
) -> Result<(String, UserId), ApiError> {
    let user = create_async_loginable_user(client, admin_password, case).await?;
    Ok((user.username, user.user_id))
}

pub async fn create_async_loginable_user(
    client: &Client<Authenticated>,
    admin_password: &str,
    case: &str,
) -> Result<TestUserCredentials, ApiError> {
    let prefix = unique_case_prefix(case);
    let username = format!("{prefix}-user");
    let password = fixture_password();
    let request = UserPost {
        identity_scope: None,
        name: username.clone(),
        password: password.clone(),
        email: Some(format!("{prefix}@example.test")),
        proper_name: None,
    };
    let user = match client.users().create_raw(request.clone()).await {
        Err(error) if error.is_reauthentication_required() => {
            client
                .credential_approvals()
                .approve(admin_password, CredentialOperation::create_user(request))
                .await?
                .send()
                .await?
        }
        result => result?,
    };

    Ok(TestUserCredentials {
        user_id: user.id,
        username,
        password,
    })
}

pub async fn create_async_group(
    client: &Client<Authenticated>,
    case: &str,
) -> Result<(String, GroupId), ApiError> {
    let prefix = unique_case_prefix(case);
    let groupname = format!("{prefix}-group");
    let group = client
        .groups()
        .create_raw(GroupPost {
            identity_scope: None,
            groupname: groupname.clone(),
            description: Some("integration group".to_string()),
        })
        .await?;

    Ok((groupname, group.id))
}

pub fn create_sync_permission_sandbox(
    client: &blocking::Client<Authenticated>,
    admin_group_id: GroupId,
    case: &str,
) -> Result<(CollectionId, ClassId), ApiError> {
    let prefix = unique_case_prefix(case);

    let collection = client.collections().create_raw(CollectionPost {
        name: format!("{prefix}-collection"),
        description: "integration collection".to_string(),
        group_id: admin_group_id,
        parent_collection_id: None,
    })?;

    let class = client.classes().create_raw(ClassPost {
        name: format!("{prefix}-class"),
        collection_id: collection.id,
        description: "integration class".to_string(),
        json_schema: None,
        validate_schema: None,
    })?;

    Ok((collection.id, class.id))
}

pub fn create_sync_object(
    client: &blocking::Client<Authenticated>,
    collection_id: CollectionId,
    class_id: ClassId,
    case: &str,
) -> Result<(String, ObjectId), ApiError> {
    let prefix = unique_case_prefix(case);
    let name = format!("{prefix}-object");
    let object = client.objects(class_id).create_raw(ObjectPost {
        name: name.clone(),
        collection_id: Some(collection_id),
        hubuum_class_id: Some(class_id),
        description: "integration object".to_string(),
        data: None,
    })?;

    Ok((name, object.id))
}

pub async fn create_async_permission_sandbox(
    client: &Client<Authenticated>,
    admin_group_id: GroupId,
    case: &str,
) -> Result<(CollectionId, ClassId), ApiError> {
    let prefix = unique_case_prefix(case);

    let collection = client
        .collections()
        .create_raw(CollectionPost {
            name: format!("{prefix}-collection"),
            description: "integration collection".to_string(),
            group_id: admin_group_id,
            parent_collection_id: None,
        })
        .await?;

    let class = client
        .classes()
        .create_raw(ClassPost {
            name: format!("{prefix}-class"),
            collection_id: collection.id,
            description: "integration class".to_string(),
            json_schema: None,
            validate_schema: None,
        })
        .await?;

    Ok((collection.id, class.id))
}

pub async fn create_async_object(
    client: &Client<Authenticated>,
    collection_id: CollectionId,
    class_id: ClassId,
    case: &str,
) -> Result<(String, ObjectId), ApiError> {
    let prefix = unique_case_prefix(case);
    let name = format!("{prefix}-object");
    let object = client
        .objects(class_id)
        .create_raw(ObjectPost {
            name: name.clone(),
            collection_id: Some(collection_id),
            hubuum_class_id: Some(class_id),
            description: "integration object".to_string(),
            data: None,
        })
        .await?;

    Ok((name, object.id))
}

fn fixture_password() -> String {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).expect("OS randomness is required for fixture passwords");
    format!("{:032x}", u128::from_ne_bytes(bytes))
}
