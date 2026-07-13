use std::future::Future;

use hubuum_client::{
    ApiError, Authenticated, BaseUrl, ClassId, ClassPost, Client, CollectionId, CollectionPost,
    Credentials, GroupId, GroupPost, ObjectId, ObjectPost, UserId, UserPost, blocking,
};

use crate::support::naming::unique_case_prefix;
use crate::support::probe::ADMIN_USERNAME;
use crate::support::stack::IntegrationStack;

#[derive(Clone)]
pub(crate) struct TestUserCredentials {
    pub(crate) user_id: UserId,
    username: String,
    password: String,
}

impl TestUserCredentials {
    pub(crate) fn login_sync(
        &self,
        base_url: BaseUrl,
    ) -> Result<blocking::Client<Authenticated>, ApiError> {
        blocking::Client::try_new(base_url)?.login(Credentials::new(
            self.username.clone(),
            self.password.clone(),
        ))
    }

    pub(crate) async fn login_async(
        &self,
        base_url: BaseUrl,
    ) -> Result<Client<Authenticated>, ApiError> {
        Client::try_new(base_url)?
            .login(Credentials::new(
                self.username.clone(),
                self.password.clone(),
            ))
            .await
    }
}

pub(crate) fn login_sync(
    base_url: BaseUrl,
    admin_password: &str,
) -> Result<blocking::Client<Authenticated>, ApiError> {
    blocking::Client::try_new(base_url)?.login(Credentials::new(
        ADMIN_USERNAME.to_string(),
        admin_password.to_string(),
    ))
}

pub(crate) fn is_unsupported_query_operator(err: &ApiError, operator: &str) -> bool {
    matches!(
        err,
        ApiError::HttpWithBody { status, message, .. }
            if *status == reqwest::StatusCode::BAD_REQUEST
                && message.contains("not implemented")
                && message.contains(operator)
    )
}

pub(crate) async fn login_async(
    base_url: BaseUrl,
    admin_password: &str,
) -> Result<Client<Authenticated>, ApiError> {
    Client::try_new(base_url)?
        .login(Credentials::new(
            ADMIN_USERNAME.to_string(),
            admin_password.to_string(),
        ))
        .await
}

pub(crate) struct SyncHarness {
    _stack: IntegrationStack,
    pub(crate) client: blocking::Client<Authenticated>,
}

impl SyncHarness {
    pub(crate) fn start() -> Result<Self, String> {
        let stack = IntegrationStack::start()?;
        let base_url = stack
            .base_url
            .parse::<BaseUrl>()
            .map_err(|err| format!("container base URL should be valid: {err}"))?;
        let client = login_sync(base_url, &stack.admin_password)
            .map_err(|err| format!("sync login failed: {err}"))?;

        Ok(Self {
            _stack: stack,
            client,
        })
    }
}

pub(crate) struct AsyncHarness {
    _stack: IntegrationStack,
    pub(crate) client: Client<Authenticated>,
    runtime: tokio::runtime::Runtime,
}

impl AsyncHarness {
    pub(crate) fn start() -> Result<Self, String> {
        let stack = IntegrationStack::start()?;
        let base_url = stack
            .base_url
            .parse::<BaseUrl>()
            .map_err(|err| format!("container base URL should be valid: {err}"))?;
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| format!("failed to create tokio runtime: {err}"))?;
        let client = runtime
            .block_on(login_async(base_url, &stack.admin_password))
            .map_err(|err| format!("async login failed: {err}"))?;

        Ok(Self {
            _stack: stack,
            client,
            runtime,
        })
    }

    pub(crate) fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.runtime.block_on(future)
    }
}

pub(crate) fn sync_admin_context(
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
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            client.groups().get_by_name(ADMIN_USERNAME)?.id()
        }
        Err(err) => return Err(err),
    };

    Ok((admin_id, admin_group_id))
}

pub(crate) fn create_sync_user(
    client: &blocking::Client<Authenticated>,
    case: &str,
) -> Result<(String, UserId), ApiError> {
    let prefix = unique_case_prefix(case);
    let username = format!("{prefix}-user");
    let user = client.users().create_raw(UserPost {
        identity_scope: None,
        name: username.clone(),
        password: format!("{prefix}-Passw0rd!"),
        email: Some(format!("{prefix}@example.test")),
        proper_name: None,
    })?;

    Ok((username, user.id))
}

pub(crate) fn create_sync_loginable_user(
    client: &blocking::Client<Authenticated>,
    case: &str,
) -> Result<TestUserCredentials, ApiError> {
    let prefix = unique_case_prefix(case);
    let username = format!("{prefix}-user");
    let password = format!("{prefix}-Passw0rd!");
    let user = client.users().create_raw(UserPost {
        identity_scope: None,
        name: username.clone(),
        password: password.clone(),
        email: Some(format!("{prefix}@example.test")),
        proper_name: None,
    })?;

    Ok(TestUserCredentials {
        user_id: user.id,
        username,
        password,
    })
}

pub(crate) fn create_sync_group(
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

pub(crate) async fn async_admin_context(
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
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            client.groups().get_by_name(ADMIN_USERNAME).await?.id()
        }
        Err(err) => return Err(err),
    };

    Ok((admin_id, admin_group_id))
}

pub(crate) async fn create_async_user(
    client: &Client<Authenticated>,
    case: &str,
) -> Result<(String, UserId), ApiError> {
    let prefix = unique_case_prefix(case);
    let username = format!("{prefix}-user");
    let user = client
        .users()
        .create_raw(UserPost {
            identity_scope: None,
            name: username.clone(),
            password: format!("{prefix}-Passw0rd!"),
            email: Some(format!("{prefix}@example.test")),
            proper_name: None,
        })
        .await?;

    Ok((username, user.id))
}

pub(crate) async fn create_async_loginable_user(
    client: &Client<Authenticated>,
    case: &str,
) -> Result<TestUserCredentials, ApiError> {
    let prefix = unique_case_prefix(case);
    let username = format!("{prefix}-user");
    let password = format!("{prefix}-Passw0rd!");
    let user = client
        .users()
        .create_raw(UserPost {
            identity_scope: None,
            name: username.clone(),
            password: password.clone(),
            email: Some(format!("{prefix}@example.test")),
            proper_name: None,
        })
        .await?;

    Ok(TestUserCredentials {
        user_id: user.id,
        username,
        password,
    })
}

pub(crate) async fn create_async_group(
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

pub(crate) fn create_sync_permission_sandbox(
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

pub(crate) fn create_sync_object(
    client: &blocking::Client<Authenticated>,
    collection_id: CollectionId,
    class_id: ClassId,
    case: &str,
) -> Result<(String, ObjectId), ApiError> {
    let prefix = unique_case_prefix(case);
    let name = format!("{prefix}-object");
    let object = client.objects(class_id).create_raw(ObjectPost {
        name: name.clone(),
        collection_id,
        hubuum_class_id: class_id,
        description: "integration object".to_string(),
        data: None,
    })?;

    Ok((name, object.id))
}

pub(crate) async fn create_async_permission_sandbox(
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

pub(crate) async fn create_async_object(
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
            collection_id,
            hubuum_class_id: class_id,
            description: "integration object".to_string(),
            data: None,
        })
        .await?;

    Ok((name, object.id))
}
