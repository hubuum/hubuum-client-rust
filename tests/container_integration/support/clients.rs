use std::future::Future;

use hubuum_client::{
    ApiError, AsyncClient, Authenticated, BaseUrl, ClassPost, Credentials, NamespacePost,
    SyncClient,
};

use crate::support::naming::unique_case_prefix;
use crate::support::probe::ADMIN_USERNAME;
use crate::support::stack::IntegrationStack;

pub(crate) fn login_sync(
    base_url: BaseUrl,
    admin_password: &str,
) -> Result<SyncClient<Authenticated>, ApiError> {
    SyncClient::new(base_url).login(Credentials::new(
        ADMIN_USERNAME.to_string(),
        admin_password.to_string(),
    ))
}

pub(crate) async fn login_async(
    base_url: BaseUrl,
    admin_password: &str,
) -> Result<AsyncClient<Authenticated>, ApiError> {
    AsyncClient::new(base_url)
        .login(Credentials::new(
            ADMIN_USERNAME.to_string(),
            admin_password.to_string(),
        ))
        .await
}

pub(crate) struct SyncHarness {
    _stack: IntegrationStack,
    pub(crate) client: SyncClient<Authenticated>,
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
    pub(crate) client: AsyncClient<Authenticated>,
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
    client: &SyncClient<Authenticated>,
) -> Result<(i32, i32), ApiError> {
    let admin = client.users().select_by_name(ADMIN_USERNAME)?;
    let admin_id = admin.id();

    let admin_group_id = match admin.groups() {
        Ok(admin_groups) => {
            if let Some(group) = admin_groups.first() {
                group.id()
            } else {
                client.groups().select_by_name(ADMIN_USERNAME)?.id()
            }
        }
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            client.groups().select_by_name(ADMIN_USERNAME)?.id()
        }
        Err(err) => return Err(err),
    };

    Ok((admin_id, admin_group_id))
}

pub(crate) async fn async_admin_context(
    client: &AsyncClient<Authenticated>,
) -> Result<(i32, i32), ApiError> {
    let admin = client.users().select_by_name(ADMIN_USERNAME).await?;
    let admin_id = admin.id();

    let admin_group_id = match admin.groups().await {
        Ok(admin_groups) => {
            if let Some(group) = admin_groups.first() {
                group.id()
            } else {
                client.groups().select_by_name(ADMIN_USERNAME).await?.id()
            }
        }
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            client.groups().select_by_name(ADMIN_USERNAME).await?.id()
        }
        Err(err) => return Err(err),
    };

    Ok((admin_id, admin_group_id))
}

pub(crate) fn create_sync_permission_sandbox(
    client: &SyncClient<Authenticated>,
    admin_group_id: i32,
    case: &str,
) -> Result<(i32, i32), ApiError> {
    let prefix = unique_case_prefix(case);

    let namespace = client.namespaces().create(NamespacePost {
        name: format!("{prefix}-namespace"),
        description: "integration namespace".to_string(),
        group_id: admin_group_id,
    })?;

    let class = client.classes().create(ClassPost {
        name: format!("{prefix}-class"),
        namespace_id: namespace.id,
        description: "integration class".to_string(),
        json_schema: None,
        validate_schema: None,
    })?;

    Ok((namespace.id, class.id))
}

pub(crate) async fn create_async_permission_sandbox(
    client: &AsyncClient<Authenticated>,
    admin_group_id: i32,
    case: &str,
) -> Result<(i32, i32), ApiError> {
    let prefix = unique_case_prefix(case);

    let namespace = client
        .namespaces()
        .create(NamespacePost {
            name: format!("{prefix}-namespace"),
            description: "integration namespace".to_string(),
            group_id: admin_group_id,
        })
        .await?;

    let class = client
        .classes()
        .create(ClassPost {
            name: format!("{prefix}-class"),
            namespace_id: namespace.id,
            description: "integration class".to_string(),
            json_schema: None,
            validate_schema: None,
        })
        .await?;

    Ok((namespace.id, class.id))
}
