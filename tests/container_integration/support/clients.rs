use crate::support::stack::IntegrationStack;
use hubuum_client::{Authenticated, BaseUrl, Client, blocking};
pub(crate) use integration_support::clients::{
    async_admin_context, create_async_group, create_async_loginable_user, create_async_object,
    create_async_permission_sandbox, create_async_user, create_sync_group,
    create_sync_loginable_user, create_sync_object, create_sync_permission_sandbox,
    create_sync_user, is_unsupported_query_operator, login_async, login_sync, sync_admin_context,
};
use std::future::Future;

pub(crate) struct SyncHarness {
    _stack: IntegrationStack,
    pub(crate) client: blocking::Client<Authenticated>,
}

impl SyncHarness {
    pub(crate) fn admin_password(&self) -> &str {
        &self._stack.admin_password
    }

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
    pub(crate) fn admin_password(&self) -> &str {
        &self._stack.admin_password
    }

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
