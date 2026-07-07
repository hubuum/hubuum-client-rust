use std::str::FromStr;

use hubuum_client::{
    ApiError, Authenticated, BaseUrl, ClassPost, Credentials, GroupPost, NamespacePost, ObjectPost,
    UserPost, blocking,
};

use crate::naming::unique_case_prefix;

const EXTERNAL_BASE_URL_ENV: &str = "HUBUUM_INTEGRATION_BASE_URL";
const EXTERNAL_ADMIN_PASSWORD_ENV: &str = "HUBUUM_INTEGRATION_ADMIN_PASSWORD";
const ADMIN_USERNAME: &str = "admin";

pub struct E2EHarness {
    pub base_url: BaseUrl,
    pub admin_password: String,
    pub client: blocking::Client<Authenticated>,
}

pub struct E2EUser {
    pub id: i32,
    pub username: String,
    pub password: String,
}

impl E2EUser {
    pub fn login(&self, base_url: BaseUrl) -> Result<blocking::Client<Authenticated>, ApiError> {
        blocking::Client::new(base_url).login(Credentials::new(
            self.username.clone(),
            self.password.clone(),
        ))
    }
}

impl E2EHarness {
    pub fn from_env() -> Result<Self, String> {
        let base_url = std::env::var(EXTERNAL_BASE_URL_ENV)
            .map_err(|_| format!("{EXTERNAL_BASE_URL_ENV} must be set"))?;
        let admin_password = std::env::var(EXTERNAL_ADMIN_PASSWORD_ENV)
            .map_err(|_| format!("{EXTERNAL_ADMIN_PASSWORD_ENV} must be set"))?;

        let parsed_base_url =
            BaseUrl::from_str(&base_url).map_err(|err| format!("invalid base url: {err}"))?;

        let client = blocking::Client::new(parsed_base_url.clone())
            .login(Credentials::new(
                ADMIN_USERNAME.to_string(),
                admin_password.to_string(),
            ))
            .map_err(|err| format!("admin login failed: {err}"))?;

        Ok(Self {
            base_url: parsed_base_url,
            admin_password,
            client,
        })
    }

    pub fn create_namespace_class_object(
        &self,
        case: &str,
        admin_group_id: i32,
    ) -> Result<(i32, i32, i32), ApiError> {
        let prefix = unique_case_prefix(case);

        let namespace = self.client.namespaces().create_raw(NamespacePost {
            name: format!("{prefix}-namespace"),
            description: "e2e namespace".to_string(),
            group_id: admin_group_id,
        })?;

        let class = self.client.classes().create_raw(ClassPost {
            name: format!("{prefix}-class"),
            namespace_id: namespace.id.into(),
            description: "e2e class".to_string(),
            json_schema: None,
            validate_schema: None,
        })?;

        let object = self.client.objects(class.id).create_raw(ObjectPost {
            name: format!("{prefix}-object"),
            namespace_id: namespace.id.into(),
            hubuum_class_id: class.id.into(),
            description: "e2e object".to_string(),
            data: Some(serde_json::json!({ "source": "e2e-client" })),
        })?;

        Ok((namespace.id.into(), class.id.into(), object.id.into()))
    }

    pub fn create_user(&self, case: &str) -> Result<E2EUser, ApiError> {
        let prefix = unique_case_prefix(case);
        let username = format!("{prefix}-user");
        let password = format!("{prefix}-Passw0rd!");
        let user = self.client.users().create_raw(UserPost {
            name: username.clone(),
            password: password.clone(),
            email: Some(format!("{prefix}@example.test")),
            proper_name: Some(format!("{prefix} User")),
        })?;

        Ok(E2EUser {
            id: user.id.into(),
            username,
            password,
        })
    }

    pub fn create_group(&self, case: &str) -> Result<(String, i32), ApiError> {
        let prefix = unique_case_prefix(case);
        let groupname = format!("{prefix}-group");
        let group = self.client.groups().create_raw(GroupPost {
            groupname: groupname.clone(),
            description: "e2e group".to_string(),
        })?;

        Ok((groupname, group.id.into()))
    }
}

pub fn admin_context(client: &blocking::Client<Authenticated>) -> Result<(i32, i32), ApiError> {
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

    Ok((admin_id.into(), admin_group_id.into()))
}
