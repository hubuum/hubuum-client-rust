use hubuum_client::BaseUrl;

pub const ADMIN_USERNAME: &str = "admin";
pub const BASE_URL_ENV: &str = "HUBUUM_INTEGRATION_BASE_URL";
pub const ADMIN_PASSWORD_ENV: &str = "HUBUUM_INTEGRATION_ADMIN_PASSWORD";

pub fn integration_connection() -> Result<(BaseUrl, String), String> {
    optional_integration_connection()?.ok_or_else(|| {
        format!(
            "set both {BASE_URL_ENV} and {ADMIN_PASSWORD_ENV} to use an external integration stack"
        )
    })
}

pub fn optional_integration_connection() -> Result<Option<(BaseUrl, String)>, String> {
    let read = |key| {
        std::env::var(key)
            .ok()
            .filter(|value| !value.trim().is_empty())
    };
    match (read(BASE_URL_ENV), read(ADMIN_PASSWORD_ENV)) {
        (Some(url), Some(password)) => {
            let url = url
                .trim()
                .parse()
                .map_err(|_| "invalid integration base URL")?;
            Ok(Some((url, password)))
        }
        (None, None) => Ok(None),
        _ => Err(format!(
            "set both {BASE_URL_ENV} and {ADMIN_PASSWORD_ENV} to use an external integration stack"
        )),
    }
}
