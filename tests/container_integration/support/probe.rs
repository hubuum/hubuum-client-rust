use serde_json::{json, Value};

pub(crate) const ADMIN_USERNAME: &str = "admin";

pub(crate) fn login_token(base_url: &str, admin_password: &str) -> Result<String, String> {
    let response = reqwest::blocking::Client::new()
        .post(format!("{base_url}/api/v0/auth/login"))
        .json(&json!({
            "username": ADMIN_USERNAME,
            "password": admin_password
        }))
        .send()
        .map_err(|err| format!("login request failed: {err}"))?;

    if !response.status().is_success() {
        return Err(format!("login failed with status {}", response.status()));
    }

    let payload: Value = response
        .json()
        .map_err(|err| format!("failed to decode login response: {err}"))?;
    payload
        .get("token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "login response missing token field".to_string())
}

pub(crate) fn fetch_admin_ids(base_url: &str, token: &str) -> Result<(i32, i32), String> {
    let http = reqwest::blocking::Client::new();

    let users_response = http
        .get(format!(
            "{base_url}/api/v1/iam/users/?username__equals={ADMIN_USERNAME}"
        ))
        .bearer_auth(token)
        .send()
        .map_err(|err| format!("users query failed: {err}"))?;
    if !users_response.status().is_success() {
        return Err(format!(
            "users query failed with status {}",
            users_response.status()
        ));
    }
    let users: Value = users_response
        .json()
        .map_err(|err| format!("failed to decode users query response: {err}"))?;
    let user_id = users
        .as_array()
        .and_then(|values| values.first())
        .and_then(|entry| entry.get("id"))
        .and_then(Value::as_i64)
        .ok_or_else(|| "failed to extract admin user id".to_string())? as i32;

    let groups_response = http
        .get(format!(
            "{base_url}/api/v1/iam/groups/?groupname__equals={ADMIN_USERNAME}"
        ))
        .bearer_auth(token)
        .send()
        .map_err(|err| format!("groups query failed: {err}"))?;
    if !groups_response.status().is_success() {
        return Err(format!(
            "groups query failed with status {}",
            groups_response.status()
        ));
    }
    let groups: Value = groups_response
        .json()
        .map_err(|err| format!("failed to decode groups query response: {err}"))?;
    let group_id = groups
        .as_array()
        .and_then(|values| values.first())
        .and_then(|entry| entry.get("id"))
        .and_then(Value::as_i64)
        .ok_or_else(|| "failed to extract admin group id".to_string())? as i32;

    Ok((user_id, group_id))
}
