pub struct UserResource {
    #[api(read_only)]
    pub id: i32,
    #[api(post_optional, skip_patch, default_local)]
    pub identity_scope: String,
    #[api(read_only, skip_query, default_local)]
    pub provider_kind: String,
    #[api(read_only, skip_query, default)]
    pub provider_managed: bool,
    // Required on create; principal renaming is not exposed through this PATCH.
    #[api(skip_patch)]
    pub name: String,
    // Write-only on create. Password changes use the dedicated operation.
    #[api(post_only)]
    pub password: String,
    #[api(optional)]
    pub email: String,
    #[api(optional)]
    pub proper_name: String,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
    #[api(read_only, optional, skip_query)]
    pub last_sync_attempted_at: HubuumDateTime,
    #[api(read_only, optional, skip_query)]
    pub last_sync_success_at: HubuumDateTime,
}
