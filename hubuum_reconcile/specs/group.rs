pub struct GroupResource {
    #[api(read_only)]
    pub id: i32,
    #[api(post_optional, skip_patch, default_local)]
    pub identity_scope: String,
    pub groupname: String,
    #[api(post_optional)]
    pub description: String,
    #[api(read_only, skip_query, default_local)]
    pub managed_by: String,
    #[api(read_only, optional, skip_query)]
    pub external_key: String,
    #[api(read_only, optional, skip_query)]
    pub last_sync_attempted_at: HubuumDateTime,
    #[api(read_only, optional, skip_query)]
    pub last_sync_success_at: HubuumDateTime,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
    #[api(read_only)]
    pub revision: ResourceRevision,
}
