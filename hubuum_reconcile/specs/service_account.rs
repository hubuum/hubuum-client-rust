pub struct ServiceAccountResource {
    #[api(read_only)]
    pub id: i32,
    #[api(post_optional, skip_patch, response_optional)]
    pub identity_scope: String,
    #[api(read_only, response_optional)]
    pub identity_scope_id: i32,
    // Required on create; principal renaming is not exposed through this PATCH.
    #[api(skip_patch)]
    pub name: String,
    // Optional on create, mutable on update, and always present in responses.
    #[api(post_optional)]
    pub description: String,
    pub owner_group_id: GroupId,
    #[api(read_only, optional)]
    pub created_by: PrincipalId,
    #[api(read_only, optional)]
    pub disabled_at: HubuumDateTime,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
    #[api(read_only)]
    pub revision: ResourceRevision,
}
