pub struct CollectionResource {
    #[api(read_only)]
    pub id: i32,
    pub name: String,
    pub description: String,
    // The owning group is set only when the collection is created.
    #[api(post_only)]
    pub group_id: GroupId,
    #[api(optional, skip_patch)]
    pub parent_collection_id: CollectionId,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}
