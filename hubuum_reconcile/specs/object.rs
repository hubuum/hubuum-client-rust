pub struct ObjectResource {
    #[api(read_only)]
    pub id: i32,
    pub name: String,
    #[api(post_optional)]
    pub collection_id: CollectionId,
    #[api(post_optional)]
    pub hubuum_class_id: ClassId,
    pub description: String,
    #[api(optional)]
    pub data: serde_json::Value,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
    #[api(read_only)]
    pub revision: ResourceRevision,
}

pub struct ObjectRelationResource {
    #[api(read_only)]
    pub id: i32,
    #[api(query_key = "from_objects")]
    pub from_hubuum_object_id: ObjectId,
    #[api(query_key = "to_objects")]
    pub to_hubuum_object_id: ObjectId,
    #[api(query_key = "class_relation")]
    pub class_relation_id: ClassRelationId,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
    #[api(read_only)]
    pub revision: ResourceRevision,
}
