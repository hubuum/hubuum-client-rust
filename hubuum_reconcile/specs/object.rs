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
}

pub struct ObjectRelationResource {
    #[api(read_only)]
    pub id: i32,
    pub from_hubuum_object_id: ObjectId,
    pub to_hubuum_object_id: ObjectId,
    pub class_relation_id: ClassRelationId,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}
