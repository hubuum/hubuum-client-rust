use hubuum_client::*;

#[test]
fn integer_resource_ids_enforce_one_contract_at_every_boundary() {
    macro_rules! check {
        ($($id:ident),+ $(,)?) => { $(
            for invalid in [0, -1] {
                assert!(matches!($id::new(invalid), Err(ApiError::InvalidResourceId { .. })));
                assert!($id::try_from(invalid).is_err());
                assert!(invalid.to_string().parse::<$id>().is_err());
                assert!(serde_json::from_str::<$id>(&invalid.to_string()).is_err());
            }
            let id = $id::new(7).unwrap();
            assert_eq!(id.get(), 7);
            assert_eq!($id::from(&id), id);
            assert_eq!("7".parse::<$id>().unwrap(), id);
            assert_eq!(serde_json::from_str::<$id>("7").unwrap(), id);
            assert_eq!(serde_json::to_string(&id).unwrap(), "7");
        )+ };
    }
    check!(
        ClassId,
        ClassRelationId,
        CollectionId,
        ExportTemplateId,
        GroupId,
        ObjectId,
        ObjectRelationId,
        ServiceAccountId,
        UserId,
        EventSinkId,
        RemoteTargetId,
        PrincipalId,
        CredentialApprovalId,
        TokenId,
        TaskId,
        TaskEventId,
        ImportResultId,
        EventSubscriptionId,
        EventDeliveryId,
        RemoteCallResultId,
        HistoryId,
        PermissionId,
        ComputedFieldDefinitionId,
        RestoreId
    );
}

#[test]
fn principal_identity_conversions_preserve_validated_ids() {
    assert_eq!(PrincipalId::from(UserId::new(7).unwrap()).get(), 7);
    assert_eq!(
        PrincipalId::from(ServiceAccountId::new(8).unwrap()).get(),
        8
    );
}
