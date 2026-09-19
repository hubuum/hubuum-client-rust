use hubuum_client::{
    CredentialOperation, FullImportGraph, FullImportRequest, NewTokenRequest, PrincipalId,
    RenewTokenRequest, RestoreCapability, RestoreConfirmRequest, RestoreId,
    RestoreStageResponse, TaskResponse, Token, TokenId, User, UserId, UserPatch, UserPost,
};

fn main() {
    let _: CredentialOperation<Token> = CredentialOperation::create_token(PrincipalId::new(1), NewTokenRequest::new());
    let _: CredentialOperation<Token> = CredentialOperation::renew_token(PrincipalId::new(1), TokenId::new(2), RenewTokenRequest::default());
    let _: CredentialOperation<User> = CredentialOperation::create_user(UserPost::default());
    let _: CredentialOperation<User> = CredentialOperation::update_user(UserId::new(1), UserPatch::default(), "new-password");
    let _: CredentialOperation<TaskResponse> = CredentialOperation::import_credentials(FullImportRequest::new(FullImportGraph::default()));
    let _: CredentialOperation<RestoreStageResponse> = CredentialOperation::confirm_restore(RestoreId::new(1), RestoreConfirmRequest::new(RestoreCapability::new("capability"), "sha256"));
}
