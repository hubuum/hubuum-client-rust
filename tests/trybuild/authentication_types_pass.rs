use hubuum_client::{
    ApiError, ApprovalInteraction, AuthenticationInteractionRequest, AuthenticationProviderId,
    CredentialOperation, LoginInteraction, NewTokenRequest, PrincipalId,
    ProviderVerificationInteraction, SecurityCandidateVerification, SessionClientId, Token,
    blocking,
};

async fn login(flow: LoginInteraction) -> Result<hubuum_client::Client<hubuum_client::Authenticated>, ApiError> {
    flow.complete().await
}

fn blocking_login(flow: blocking::LoginInteraction) -> Result<blocking::Client<hubuum_client::Authenticated>, ApiError> {
    flow.complete()
}

async fn verification(flow: ProviderVerificationInteraction) -> Result<SecurityCandidateVerification, ApiError> {
    flow.complete().await
}

fn blocking_verification(flow: blocking::ProviderVerificationInteraction) -> Result<SecurityCandidateVerification, ApiError> {
    flow.complete()
}

async fn approval(flow: ApprovalInteraction<Token>) -> Result<Token, ApiError> {
    flow.complete().await?.send().await
}

fn blocking_approval(flow: blocking::ApprovalInteraction<Token>) -> Result<Token, ApiError> {
    flow.complete()?.send()
}

fn main() {
    let _ = AuthenticationInteractionRequest::new(SessionClientId::default(), AuthenticationProviderId::local());
    let _ = CredentialOperation::create_token(PrincipalId::new(1).unwrap(), NewTokenRequest::new());
}
