//! Independent public-API consumer, controlled over private stdin/stdout pipes.
//! Only public interaction instructions and sanitized check names leave stdout.
use std::{
    env,
    error::Error,
    fs,
    io::{self, Write},
    time::{Duration, SystemTime},
};

use hubuum_client::{
    AuthenticationInteractionRequest, AuthenticationInteractionState, AuthenticationNext,
    AuthenticationProviderId, AuthenticationProviderKind, AuthenticationProviderUpdate, BaseUrl,
    Client, CredentialOperation, Credentials, NewTokenRequest, ProviderConfigurationInput,
    ProviderCredentialInput, SecurityCandidateRequest, SessionClientId, blocking,
};
use serde_json::{Value, json};

fn emit(event: Value) -> Result<(), Box<dyn Error>> {
    println!("{event}");
    io::stdout().flush()?;
    Ok(())
}

fn proceed() -> Result<(), Box<dyn Error>> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if line.trim() != "continue" {
        return Err("Fixture acknowledgement missing".into());
    }
    Ok(())
}

fn browser(
    id: &hubuum_client::AuthenticationInteractionId,
    next: &AuthenticationNext,
) -> Result<(), Box<dyn Error>> {
    let AuthenticationNext::Browser {
        verification_uri,
        user_code,
    } = next
    else {
        return Err("Expected browser step".into());
    };
    emit(
        json!({"event":"browser", "id":id.as_str(), "next":{"kind":"browser","verification_uri":verification_uri,"user_code":user_code}}),
    )?;
    proceed()
}

fn passed(check: &str) -> Result<(), Box<dyn Error>> {
    emit(json!({"event":"passed","check":check}))
}

macro_rules! run {
    ($client:ident, $config:ident, $finish:ident, $sleep:ident) => {{
        let client_id=SessionClientId::new("oidc-qa")?;
        let password=$config["local_password"].as_str().ok_or("Missing fixture password")?;
        let local=$finish!($client.login_session(Credentials::new("admin",password),client_id.clone()))?;
        passed("local administrator session is available before external setup")?;
        let state=$finish!(local.effective_authentication_settings())?;
        let definition=$config["definition"].clone();
        let secret=ProviderCredentialInput::replace($config["client_secret"].as_str().ok_or("Missing client secret")?)?;
        let provider=match $config["kind"].as_str() {
            Some("oidc") => ProviderConfigurationInput::oidc(definition,secret)?,
            Some("oauth") => ProviderConfigurationInput::oauth(definition,secret)?,
            _ => return Err("Unsupported fixture kind".into()),
        };
        let mut update=AuthenticationProviderUpdate::runtime("sdk-consumer",provider)?;
        if let Some(existing)=state.providers().iter().find(|p|p.name=="sdk-consumer").and_then(|p|p.provider_id.clone()) {
            update=update.existing(existing)?;
        }
        let report=$finish!(local.create_security_candidate(SecurityCandidateRequest::authentication(
            state.expected_revision(),vec![update],
        )))?;
        let provider_id=report.providers.first().ok_or("Candidate has no provider")?.provider_id.clone();
        emit(json!({"event":"provider","id":provider_id.as_str()}))?;
        proceed()?;
        let verification=$finish!(local.begin_provider_verification_interaction(
            AuthenticationInteractionRequest::new(client_id.clone(),provider_id.clone()),report.id.clone(),
        ))?;
        browser(verification.id(),verification.next())?;
        let verified=$finish!(verification.complete())?;
        if verified.verification.issued_session || verified.verification.provisioned { return Err("Preview had live effects".into()); }
        emit(json!({"event":"preview_completed"}))?;
        proceed()?;
        let operation=CredentialOperation::activate_security_candidate(verified.candidate.into_activation()?);
        let approved=$finish!(local.credential_approvals().approve(password,operation))?;
        let activated=$finish!(approved.send())?;
        if !activated.changed { return Err("Candidate did not activate".into()); }
        passed("runtime encrypted configuration, non-login preview and exact fresh-approved activation")?;
        let methods=$finish!($client.authentication_methods())?;
        let method=methods.methods.iter().find(|m|m.provider_id==provider_id).ok_or("Activated provider absent")?;
        let is_oauth=method.kind==AuthenticationProviderKind::Oauth;
        let mut stable_principal=None;
        for attempt in 0..2 {
            let mut flow=$finish!($client.begin_login_interaction(AuthenticationInteractionRequest::new(client_id.clone(),provider_id.clone())))?;
            browser(flow.id(),flow.next())?;
            $sleep!(flow.poll_after());
            let status=$finish!(flow.poll())?;
            if status.state!=AuthenticationInteractionState::Ready { return Err("Fixture interaction not ready".into()); }
            let session=$finish!(flow.complete())?;
            let identity=$finish!(session.me())?;
            if stable_principal.is_some_and(|id|id!=identity.principal.principal_id) { return Err("Provider identity changed".into()); }
            stable_principal=Some(identity.principal.principal_id);
            if attempt==0 {
                let before=session.session_info().ok_or("Missing session metadata")?;
                let token=session.token()?;
                let expires:SystemTime=before.access_expires_at().0.into();
                let delay=expires.duration_since(SystemTime::now()).unwrap_or_default()+Duration::from_millis(100);
                if delay>Duration::from_secs(35) { return Err("Fixture access lifetime must be 30 seconds".into()); }
                $sleep!(delay);
                if $finish!(session.me())?.principal.principal_id!=identity.principal.principal_id || session.token()?==token || session.session_info().unwrap().id()!=before.id() {
                    return Err("Session renewal changed identity/family or failed to rotate".into());
                }
                passed("browser login adopts ordinary rotating session and retains principal and family")?;
            }
            let operation=CredentialOperation::create_token(identity.principal.principal_id,NewTokenRequest::new().name("sdk-project-consumer"));
            emit(json!({"event":"stage","stage":"fresh approval begin"}))?;
            let approval=$finish!(session.begin_credential_approval_interaction(AuthenticationInteractionRequest::new(client_id.clone(),provider_id.clone()),operation));
            match approval {
                Err(error) if is_oauth && error.is_capability_unsupported() => passed("OAuth fresh approval is explicitly unsupported")?,
                Ok(flow) if !is_oauth => {
                    emit(json!({"event":"stage","stage":"fresh approval browser"}))?;
                    browser(flow.id(),flow.next())?;
                    emit(json!({"event":"stage","stage":"fresh approval completion"}))?;
                    let approved=$finish!(flow.complete())?;
                    emit(json!({"event":"stage","stage":"fresh approved token issuance"}))?;
                    let token=$finish!(approved.send())?;
                    emit(json!({"event":"stage","stage":"fresh issued token cleanup"}))?;
                    let pat=$client.authenticate(token);
                    if $finish!(pat.me())?.principal.principal_id!=identity.principal.principal_id {return Err("PAT changed principal".into());}
                    $finish!(pat.logout())?;
                    passed("OIDC exact-operation fresh approval retains originating credential")?;
                }
                _ => return Err("Unexpected fresh-approval capability".into()),
            }
            let clone=session.clone();
            $finish!(session.logout())?;
            if $finish!(clone.me()).is_ok() { return Err("Logout left session authorized".into()); }
            passed("local logout revokes external session")?;
        }
        passed("repeat browser login resolves the same immutable principal")?;
        let mut recovery=$finish!($client.begin_login_interaction(AuthenticationInteractionRequest::new(client_id,AuthenticationProviderId::local())))?;
        $finish!(recovery.submit_credentials("admin",password))?;
        let recovery=$finish!(recovery.complete())?;
        if $finish!(recovery.me())?.principal.name!="admin" { return Err("Local recovery identity changed".into()); }
        $finish!(recovery.logout())?;
        passed("local recovery remains available after runtime activation")?;
        $finish!(local.logout())?;
        emit(json!({"event":"complete"}))?;
        Ok(())
    }};
}

fn execute() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let mode = args.next().ok_or("Missing client mode")?;
    let config: Value =
        serde_json::from_slice(&fs::read(args.next().ok_or("Missing fixture file")?)?)?;
    let base = BaseUrl::new(config["origin"].as_str().ok_or("Missing public origin")?)?;
    let ca = reqwest::Certificate::from_pem(&fs::read(
        config["ca_file"].as_str().ok_or("Missing CA")?,
    )?)?;
    match mode.as_str() {
        "blocking" => {
            macro_rules! finish {
                ($request:expr) => {
                    $request
                };
            }
            macro_rules! sleep {
                ($delay:expr) => {
                    std::thread::sleep($delay)
                };
            }
            let http = reqwest::blocking::Client::builder()
                .add_root_certificate(ca)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?;
            let client = blocking::Client::builder(base)
                .with_http_client(http)
                .build()?;
            run!(client, config, finish, sleep)
        }
        "async" => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                macro_rules! finish {
                    ($request:expr) => {
                        $request.await
                    };
                }
                macro_rules! sleep {
                    ($delay:expr) => {
                        tokio::time::sleep($delay).await
                    };
                }
                let http = reqwest::Client::builder()
                    .add_root_certificate(ca)
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(30))
                    .build()?;
                let client = Client::builder(base).with_http_client(http).build()?;
                run!(client, config, finish, sleep)
            }),
        _ => Err("Unknown client mode".into()),
    }
}

fn main() -> std::process::ExitCode {
    match execute() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            if let Some(error) = error.downcast_ref::<hubuum_client::ApiError>() {
                let category = if error.json_error().is_some() {
                    "json"
                } else {
                    "api"
                };
                let _ = emit(
                    json!({"event":"failure","category":category,"status":error.status().map(|s|s.as_u16())}),
                );
            }
            eprintln!("Project authentication consumer failed; inspect the last sanitized stage.");
            std::process::ExitCode::FAILURE
        }
    }
}
