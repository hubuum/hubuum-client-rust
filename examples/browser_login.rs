//! Project-only browser login. Supply public HUBUUM_URL and HUBUUM_PROVIDER_ID.
//! Local/LDAP use the Hubuum-hosted password form; no passwords enter this process.
use std::{env, error::Error};

use hubuum_client::{
    AuthenticationInteractionRequest, AuthenticationInteractionState, AuthenticationNext,
    AuthenticationProviderId, Client, SessionClientId,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::from_url(&env::var("HUBUUM_URL")?)?;
    let provider = AuthenticationProviderId::new(env::var("HUBUUM_PROVIDER_ID")?)?;
    let methods = client.authentication_methods().await?;
    let method = methods
        .methods
        .iter()
        .find(|m| m.provider_id == provider)
        .ok_or("Provider is unavailable")?;
    if !method.browser_available {
        return Err("Provider has no hosted browser capability".into());
    }
    let mut flow = client
        .begin_login_interaction(
            AuthenticationInteractionRequest::new(
                SessionClientId::new("hubuum-sdk-browser-example")?,
                provider,
            )
            .hosted_browser(),
        )
        .await?;
    match flow.next() {
        AuthenticationNext::Browser {
            verification_uri,
            user_code,
        } => {
            println!("Open {verification_uri} and enter {user_code}");
        }
        _ => {
            flow.cancel().await?;
            return Err("Expected a browser interaction".into());
        }
    }
    loop {
        tokio::time::sleep(flow.poll_after()).await;
        match flow.poll().await {
            Ok(status) if status.state == AuthenticationInteractionState::Ready => break,
            Ok(status) if status.state.is_terminal() => return Err("Authentication stopped".into()),
            Ok(_) => (),
            Err(error)
                if error
                    .status()
                    .is_some_and(|s| s.as_u16() == 429 || s.as_u16() == 503) => {}
            Err(error) => {
                let _ = flow.cancel().await;
                return Err(error.into());
            }
        }
    }
    let cleanup = flow.issued_session_cleanup();
    let session = match flow.complete().await {
        Ok(session) => session,
        Err(error) => {
            let _ = cleanup.revoke().await;
            return Err(error.into());
        }
    };
    let identity = session.me().await;
    session.logout().await?;
    identity?;
    println!("Authenticated and logged out.");
    Ok(())
}
