//! Validated origin-bound interaction capabilities shared by both transports.
use std::time::{Duration, Instant};

use chrono::Utc;
use reqwest::{StatusCode, header::HeaderMap};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AuthenticationInteractionId, AuthenticationInteractionStatus, AuthenticationNext,
    BaseUrl, HubuumDateTime, SessionClientId,
};

#[derive(Clone, Debug)]
pub(super) struct InteractionAccess {
    id: AuthenticationInteractionId,
    client_id: SessionClientId,
    secret: SecretString,
}

impl InteractionAccess {
    pub fn id(&self) -> &AuthenticationInteractionId {
        &self.id
    }

    pub fn client_id(&self) -> &SessionClientId {
        &self.client_id
    }

    pub fn authorization(&self) -> String {
        format!("Hubuum-Interaction {}", self.secret.expose_secret())
    }

    pub fn body(&self) -> impl Serialize + '_ {
        #[derive(Serialize)]
        struct Request<'a> {
            client_id: &'a SessionClientId,
        }
        Request {
            client_id: &self.client_id,
        }
    }
}

#[derive(Deserialize)]
struct WireBegun {
    id: AuthenticationInteractionId,
    interaction_version: u8,
    redemption_secret: SecretString,
    expires_at: HubuumDateTime,
    interval_seconds: u32,
    next: AuthenticationNext,
}

#[derive(Debug)]
pub(super) struct InteractionBinding {
    access: InteractionAccess,
    expires_at: HubuumDateTime,
    next: AuthenticationNext,
    interval: Duration,
    next_poll: Instant,
    deadline: Instant,
    closed: bool,
}

impl InteractionBinding {
    pub fn decode(
        body: &[u8],
        base: &BaseUrl,
        client_id: SessionClientId,
    ) -> Result<Self, ApiError> {
        let value: WireBegun =
            serde_json::from_slice(body).map_err(|_| ApiError::InvalidAuthenticationInteraction)?;
        let secret = value.redemption_secret.expose_secret();
        if value.interaction_version != 1
            || secret.len() != 69
            || !secret.starts_with("hai1.")
            || !secret.as_bytes()[5..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            || !(1..=600).contains(&value.interval_seconds)
        {
            return Err(ApiError::InvalidAuthenticationInteraction);
        }
        let remaining = (value.expires_at.0 - Utc::now())
            .to_std()
            .map_err(|_| ApiError::AuthenticationInteractionExpired)?
            .min(Duration::from_secs(600));
        if remaining.is_zero() {
            return Err(ApiError::AuthenticationInteractionExpired);
        }
        if let AuthenticationNext::Browser {
            verification_uri,
            user_code,
        } = &value.next
        {
            let uri = url::Url::parse(verification_uri)
                .map_err(|_| ApiError::InvalidAuthenticationInteraction)?;
            if uri.origin() != base.as_url().origin()
                || !uri.username().is_empty()
                || uri.password().is_some()
                || uri.query().is_some()
                || uri.fragment().is_some()
                || user_code.is_empty()
                || user_code.len() > 128
                || user_code.chars().any(char::is_control)
            {
                return Err(ApiError::InvalidAuthenticationInteraction);
            }
        }
        let interval = Duration::from_secs(value.interval_seconds.into());
        Ok(Self {
            access: InteractionAccess {
                id: value.id,
                client_id,
                secret: value.redemption_secret,
            },
            expires_at: value.expires_at,
            next: value.next,
            interval,
            next_poll: Instant::now() + interval,
            deadline: Instant::now() + remaining,
            closed: false,
        })
    }

    pub fn access(&self) -> &InteractionAccess {
        &self.access
    }

    pub fn next(&self) -> &AuthenticationNext {
        &self.next
    }

    pub fn expires_at(&self) -> &HubuumDateTime {
        &self.expires_at
    }

    pub fn ensure_live(&self) -> Result<(), ApiError> {
        if self.closed {
            return Err(ApiError::AuthenticationInteractionTerminated);
        }
        if Instant::now() >= self.deadline || Utc::now() >= self.expires_at.0 {
            Err(ApiError::AuthenticationInteractionExpired)
        } else {
            Ok(())
        }
    }

    pub fn poll_after(&self) -> Duration {
        self.next_poll
            .saturating_duration_since(Instant::now())
            .min(self.deadline.saturating_duration_since(Instant::now()))
    }

    pub fn before_poll(&self) -> Result<(), ApiError> {
        self.ensure_live()?;
        if Instant::now() < self.next_poll {
            Err(ApiError::AuthenticationPollingTooEarly)
        } else {
            Ok(())
        }
    }

    pub fn after_poll(&mut self, status: StatusCode, headers: &HeaderMap) {
        if status.is_client_error() && status != StatusCode::TOO_MANY_REQUESTS {
            self.closed = true;
        }
        if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE {
            let retry = super::shared::retry_after(headers).unwrap_or(Duration::ZERO);
            self.interval = self
                .interval
                .saturating_add(Duration::from_secs(5))
                .max(retry)
                .min(Duration::from_secs(600));
        }
        self.schedule_poll();
    }

    pub fn after_transport_failure(&mut self) {
        self.interval = self
            .interval
            .saturating_mul(2)
            .min(Duration::from_secs(600));
        self.schedule_poll();
    }

    fn schedule_poll(&mut self) {
        let jitter = Duration::from_millis(fastrand::u64(0..=self.interval.as_millis() as u64 / 5));
        self.next_poll = Instant::now() + self.interval + jitter;
    }

    pub fn decode_status(
        &mut self,
        body: &[u8],
    ) -> Result<AuthenticationInteractionStatus, ApiError> {
        let status: AuthenticationInteractionStatus =
            serde_json::from_slice(body).map_err(|_| ApiError::InvalidAuthenticationInteraction)?;
        if status.id != self.access.id || status.expires_at != self.expires_at {
            return Err(ApiError::InvalidAuthenticationInteraction);
        }
        if status.state.is_terminal() {
            self.closed = true;
        }
        Ok(status)
    }
}

#[derive(Serialize)]
pub(super) struct InteractionCredentials<'a> {
    pub client_id: &'a SessionClientId,
    pub name: &'a str,
    #[serde(serialize_with = "crate::types::serialize_secret")]
    pub password: SecretString,
}
