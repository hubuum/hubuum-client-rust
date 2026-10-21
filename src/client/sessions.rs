use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{ApiError, Credentials, HubuumDateTime, SessionClientId, SessionInfo, Token};

#[derive(Serialize)]
pub(super) struct SessionLogin<'a> {
    #[serde(flatten)]
    pub credentials: &'a Credentials,
    pub client_id: &'a SessionClientId,
}

#[derive(Serialize)]
pub(super) struct SessionRefresh<'a> {
    client_id: &'a SessionClientId,
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct WirePair {
    session_id: String,
    token_type: String,
    access_token: SecretString,
    refresh_token: SecretString,
    access_expires_at: DateTime<Utc>,
    refresh_expires_at: DateTime<Utc>,
    absolute_expires_at: DateTime<Utc>,
}

pub(super) struct SessionPair {
    token: Token,
    refresh: SecretString,
    info: SessionInfo,
    refresh_at: Instant,
}

impl SessionPair {
    pub fn decode(body: &[u8]) -> Result<Self, ApiError> {
        let wire: WirePair =
            serde_json::from_slice(body).map_err(|_| ApiError::InvalidSessionResponse)?;
        let now = Utc::now();
        if wire.token_type != "Bearer"
            || wire.session_id.is_empty()
            || wire.session_id.len() > 128
            || wire.access_token.expose_secret().is_empty()
            || wire.refresh_token.expose_secret().is_empty()
            || wire.access_token.expose_secret() == wire.refresh_token.expose_secret()
            || wire.access_expires_at <= now
            || wire.access_expires_at > wire.refresh_expires_at
            || wire.refresh_expires_at > wire.absolute_expires_at
        {
            return Err(ApiError::InvalidSessionResponse);
        }
        let remaining = (wire.access_expires_at - now)
            .to_std()
            .map_err(|_| ApiError::InvalidSessionResponse)?;
        let refresh_after = remaining - Duration::from_secs(30).min(remaining / 10);
        let refresh_at = Instant::now()
            .checked_add(refresh_after)
            .ok_or(ApiError::InvalidSessionResponse)?;
        Ok(Self {
            token: Token::issued(wire.access_token, HubuumDateTime(wire.access_expires_at)),
            refresh: wire.refresh_token,
            info: SessionInfo {
                id: wire.session_id,
                access_expires_at: HubuumDateTime(wire.access_expires_at),
                refresh_expires_at: HubuumDateTime(wire.refresh_expires_at),
                absolute_expires_at: HubuumDateTime(wire.absolute_expires_at),
            },
            refresh_at,
        })
    }

    pub fn validate_successor(&self, previous: &Self) -> Result<(), ApiError> {
        if self.info.id != previous.info.id
            || self.info.absolute_expires_at != previous.info.absolute_expires_at
            || self.refresh.expose_secret() == previous.refresh.expose_secret()
        {
            return Err(ApiError::InvalidSessionResponse);
        }
        Ok(())
    }

    pub fn request<'a>(&'a self, client_id: &'a SessionClientId) -> SessionRefresh<'a> {
        SessionRefresh {
            client_id,
            refresh_token: self.refresh.expose_secret(),
        }
    }
}

pub(super) struct SessionState {
    pub client_id: SessionClientId,
    pair: Mutex<Option<SessionPair>>,
    closed: AtomicBool,
    #[cfg(feature = "async")]
    pub async_lock: tokio::sync::Mutex<()>,
    #[cfg(feature = "blocking")]
    pub blocking_lock: Mutex<()>,
}

impl SessionState {
    pub fn new(pair: SessionPair, client_id: SessionClientId) -> Self {
        Self {
            client_id,
            pair: Mutex::new(Some(pair)),
            closed: AtomicBool::new(false),
            #[cfg(feature = "async")]
            async_lock: tokio::sync::Mutex::new(()),
            #[cfg(feature = "blocking")]
            blocking_lock: Mutex::new(()),
        }
    }

    pub fn token(&self) -> Result<Token, ApiError> {
        let pair = self.pair.lock().map_err(|_| ApiError::SessionExpired)?;
        pair.as_ref()
            .map(|pair| pair.token.clone())
            .ok_or(ApiError::SessionExpired)
    }

    pub fn info(&self) -> Option<SessionInfo> {
        self.pair
            .lock()
            .ok()?
            .as_ref()
            .map(|pair| pair.info.clone())
    }

    // Called with the runtime's single-flight lock held. Taking the pair before
    // sending means cancellation or an uncertain response cannot reuse it.
    pub fn take_if_due(&self) -> Result<Option<SessionPair>, ApiError> {
        let mut guard = self.pair.lock().map_err(|_| ApiError::SessionExpired)?;
        let pair = guard.as_ref().ok_or(ApiError::SessionExpired)?;
        if Utc::now() >= pair.info.refresh_expires_at.0 {
            *guard = None;
            return Err(ApiError::SessionExpired);
        }
        if Instant::now() < pair.refresh_at && Utc::now() < pair.info.access_expires_at.0 {
            return Ok(None);
        }
        Ok(guard.take())
    }

    pub fn install(&self, pair: SessionPair) -> Result<(), ApiError> {
        let mut guard = self.pair.lock().map_err(|_| ApiError::SessionExpired)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(ApiError::SessionExpired);
        }
        *guard = Some(pair);
        Ok(())
    }

    pub fn clear(&self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut pair) = self.pair.lock() {
            *pair = None;
        }
    }
}
