use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};

use crate::{ApiError, BaseUrl, Credentials, HubuumDateTime, SessionClientId, SessionInfo, Token};

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

#[derive(Clone, Deserialize, Serialize)]
struct WirePair {
    session_id: String,
    token_type: String,
    #[serde(serialize_with = "serialize_secret")]
    access_token: SecretString,
    #[serde(serialize_with = "serialize_secret")]
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
        Self::from_wire(wire, false)
    }

    fn from_wire(wire: WirePair, restoring: bool) -> Result<Self, ApiError> {
        let now = Utc::now();
        if wire.token_type != "Bearer"
            || wire.session_id.is_empty()
            || wire.session_id.len() > 128
            || wire.access_token.expose_secret().is_empty()
            || wire.refresh_token.expose_secret().is_empty()
            || wire.access_token.expose_secret() == wire.refresh_token.expose_secret()
            || (!restoring && wire.access_expires_at <= now)
            || wire.access_expires_at > wire.refresh_expires_at
            || wire.refresh_expires_at > wire.absolute_expires_at
        {
            return Err(ApiError::InvalidSessionResponse);
        }
        let remaining = (wire.access_expires_at - now).to_std().unwrap_or_default();
        let margin = if restoring {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(30).min(remaining / 10)
        };
        let refresh_at = Instant::now()
            .checked_add(remaining.saturating_sub(margin))
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

    pub(super) fn snapshot(
        &self,
        base_url: &BaseUrl,
        client_id: &SessionClientId,
    ) -> StoredSession {
        StoredSession {
            base_url: base_url.as_str().to_owned(),
            client_id: client_id.clone(),
            refresh_at: Utc::now()
                + chrono::Duration::from_std(
                    self.refresh_at.saturating_duration_since(Instant::now()),
                )
                .unwrap_or_default(),
            pair: WirePair {
                session_id: self.info.id.clone(),
                token_type: "Bearer".into(),
                access_token: SecretString::from(self.token.as_str().to_owned()),
                refresh_token: self.refresh.clone(),
                access_expires_at: self.info.access_expires_at.0,
                refresh_expires_at: self.info.refresh_expires_at.0,
                absolute_expires_at: self.info.absolute_expires_at.0,
            },
        }
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
    pub store: Option<Arc<dyn SessionStore>>,
    // A new login must not change the family owned by existing clients/clones.
    session_id: String,
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
            store: None,
            session_id: pair.info.id.clone(),
            pair: Mutex::new(Some(pair)),
            closed: AtomicBool::new(false),
            #[cfg(feature = "async")]
            async_lock: tokio::sync::Mutex::new(()),
            #[cfg(feature = "blocking")]
            blocking_lock: Mutex::new(()),
        }
    }

    pub fn with_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn reload(
        &self,
        guard: &dyn SessionStoreGuard,
        base_url: &BaseUrl,
    ) -> Result<(), ApiError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ApiError::SessionExpired);
        }
        let stored = guard.load()?.ok_or(ApiError::SessionExpired)?;
        let pair = stored.restore(base_url, &self.client_id)?;
        if pair.info.id != self.session_id {
            self.clear();
            return Err(ApiError::SessionExpired);
        }
        self.install(pair)
    }

    pub fn save(
        &self,
        guard: &mut dyn SessionStoreGuard,
        base_url: &BaseUrl,
    ) -> Result<(), ApiError> {
        let pair = self.pair.lock().map_err(|_| ApiError::SessionExpired)?;
        let pair = pair.as_ref().ok_or(ApiError::SessionExpired)?;
        guard.save(Some(&pair.snapshot(base_url, &self.client_id)))
    }

    pub fn forget(&self, guard: &mut dyn SessionStoreGuard) -> Result<(), ApiError> {
        self.clear();
        if let Some(stored) = guard.load()?
            && self.session_id == stored.pair.session_id
        {
            guard.save(None)?;
        }
        Ok(())
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

// Authentication errors must not retain reflected credentials, including errors
// supplied by custom transports. Preserve useful HTTP status without the body.
pub(super) fn login_error(error: ApiError) -> ApiError {
    match error {
        ApiError::HttpWithBody {
            method,
            url,
            status,
            ..
        } => ApiError::HttpWithBody {
            method,
            url,
            status,
            message: "Interactive session login failed".into(),
            body: String::new(),
        },
        ApiError::InvalidSessionResponse => ApiError::InvalidSessionResponse,
        _ => ApiError::Api("Interactive session login failed".into()),
    }
}

fn serialize_secret<S: Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}

/// Opaque, secret-bearing session snapshot for an application-owned store.
///
/// Serialization deliberately includes both credentials. Protect serialized data
/// like a password. Debug output is redacted. Snapshots are bound to the API base
/// URL and client ID and validated before use; the store must additionally isolate
/// different users and identity providers.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredSession {
    base_url: String,
    client_id: SessionClientId,
    refresh_at: DateTime<Utc>,
    pair: WirePair,
}

impl std::fmt::Debug for StoredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSession").finish_non_exhaustive()
    }
}

impl StoredSession {
    pub(super) fn restore(
        &self,
        base_url: &BaseUrl,
        client_id: &SessionClientId,
    ) -> Result<SessionPair, ApiError> {
        if self.base_url != base_url.as_str() || &self.client_id != client_id {
            return Err(ApiError::InvalidSessionResponse);
        }
        if self.refresh_at > self.pair.access_expires_at {
            return Err(ApiError::InvalidSessionResponse);
        }
        let mut pair = SessionPair::from_wire(self.pair.clone(), true)?;
        pair.refresh_at = Instant::now()
            .checked_add((self.refresh_at - Utc::now()).to_std().unwrap_or_default())
            .ok_or(ApiError::InvalidSessionResponse)?;
        Ok(pair)
    }

    pub(super) fn expired(&self) -> bool {
        Utc::now() >= self.pair.refresh_expires_at
    }
}

/// Application-owned, identity-scoped persistent session storage.
///
/// `lock` must exclusively coordinate all processes using the same session, and
/// return an owned guard whose drop releases the lock. Async clients acquire this
/// potentially blocking lock on a blocking worker. Guard I/O should be brief.
/// Implementations must protect secrets and avoid including them in errors.
pub trait SessionStore: std::fmt::Debug + Send + Sync {
    fn lock(&self) -> Result<Box<dyn SessionStoreGuard>, ApiError>;
}

/// Exclusive transaction over one identity's session.
///
/// `save` must atomically and durably replace the stored value before returning.
/// The SDK saves `None` before sending a single-use refresh credential, then saves
/// its successor before using it. A crash, cancellation or uncertain exchange
/// therefore requires a new login instead of replaying a consumed credential.
pub trait SessionStoreGuard: Send + Sync {
    fn load(&self) -> Result<Option<StoredSession>, ApiError>;
    fn save(&mut self, session: Option<&StoredSession>) -> Result<(), ApiError>;
}
