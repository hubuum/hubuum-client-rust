use std::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};

use crate::{ApiError, HubuumDateTime, PrincipalId};

/// Validated source-history pagination: offset 0–256 and limit 1–100.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialActivityPageOptions {
    offset: usize,
    limit: usize,
}

impl Default for CredentialActivityPageOptions {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 50,
        }
    }
}

impl CredentialActivityPageOptions {
    pub fn offset(mut self, offset: usize) -> Result<Self, ApiError> {
        if offset > 256 {
            return Err(ApiError::InvalidCredentialActivityPagination {
                reason: "offset must be between 0 and 256",
            });
        }
        self.offset = offset;
        Ok(self)
    }

    pub fn limit(mut self, limit: usize) -> Result<Self, ApiError> {
        if !(1..=100).contains(&limit) {
            return Err(ApiError::InvalidPageLimit {
                value: limit,
                min: 1,
                max: 100,
            });
        }
        self.limit = limit;
        Ok(self)
    }

    pub const fn offset_value(&self) -> usize {
        self.offset
    }
    pub const fn limit_value(&self) -> usize {
        self.limit
    }
}

/// Immutable issuance evidence. The issuer can differ from the token's owner.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialCreationResponse {
    pub issuer_id: Option<PrincipalId>,
    /// Server-defined method, such as `login`, `creation`, or `renewal`.
    pub issuance_method: String,
    pub issued_at: HubuumDateTime,
    pub address: Option<IpAddr>,
    /// `connection_peer`, `trusted_forwarded`, or `unavailable` on server 0.0.20.
    pub address_method: String,
}

impl fmt::Debug for CredentialCreationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialCreationResponse")
            .field("issuer_id", &self.issuer_id)
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

/// One distinct address/resolution-method pair observed during authentication.
/// Times are approximate; a later authorization denial still counts as use.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSourceResponse {
    pub address: Option<IpAddr>,
    pub address_method: String,
    pub first_seen: HubuumDateTime,
    pub last_seen: HubuumDateTime,
}

impl fmt::Debug for CredentialSourceResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialSourceResponse")
            .field("first_seen", &self.first_seen)
            .field("last_seen", &self.last_seen)
            .finish_non_exhaustive()
    }
}

/// One page of best-effort credential activity, independent of token revisions.
/// This is not a complete request ledger or proof of authorized use.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialActivityResponse {
    /// Rotating access tokens share their session family's creation and sources.
    pub session_id: Option<String>,
    /// Historical credentials can have no creation evidence.
    pub creation: Option<CredentialCreationResponse>,
    pub sources: Vec<CredentialSourceResponse>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub next_offset: Option<usize>,
    pub collection_enabled: bool,
    pub best_effort: bool,
    pub retention_days: i64,
    pub source_cap: usize,
    /// First omitted source after reaching the cap; remains set after rows expire.
    pub overflow_since: Option<HubuumDateTime>,
}

impl CredentialActivityResponse {
    /// Options for the next page, preserving the server's page size.
    /// Rejects non-advancing or out-of-range continuations before another request.
    pub fn next_page_options(&self) -> Result<Option<CredentialActivityPageOptions>, ApiError> {
        let Some(offset) = self.next_offset else {
            return Ok(None);
        };
        if offset <= self.offset {
            return Err(ApiError::InvalidCredentialActivityPagination {
                reason: "next offset must advance",
            });
        }
        CredentialActivityPageOptions::default()
            .offset(offset)?
            .limit(self.limit)
            .map(Some)
    }
}

impl fmt::Debug for CredentialActivityResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialActivityResponse")
            .field("creation", &self.creation)
            .field("sources", &self.sources)
            .field("total", &self.total)
            .field("offset", &self.offset)
            .field("limit", &self.limit)
            .field("next_offset", &self.next_offset)
            .field("collection_enabled", &self.collection_enabled)
            .field("best_effort", &self.best_effort)
            .field("retention_days", &self.retention_days)
            .field("source_cap", &self.source_cap)
            .field("overflow_since", &self.overflow_since)
            .finish_non_exhaustive()
    }
}
