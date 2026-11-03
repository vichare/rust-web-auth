use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Consumer-owned business user identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(String);

impl UserId {
    /// Creates a non-empty user identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is empty or longer than 512 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() || value.len() > 512 {
            return Err("user id must contain 1 to 512 bytes");
        }
        Ok(Self(value))
    }

    /// Returns the consumer identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable verified OIDC identity key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityKey {
    /// Verified issuer URL.
    pub issuer: String,
    /// Verified immutable subject identifier.
    pub subject: String,
}

/// Identity claims accepted after complete provider verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedIdentity {
    /// Stable identity key. Email is intentionally excluded.
    pub key: IdentityKey,
    /// Email accepted only after an `email_verified=true` claim.
    pub verified_email: String,
    /// Provider profile name, when supplied.
    pub display_name: Option<String>,
}

/// Persisted one-time authorization attempt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginAttempt {
    /// Keyed digest of the raw state value.
    pub state_digest: [u8; 32],
    /// PKCE verifier deleted atomically when the attempt is consumed.
    pub pkce_verifier: String,
    /// OIDC nonce deleted atomically when the attempt is consumed.
    pub nonce: String,
    /// Exact validated redirect URI used at both endpoints.
    pub redirect_uri: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Exclusive expiry time.
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for LoginAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginAttempt")
            .field("state_digest", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl LoginAttempt {
    /// Returns whether the attempt is valid at `now`.
    #[must_use]
    pub fn is_available_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.created_at && now < self.expires_at
    }
}

/// Stable application-session identifier.
pub type SessionId = Uuid;

/// Persisted application session. Only a keyed token digest is stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// Stable session identifier.
    pub session_id: SessionId,
    /// Consumer-owned user identifier.
    pub user_id: UserId,
    /// Keyed digest of the random token.
    pub token_digest: [u8; 32],
    /// Fresh-login time.
    pub created_at: DateTime<Utc>,
    /// Last persisted activity time.
    pub last_activity_at: DateTime<Utc>,
    /// Sliding expiry.
    pub expires_at: DateTime<Utc>,
    /// Revocation time.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Optimistic concurrency revision.
    pub version: u64,
}

impl SessionRecord {
    /// Returns whether this session authenticates at `now`.
    #[must_use]
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && now >= self.created_at && now < self.expires_at
    }
}

/// Trusted authentication result for business handlers.
///
/// Business code should obtain `user_id` only from this context, never from a
/// request body, query parameter, or route parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedContext {
    /// Authenticated business user.
    pub user_id: UserId,
    /// Current device/session.
    pub session_id: SessionId,
    /// Fresh sign-in time.
    pub session_created_at: DateTime<Utc>,
    /// New cookie expiry when this request won a sliding-renewal CAS.
    pub renewed_expires_at: Option<DateTime<Utc>>,
}
