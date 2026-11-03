use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use url::Url;

use crate::{IdentityKey, LoginAttempt, SessionId, SessionRecord, UserId, VerifiedIdentity};

/// Persistence failure safe to expose across the library boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("authentication persistence failed")]
pub struct StorageError;

/// Result of an optimistic compare-and-swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasOutcome {
    /// The expected record was replaced.
    Updated,
    /// The record changed or disappeared.
    Stale,
}

/// Outcome from a consumer-provided start-login limiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Login may start.
    Allowed,
    /// Login must be rejected.
    Rejected,
}

/// Atomic persistence port for short-lived login attempts.
#[async_trait]
pub trait AttemptStore: Send + Sync {
    /// Inserts without replacing an existing digest.
    async fn create(&self, attempt: LoginAttempt) -> Result<(), StorageError>;

    /// Atomically checks availability, consumes, and deletes the record.
    ///
    /// Exactly one concurrent caller may receive `Some`. Implementations must
    /// not split the read and delete into separate transactions.
    async fn consume_and_delete(
        &self,
        state_digest: &[u8; 32],
        now: DateTime<Utc>,
    ) -> Result<Option<LoginAttempt>, StorageError>;

    /// Removes expired or otherwise unavailable records.
    async fn cleanup(&self, now: DateTime<Utc>) -> Result<usize, StorageError>;
}

/// Consumer-owned mapping from verified identity to business user.
#[async_trait]
pub trait IdentityMapper: Send + Sync {
    /// Finds or atomically creates the user for `(issuer, subject)`.
    ///
    /// Implementations may update profile fields, but must never look up or
    /// merge users by email address.
    async fn resolve_user(&self, identity: &VerifiedIdentity) -> Result<UserId, StorageError>;

    /// Optional lookup useful to audit mappings.
    async fn find_user(&self, key: &IdentityKey) -> Result<Option<UserId>, StorageError>;
}

/// Consumer-owned application-session persistence.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Creates a new session and both token/user indexes atomically.
    async fn create(&self, session: SessionRecord) -> Result<(), StorageError>;
    /// Finds by keyed token digest.
    async fn find_by_token_digest(
        &self,
        token_digest: &[u8; 32],
    ) -> Result<Option<SessionRecord>, StorageError>;
    /// Finds by stable identifier.
    async fn find_by_id(
        &self,
        session_id: SessionId,
    ) -> Result<Option<SessionRecord>, StorageError>;
    /// Replaces only when the complete expected record is unchanged.
    async fn replace_if_unchanged(
        &self,
        expected: &SessionRecord,
        replacement: SessionRecord,
    ) -> Result<CasOutcome, StorageError>;
    /// Atomically revokes all active sessions for a user.
    async fn revoke_all_for_user(
        &self,
        user_id: &UserId,
        revoked_at: DateTime<Utc>,
    ) -> Result<usize, StorageError>;
}

/// Rate-limit port called before secrets or provider URLs are generated.
#[async_trait]
pub trait LoginRateLimiter: Send + Sync {
    /// Checks and records one login-start attempt for a consumer-defined key.
    async fn check(&self, key: &str, now: DateTime<Utc>)
    -> Result<RateLimitDecision, StorageError>;
}

/// Classified OIDC provider failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    /// Discovery, JWKS, or token endpoint unavailable.
    #[error("OIDC provider unavailable")]
    ProviderUnavailable,
    /// Authorization code or ID token rejected.
    #[error("OIDC token rejected")]
    TokenRejected,
    /// A verified token lacks required profile claims.
    #[error("OIDC identity incomplete")]
    IdentityIncomplete,
}

/// Backend-only OIDC relying-party adapter.
#[async_trait]
pub trait OidcProvider: Send + Sync {
    /// Builds the browser authorization URL.
    fn authorization_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: &str,
    ) -> Url;

    /// Exchanges the code on the backend and verifies the returned ID token.
    ///
    /// Implementations must not expose the code, access token, or ID token to
    /// frontend code.
    async fn redeem_code(
        &self,
        authorization_code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ProviderError>;
}
