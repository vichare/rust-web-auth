use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::ports::{
    AttemptStore, CasOutcome, IdentityMapper, LoginRateLimiter, OidcProvider, ProviderError,
    RateLimitDecision, SessionStore, StorageError,
};
use crate::secrets::{keyed_digest, parse_token, random_token, s256_challenge, secrets_equal};
use crate::{AuthenticatedContext, LoginAttempt, SessionRecord, UserId};

/// Validated login-service configuration.
#[derive(Clone)]
pub struct LoginConfig {
    redirect_uri: String,
    attempt_lifetime: Duration,
    state_digest_key: [u8; 32],
}

impl LoginConfig {
    /// Creates production defaults: exact redirect URI and a ten-minute attempt.
    ///
    /// HTTPS is required except for loopback development addresses. Query,
    /// fragment, userinfo, and non-root-relative callback ambiguity are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`LoginError::InvalidConfiguration`] for an unsafe URI.
    pub fn new(
        redirect_uri: impl Into<String>,
        state_digest_key: [u8; 32],
    ) -> Result<Self, LoginError> {
        let redirect_uri = redirect_uri.into();
        validate_redirect_uri(&redirect_uri)?;
        Ok(Self {
            redirect_uri,
            attempt_lifetime: Duration::minutes(10),
            state_digest_key,
        })
    }

    /// Overrides the attempt lifetime. Values must be positive and no longer
    /// than one hour.
    ///
    /// # Errors
    ///
    /// Returns [`LoginError::InvalidConfiguration`] outside the allowed range.
    pub fn with_attempt_lifetime(mut self, lifetime: Duration) -> Result<Self, LoginError> {
        if lifetime <= Duration::zero() || lifetime > Duration::hours(1) {
            return Err(LoginError::InvalidConfiguration);
        }
        self.attempt_lifetime = lifetime;
        Ok(self)
    }
}

/// Successful login-start response for an HTTP adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginStart {
    /// URL to redirect the browser to.
    pub authorization_url: Url,
    /// Raw state stored only in an `HttpOnly` host cookie.
    pub state_cookie_value: String,
    /// Attempt expiry for the state cookie.
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for LoginStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginStart")
            .field("authorization_url", &"[REDACTED]")
            .field("state_cookie_value", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Untrusted values from the provider callback and state cookie.
#[derive(Clone, Copy)]
pub struct LoginCallback<'a> {
    /// Query `state`.
    pub state: Option<&'a str>,
    /// State cookie.
    pub state_cookie: Option<&'a str>,
    /// Query authorization code.
    pub authorization_code: Option<&'a str>,
    /// Whether the provider returned an OAuth error.
    pub provider_reported_error: bool,
}

impl fmt::Debug for LoginCallback<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginCallback")
            .field("state", &self.state.map(|_| "[REDACTED]"))
            .field("state_cookie", &self.state_cookie.map(|_| "[REDACTED]"))
            .field(
                "authorization_code",
                &self.authorization_code.map(|_| "[REDACTED]"),
            )
            .field("provider_reported_error", &self.provider_reported_error)
            .finish()
    }
}

/// A newly issued session. Its debug form intentionally redacts the token.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginCompletion {
    /// Raw random token for a response cookie. Never persist or log it.
    pub cookie_value: String,
    /// Authenticated consumer user.
    pub user_id: UserId,
    /// Stable session identifier.
    pub session_id: Uuid,
    /// Cookie and persisted expiry.
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for LoginCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginCompletion")
            .field("cookie_value", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Login orchestration failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LoginError {
    /// Redirect URI or lifetime is unsafe.
    #[error("invalid authentication configuration")]
    InvalidConfiguration,
    /// Login-start limiter rejected this key.
    #[error("login start rate limited")]
    RateLimited,
    /// State/cookie is missing, mismatched, expired, malformed, or replayed.
    #[error("invalid or expired login attempt")]
    InvalidAttempt,
    /// User denied access or provider returned an OAuth error.
    #[error("provider authorization denied")]
    AccessDenied,
    /// Discovery, JWKS, or token endpoint unavailable.
    #[error("OIDC provider unavailable")]
    ProviderUnavailable,
    /// Code or ID token rejected.
    #[error("OIDC token rejected")]
    TokenRejected,
    /// Verified token lacks required claims.
    #[error("OIDC identity incomplete")]
    IdentityIncomplete,
    /// Randomness or consumer persistence failed.
    #[error("authentication service failed")]
    Internal,
}

/// Backend-only Google/OIDC login orchestration.
pub struct LoginService {
    config: LoginConfig,
    provider: Arc<dyn OidcProvider>,
    attempts: Arc<dyn AttemptStore>,
    identities: Arc<dyn IdentityMapper>,
    limiter: Arc<dyn LoginRateLimiter>,
    sessions: Arc<SessionService>,
}

impl LoginService {
    /// Creates a service from consumer-owned ports.
    #[must_use]
    pub fn new(
        config: LoginConfig,
        provider: Arc<dyn OidcProvider>,
        attempts: Arc<dyn AttemptStore>,
        identities: Arc<dyn IdentityMapper>,
        limiter: Arc<dyn LoginRateLimiter>,
        sessions: Arc<SessionService>,
    ) -> Self {
        Self {
            config,
            provider,
            attempts,
            identities,
            limiter,
            sessions,
        }
    }

    /// Starts Authorization Code + S256 PKCE with state and nonce.
    ///
    /// `rate_limit_key` is consumer-defined, typically a privacy-preserving
    /// digest of client IP plus a coarse network prefix.
    ///
    /// # Errors
    ///
    /// Returns a classified [`LoginError`].
    pub async fn begin(
        &self,
        rate_limit_key: &str,
        now: DateTime<Utc>,
    ) -> Result<LoginStart, LoginError> {
        match self.limiter.check(rate_limit_key, now).await {
            Ok(RateLimitDecision::Allowed) => {}
            Ok(RateLimitDecision::Rejected) => return Err(LoginError::RateLimited),
            Err(_) => return Err(LoginError::Internal),
        }
        let state = random_token().map_err(|_| LoginError::Internal)?;
        let verifier = random_token().map_err(|_| LoginError::Internal)?;
        let nonce = random_token().map_err(|_| LoginError::Internal)?;
        let expires_at = now + self.config.attempt_lifetime;
        let state_digest = keyed_digest(&self.config.state_digest_key, state.as_bytes());
        let attempt = LoginAttempt {
            state_digest,
            pkce_verifier: verifier.clone(),
            nonce: nonce.clone(),
            redirect_uri: self.config.redirect_uri.clone(),
            created_at: now,
            expires_at,
        };
        self.attempts
            .create(attempt)
            .await
            .map_err(|_| LoginError::Internal)?;
        let authorization_url = self.provider.authorization_url(
            &self.config.redirect_uri,
            &state,
            &nonce,
            &s256_challenge(&verifier),
        );
        Ok(LoginStart {
            authorization_url,
            state_cookie_value: state,
            expires_at,
        })
    }

    /// Consumes a callback exactly once, verifies identity, maps the business
    /// user, and issues an application session.
    ///
    /// The attempt is consumed before provider interaction, including denial
    /// paths. Therefore a code is never exchanged twice by this service.
    ///
    /// # Errors
    ///
    /// Returns a classified [`LoginError`].
    pub async fn complete(
        &self,
        callback: LoginCallback<'_>,
        now: DateTime<Utc>,
    ) -> Result<LoginCompletion, LoginError> {
        let (Some(state), Some(cookie)) = (callback.state, callback.state_cookie) else {
            return Err(LoginError::InvalidAttempt);
        };
        if !secrets_equal(state, cookie) || parse_token(state).is_none() {
            return Err(LoginError::InvalidAttempt);
        }
        let state_digest = keyed_digest(&self.config.state_digest_key, state.as_bytes());
        let attempt = self
            .attempts
            .consume_and_delete(&state_digest, now)
            .await
            .map_err(|_| LoginError::Internal)?
            .filter(|attempt| attempt.is_available_at(now))
            .ok_or(LoginError::InvalidAttempt)?;
        if callback.provider_reported_error {
            return Err(LoginError::AccessDenied);
        }
        let code = callback
            .authorization_code
            .ok_or(LoginError::InvalidAttempt)?;
        let identity = self
            .provider
            .redeem_code(
                code,
                &attempt.redirect_uri,
                &attempt.pkce_verifier,
                &attempt.nonce,
            )
            .await
            .map_err(map_provider_error)?;
        let user_id = self
            .identities
            .resolve_user(&identity)
            .await
            .map_err(|_| LoginError::Internal)?;
        self.sessions
            .issue(user_id, now)
            .await
            .map_err(|_| LoginError::Internal)
    }

    /// Cleans expired attempts.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] from the consumer store.
    pub async fn cleanup_attempts(&self, now: DateTime<Utc>) -> Result<usize, StorageError> {
        self.attempts.cleanup(now).await
    }
}

fn map_provider_error(error: ProviderError) -> LoginError {
    match error {
        ProviderError::ProviderUnavailable => LoginError::ProviderUnavailable,
        ProviderError::TokenRejected => LoginError::TokenRejected,
        ProviderError::IdentityIncomplete => LoginError::IdentityIncomplete,
    }
}

fn validate_redirect_uri(value: &str) -> Result<(), LoginError> {
    let url = Url::parse(value).map_err(|_| LoginError::InvalidConfiguration)?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || url.path().is_empty()
    {
        return Err(LoginError::InvalidConfiguration);
    }
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(LoginError::InvalidConfiguration);
    }
    Ok(())
}

/// Application-session policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    /// Sliding lifetime.
    pub lifetime: Duration,
    /// Minimum interval between persisted activity writes.
    pub write_throttle: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            lifetime: Duration::days(30),
            write_throttle: Duration::hours(24),
        }
    }
}

/// Session lifecycle failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    /// Token is invalid or session is unavailable.
    #[error("session is unauthenticated")]
    Unauthenticated,
    /// Policy is invalid.
    #[error("invalid session configuration")]
    InvalidConfiguration,
    /// Randomness or persistence failed.
    #[error("session service failed")]
    Internal,
}

/// Issues, authenticates, renews, and revokes consumer-owned sessions.
pub struct SessionService {
    config: SessionConfig,
    store: Arc<dyn SessionStore>,
    token_digest_key: [u8; 32],
}

impl SessionService {
    /// Creates a session service.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidConfiguration`] for non-positive policy.
    pub fn new(
        config: SessionConfig,
        store: Arc<dyn SessionStore>,
        token_digest_key: [u8; 32],
    ) -> Result<Self, SessionError> {
        if config.lifetime <= Duration::zero()
            || config.write_throttle <= Duration::zero()
            || config.write_throttle >= config.lifetime
        {
            return Err(SessionError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            store,
            token_digest_key,
        })
    }

    /// Issues a random 256-bit session token and persists only its keyed digest.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Internal`] on randomness or persistence failure.
    pub async fn issue(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<LoginCompletion, SessionError> {
        let cookie_value = random_token().map_err(|_| SessionError::Internal)?;
        let token_digest = keyed_digest(&self.token_digest_key, cookie_value.as_bytes());
        let session_id = Uuid::now_v7();
        let expires_at = now + self.config.lifetime;
        self.store
            .create(SessionRecord {
                session_id,
                user_id: user_id.clone(),
                token_digest,
                created_at: now,
                last_activity_at: now,
                expires_at,
                revoked_at: None,
                version: 0,
            })
            .await
            .map_err(|_| SessionError::Internal)?;
        Ok(LoginCompletion {
            cookie_value,
            user_id,
            session_id,
            expires_at,
        })
    }

    /// Authenticates and performs at most one sliding-expiry write per throttle
    /// interval. A stale CAS is reloaded once and never overwrites newer data.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Internal`] on persistence failure.
    pub async fn authenticate(
        &self,
        cookie_value: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthenticatedContext>, SessionError> {
        if parse_token(cookie_value).is_none() {
            return Ok(None);
        }
        let digest = keyed_digest(&self.token_digest_key, cookie_value.as_bytes());
        let Some(session) = self
            .store
            .find_by_token_digest(&digest)
            .await
            .map_err(|_| SessionError::Internal)?
        else {
            return Ok(None);
        };
        self.authenticate_record(session, now, true).await
    }

    async fn authenticate_record(
        &self,
        session: SessionRecord,
        now: DateTime<Utc>,
        retry: bool,
    ) -> Result<Option<AuthenticatedContext>, SessionError> {
        if !session.is_active_at(now) {
            return Ok(None);
        }
        let context = |renewed_expires_at| AuthenticatedContext {
            user_id: session.user_id.clone(),
            session_id: session.session_id,
            session_created_at: session.created_at,
            renewed_expires_at,
        };
        if now - session.last_activity_at < self.config.write_throttle {
            return Ok(Some(context(None)));
        }
        let mut replacement = session.clone();
        replacement.last_activity_at = now;
        replacement.expires_at = now + self.config.lifetime;
        replacement.version = replacement
            .version
            .checked_add(1)
            .ok_or(SessionError::Internal)?;
        match self
            .store
            .replace_if_unchanged(&session, replacement.clone())
            .await
            .map_err(|_| SessionError::Internal)?
        {
            CasOutcome::Updated => Ok(Some(context(Some(replacement.expires_at)))),
            CasOutcome::Stale if retry => {
                let latest = self
                    .store
                    .find_by_id(session.session_id)
                    .await
                    .map_err(|_| SessionError::Internal)?;
                match latest {
                    Some(latest) if latest.is_active_at(now) => Ok(Some(AuthenticatedContext {
                        user_id: latest.user_id,
                        session_id: latest.session_id,
                        session_created_at: latest.created_at,
                        renewed_expires_at: None,
                    })),
                    _ => Ok(None),
                }
            }
            CasOutcome::Stale => Ok(None),
        }
    }

    /// Revokes the current cookie's session. Unknown tokens are idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Internal`] on persistence failure.
    pub async fn revoke_current(
        &self,
        cookie_value: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, SessionError> {
        if parse_token(cookie_value).is_none() {
            return Ok(false);
        }
        let digest = keyed_digest(&self.token_digest_key, cookie_value.as_bytes());
        let Some(session) = self
            .store
            .find_by_token_digest(&digest)
            .await
            .map_err(|_| SessionError::Internal)?
        else {
            return Ok(false);
        };
        for _ in 0..2 {
            let Some(current) = self
                .store
                .find_by_id(session.session_id)
                .await
                .map_err(|_| SessionError::Internal)?
            else {
                return Ok(false);
            };
            if current.revoked_at.is_some() {
                return Ok(true);
            }
            let mut revoked = current.clone();
            revoked.revoked_at = Some(revoked_at);
            revoked.version = revoked
                .version
                .checked_add(1)
                .ok_or(SessionError::Internal)?;
            if self
                .store
                .replace_if_unchanged(&current, revoked)
                .await
                .map_err(|_| SessionError::Internal)?
                == CasOutcome::Updated
            {
                return Ok(true);
            }
        }
        Err(SessionError::Internal)
    }

    /// Revokes every device for the authenticated user.
    ///
    /// Callers should pass `context.user_id`, not an untrusted request value.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Internal`] on persistence failure.
    pub async fn revoke_all(
        &self,
        context: &AuthenticatedContext,
        revoked_at: DateTime<Utc>,
    ) -> Result<usize, SessionError> {
        self.store
            .revoke_all_for_user(&context.user_id, revoked_at)
            .await
            .map_err(|_| SessionError::Internal)
    }
}
