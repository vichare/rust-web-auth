#![forbid(unsafe_code)]
//! Reusable known-user, non-discoverable `WebAuthn` passkey ceremonies.
//!
//! This crate deliberately exposes only the known-user flow: the consumer
//! identifies a [`UserId`] before authentication and supplies that user's
//! credentials. Discoverable/usernameless credentials are not silently
//! enabled. All cryptographic verification is delegated to `webauthn-rs`.
//!
//! Ceremony state is intentionally kept as opaque typed Rust values. The
//! dangerous `webauthn-rs` state-serialisation feature is not enabled. A
//! consumer can use an in-process store or a distributed session service able
//! to retain opaque values, but must never put [`CeremonyState`] in a client
//! cookie. Only [`CeremonyToken`] belongs in an `HttpOnly`, `Secure`,
//! `SameSite` state cookie.

use std::fmt;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use getrandom::fill;
use hmac::{Hmac, Mac as _};
pub use rust_web_auth_core::UserId;
use sha2::Sha256;
use thiserror::Error;
use url::Url;
use uuid::Uuid;
pub use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, Passkey, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Webauthn, WebauthnBuilder};

type HmacSha256 = Hmac<Sha256>;

/// Stable, opaque `WebAuthn` user handle.
///
/// This UUID is distinct from the consumer's business [`UserId`] and must
/// remain stable for the lifetime of that user's credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WebauthnUserHandle(Uuid);

impl WebauthnUserHandle {
    /// Wraps a stable opaque UUID allocated by the consumer.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the UUID supplied to `WebAuthn`.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl CeremonyTokenDigest {
    /// Returns the digest bytes for a server-side lookup key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Random 256-bit bearer token for the ceremony state cookie.
///
/// Store only [`CeremonyTokenDigest`] server-side. The token must be sent in
/// an `HttpOnly`, `Secure`, `SameSite` cookie and never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct CeremonyToken(String);

impl CeremonyToken {
    /// Returns the URL-safe token for the state cookie.
    #[must_use]
    pub fn expose_for_cookie(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CeremonyToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CeremonyToken([REDACTED])")
    }
}

/// Keyed digest used as the server-side ceremony lookup key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CeremonyTokenDigest([u8; 32]);

impl fmt::Debug for CeremonyTokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CeremonyTokenDigest([REDACTED])")
    }
}

/// Opaque typed state for one known-user `WebAuthn` ceremony.
///
/// This type is non-serializable by design. Stores must atomically consume and
/// delete it and must not expose it to the browser.
#[non_exhaustive]
pub enum CeremonyState {
    /// Registration state for an already authenticated user.
    Registration {
        /// Consumer business user identifier.
        user_id: UserId,
        /// Stable opaque `WebAuthn` user handle.
        user_handle: WebauthnUserHandle,
        /// Typed `webauthn-rs` registration state.
        state: PasskeyRegistration,
        /// Earliest valid completion time.
        created_at: DateTime<Utc>,
        /// Exclusive completion deadline.
        expires_at: DateTime<Utc>,
    },
    /// Authentication state for a consumer-resolved user.
    Authentication {
        /// Consumer business user identifier.
        user_id: UserId,
        /// Stable opaque `WebAuthn` user handle.
        user_handle: WebauthnUserHandle,
        /// Typed `webauthn-rs` authentication state.
        state: PasskeyAuthentication,
        /// Earliest valid completion time.
        created_at: DateTime<Utc>,
        /// Exclusive completion deadline.
        expires_at: DateTime<Utc>,
    },
    #[cfg(test)]
    /// State used only to verify storage semantics without a browser.
    Test {
        /// Earliest valid completion time.
        created_at: DateTime<Utc>,
        /// Exclusive completion deadline.
        expires_at: DateTime<Utc>,
    },
}

impl CeremonyState {
    fn is_available_at(&self, now: DateTime<Utc>) -> bool {
        let (created_at, expires_at) = match self {
            Self::Registration {
                created_at,
                expires_at,
                ..
            }
            | Self::Authentication {
                created_at,
                expires_at,
                ..
            } => (*created_at, *expires_at),
            #[cfg(test)]
            Self::Test {
                created_at,
                expires_at,
            } => (*created_at, *expires_at),
        };
        now >= created_at && now < expires_at
    }
}

impl fmt::Debug for CeremonyState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Registration { .. } => "Registration",
            Self::Authentication { .. } => "Authentication",
            #[cfg(test)]
            Self::Test { .. } => "Test",
        };
        formatter
            .debug_struct("CeremonyState")
            .field("kind", &name)
            .field("state", &"[REDACTED]")
            .finish()
    }
}

/// Persistence failure without backend details.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("passkey persistence failed")]
pub struct PasskeyStorageError;

/// Atomic server-side storage for non-serializable ceremony state.
#[async_trait]
pub trait CeremonyStore: Send + Sync {
    /// Inserts state without replacing an existing digest.
    async fn create(
        &self,
        digest: CeremonyTokenDigest,
        state: CeremonyState,
    ) -> Result<(), PasskeyStorageError>;

    /// Atomically consumes and deletes state.
    ///
    /// Exactly one concurrent caller may receive `Some`. Expired state must be
    /// deleted and returned as `None`.
    async fn consume_and_delete(
        &self,
        digest: &CeremonyTokenDigest,
        now: DateTime<Utc>,
    ) -> Result<Option<CeremonyState>, PasskeyStorageError>;

    /// Deletes expired ceremony state.
    async fn cleanup(&self, now: DateTime<Utc>) -> Result<usize, PasskeyStorageError>;
}

/// Consumer-owned passkeys for one business user.
#[derive(Clone, Debug)]
pub struct UserPasskeys {
    /// Stable `WebAuthn` user handle associated with the business user.
    pub user_handle: WebauthnUserHandle,
    /// Every active credential owned by the user.
    pub credentials: Vec<Passkey>,
}

/// Result of atomically registering a credential ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyRegistrationOutcome {
    /// Credential was saved for the owner.
    Saved,
    /// Credential ID already belongs to any account.
    CredentialConflict,
}

/// Consumer credential storage port.
///
/// Implementations must key every owner-scoped operation by both [`UserId`]
/// and [`WebauthnUserHandle`]. `update_credential` must locate a credential only
/// inside that owner, invoke [`Passkey::update_credential`], and persist the
/// resulting counter/backup-state changes atomically. `revoke_credential`
/// follows the same ownership rule.
#[async_trait]
pub trait PasskeyCredentialStore: Send + Sync {
    /// Loads all credentials for one consumer-resolved user.
    async fn load(&self, user_id: &UserId) -> Result<Option<UserPasskeys>, PasskeyStorageError>;

    /// Saves a newly verified registration for the exact owner.
    ///
    /// This operation must atomically reject a credential ID already stored
    /// for any user. Global credential-ID uniqueness is a `WebAuthn` relying
    /// party invariant, not merely a per-user duplicate check.
    async fn save_registered(
        &self,
        user_id: &UserId,
        user_handle: WebauthnUserHandle,
        passkey: Passkey,
    ) -> Result<PasskeyRegistrationOutcome, PasskeyStorageError>;

    /// Applies a verified authentication result to the exact owner's passkey.
    ///
    /// Returns `true` when the credential matched and was persisted, even when
    /// `Passkey::update_credential` reports that no fields changed. Returns
    /// `false` only for an owner, handle, or credential mismatch.
    async fn update_credential(
        &self,
        user_id: &UserId,
        user_handle: WebauthnUserHandle,
        result: &AuthenticationResult,
    ) -> Result<bool, PasskeyStorageError>;

    /// Revokes one credential only when it belongs to the exact owner.
    async fn revoke_credential(
        &self,
        user_id: &UserId,
        user_handle: WebauthnUserHandle,
        credential_id: &CredentialID,
    ) -> Result<bool, PasskeyStorageError>;
}

/// Fail-closed relying-party and ceremony configuration.
#[derive(Clone)]
pub struct PasskeyConfig {
    rp_id: String,
    rp_origin: Url,
    rp_name: String,
    ceremony_lifetime: Duration,
    token_digest_key: [u8; 32],
}

impl PasskeyConfig {
    /// Creates configuration with a five-minute ceremony lifetime.
    ///
    /// `rp_origin` must be an exact HTTPS origin whose host exactly equals
    /// `rp_id`. HTTP is accepted only for the `localhost` development
    /// loopback supported by `webauthn-rs`. Paths, userinfo, query strings,
    /// and fragments are rejected. Subdomain and arbitrary-port matching
    /// remain disabled.
    ///
    /// # Errors
    ///
    /// Returns [`PasskeyError::InvalidConfiguration`] for any unsafe value.
    pub fn new(
        rp_id: impl Into<String>,
        rp_origin: impl AsRef<str>,
        rp_name: impl Into<String>,
        token_digest_key: [u8; 32],
    ) -> Result<Self, PasskeyError> {
        let rp_id = rp_id.into();
        let rp_name = rp_name.into();
        let rp_origin =
            Url::parse(rp_origin.as_ref()).map_err(|_| PasskeyError::InvalidConfiguration)?;
        let host = rp_origin
            .host_str()
            .ok_or(PasskeyError::InvalidConfiguration)?;
        let loopback = host == "localhost";
        let valid_scheme =
            rp_origin.scheme() == "https" || (rp_origin.scheme() == "http" && loopback);
        if rp_id.is_empty()
            || host != rp_id
            || rp_name.trim().is_empty()
            || rp_origin.username() != ""
            || rp_origin.password().is_some()
            || rp_origin.path() != "/"
            || rp_origin.query().is_some()
            || rp_origin.fragment().is_some()
            || !valid_scheme
            || token_digest_key == [0; 32]
        {
            return Err(PasskeyError::InvalidConfiguration);
        }
        WebauthnBuilder::new(&rp_id, &rp_origin).map_err(|_| PasskeyError::InvalidConfiguration)?;
        Ok(Self {
            rp_id,
            rp_origin,
            rp_name,
            ceremony_lifetime: Duration::minutes(5),
            token_digest_key,
        })
    }

    /// Overrides the server-side state lifetime, up to ten minutes.
    ///
    /// # Errors
    ///
    /// Returns [`PasskeyError::InvalidConfiguration`] for a non-positive or
    /// excessive lifetime.
    pub fn with_ceremony_lifetime(mut self, lifetime: Duration) -> Result<Self, PasskeyError> {
        if lifetime <= Duration::zero() || lifetime > Duration::minutes(10) {
            return Err(PasskeyError::InvalidConfiguration);
        }
        self.ceremony_lifetime = lifetime;
        Ok(self)
    }
}

impl fmt::Debug for PasskeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasskeyConfig")
            .field("rp_id", &self.rp_id)
            .field("rp_origin", &self.rp_origin)
            .field("rp_name", &self.rp_name)
            .field("ceremony_lifetime", &self.ceremony_lifetime)
            .field("token_digest_key", &"[REDACTED]")
            .finish()
    }
}

/// Authenticated known-user registration input.
#[derive(Clone, Debug)]
pub struct KnownUserRegistration {
    /// Authenticated consumer business user.
    pub user_id: UserId,
    /// Stable opaque handle allocated for this user.
    pub user_handle: WebauthnUserHandle,
    /// Non-secret account label shown by authenticators.
    pub user_name: String,
    /// Human-friendly account label shown by authenticators.
    pub user_display_name: String,
}

/// Browser challenge plus opaque state-cookie token.
pub struct RegistrationStart {
    /// Options to serialize into `navigator.credentials.create`.
    pub challenge: CreationChallengeResponse,
    /// One-time value for an `HttpOnly` state cookie.
    pub ceremony_token: CeremonyToken,
}

impl fmt::Debug for RegistrationStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationStart")
            .field("challenge", &"[REDACTED]")
            .field("ceremony_token", &"[REDACTED]")
            .finish()
    }
}

/// Browser authentication challenge plus opaque state-cookie token.
pub struct AuthenticationStart {
    /// Options to serialize into `navigator.credentials.get`.
    pub challenge: RequestChallengeResponse,
    /// One-time value for an `HttpOnly` state cookie.
    pub ceremony_token: CeremonyToken,
}

impl fmt::Debug for AuthenticationStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationStart")
            .field("challenge", &"[REDACTED]")
            .field("ceremony_token", &"[REDACTED]")
            .finish()
    }
}

/// Generic passkey service failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PasskeyError {
    /// RP origin, RP ID, name, key, or lifetime is unsafe.
    #[error("invalid passkey configuration")]
    InvalidConfiguration,
    /// Request, account, credential, token, expiry, replay, or verification failed.
    #[error("passkey ceremony failed")]
    CeremonyFailed,
    /// Randomness or consumer storage is unavailable.
    #[error("passkey service unavailable")]
    Unavailable,
}

/// Production passkey service backed by typed `webauthn-rs` ceremonies.
pub struct PasskeyService {
    webauthn: Webauthn,
    config: PasskeyConfig,
    ceremonies: Arc<dyn CeremonyStore>,
    credentials: Arc<dyn PasskeyCredentialStore>,
}

impl PasskeyService {
    /// Builds the production service with exact-origin checks and required
    /// user verification.
    ///
    /// This constructor uses `WebauthnBuilder` and the non-discoverable
    /// `start_passkey_*` APIs. No discoverable flow is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`PasskeyError::InvalidConfiguration`] if `webauthn-rs`
    /// rejects the validated RP configuration.
    pub fn new(
        config: PasskeyConfig,
        ceremonies: Arc<dyn CeremonyStore>,
        credentials: Arc<dyn PasskeyCredentialStore>,
    ) -> Result<Self, PasskeyError> {
        let timeout = config
            .ceremony_lifetime
            .to_std()
            .map_err(|_| PasskeyError::InvalidConfiguration)?;
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
            .map_err(|_| PasskeyError::InvalidConfiguration)?
            .rp_name(&config.rp_name)
            .allow_subdomains(false)
            .allow_any_port(false)
            .timeout(StdDuration::from_secs(timeout.as_secs()))
            .build()
            .map_err(|_| PasskeyError::InvalidConfiguration)?;
        Ok(Self {
            webauthn,
            config,
            ceremonies,
            credentials,
        })
    }

    /// Starts registration for an already authenticated user.
    ///
    /// Every existing credential is placed in the exclude list, supporting
    /// multiple credentials while preventing accidental duplicate enrollment.
    ///
    /// # Errors
    ///
    /// Returns a generic failure for owner/handle mismatch or `WebAuthn` errors.
    pub async fn start_registration(
        &self,
        input: KnownUserRegistration,
        now: DateTime<Utc>,
    ) -> Result<RegistrationStart, PasskeyError> {
        if input.user_name.is_empty() || input.user_display_name.is_empty() {
            return Err(PasskeyError::CeremonyFailed);
        }
        let existing = self
            .credentials
            .load(&input.user_id)
            .await
            .map_err(|_| PasskeyError::Unavailable)?;
        if existing
            .as_ref()
            .is_some_and(|record| record.user_handle != input.user_handle)
        {
            return Err(PasskeyError::CeremonyFailed);
        }
        let exclude = existing.map(|record| {
            record
                .credentials
                .iter()
                .map(|credential| credential.cred_id().clone())
                .collect()
        });
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(
                input.user_handle.as_uuid(),
                &input.user_name,
                &input.user_display_name,
                exclude,
            )
            .map_err(|_| PasskeyError::CeremonyFailed)?;
        let token = self
            .store_state(CeremonyState::Registration {
                user_id: input.user_id,
                user_handle: input.user_handle,
                state,
                created_at: now,
                expires_at: now + self.config.ceremony_lifetime,
            })
            .await?;
        Ok(RegistrationStart {
            challenge,
            ceremony_token: token,
        })
    }

    /// Finishes registration after atomically consuming its state.
    ///
    /// # Errors
    ///
    /// Unknown, malformed, expired, replayed, and invalid responses all return
    /// [`PasskeyError::CeremonyFailed`].
    pub async fn finish_registration(
        &self,
        ceremony_token: &str,
        response: &RegisterPublicKeyCredential,
        now: DateTime<Utc>,
    ) -> Result<(), PasskeyError> {
        let state = self.consume_state(ceremony_token, now).await?;
        let CeremonyState::Registration {
            user_id,
            user_handle,
            state,
            ..
        } = state
        else {
            return Err(PasskeyError::CeremonyFailed);
        };
        let current = self
            .credentials
            .load(&user_id)
            .await
            .map_err(|_| PasskeyError::Unavailable)?;
        if current
            .as_ref()
            .is_some_and(|record| record.user_handle != user_handle)
        {
            return Err(PasskeyError::CeremonyFailed);
        }
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &state)
            .map_err(|_| PasskeyError::CeremonyFailed)?;
        match self
            .credentials
            .save_registered(&user_id, user_handle, passkey)
            .await
            .map_err(|_| PasskeyError::Unavailable)?
        {
            PasskeyRegistrationOutcome::Saved => Ok(()),
            PasskeyRegistrationOutcome::CredentialConflict => Err(PasskeyError::CeremonyFailed),
        }
    }

    /// Starts known-user authentication after consumer account lookup.
    ///
    /// HTTP adapters must return the same status/body for this method's generic
    /// failure as for an unknown account; no public response should reveal
    /// whether a user or credential exists.
    ///
    /// # Errors
    ///
    /// Missing users, empty credential sets, and `WebAuthn` errors return the
    /// same [`PasskeyError::CeremonyFailed`] value.
    pub async fn start_authentication(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<AuthenticationStart, PasskeyError> {
        let record = self
            .credentials
            .load(&user_id)
            .await
            .map_err(|_| PasskeyError::Unavailable)?
            .filter(|record| !record.credentials.is_empty())
            .ok_or(PasskeyError::CeremonyFailed)?;
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(&record.credentials)
            .map_err(|_| PasskeyError::CeremonyFailed)?;
        let token = self
            .store_state(CeremonyState::Authentication {
                user_id,
                user_handle: record.user_handle,
                state,
                created_at: now,
                expires_at: now + self.config.ceremony_lifetime,
            })
            .await?;
        Ok(AuthenticationStart {
            challenge,
            ceremony_token: token,
        })
    }

    /// Finishes authentication and returns only the consumer business user ID.
    ///
    /// The credential owner and user handle are checked before the consumer
    /// store atomically applies `Passkey::update_credential`. This API performs
    /// no email lookup, account linking, or automatic account merge.
    ///
    /// # Errors
    ///
    /// All token, owner, credential, verification, and user-verification
    /// failures return [`PasskeyError::CeremonyFailed`].
    pub async fn finish_authentication(
        &self,
        ceremony_token: &str,
        response: &PublicKeyCredential,
        now: DateTime<Utc>,
    ) -> Result<UserId, PasskeyError> {
        let state = self.consume_state(ceremony_token, now).await?;
        let CeremonyState::Authentication {
            user_id,
            user_handle,
            state,
            ..
        } = state
        else {
            return Err(PasskeyError::CeremonyFailed);
        };
        let result = self
            .webauthn
            .finish_passkey_authentication(response, &state)
            .map_err(|_| PasskeyError::CeremonyFailed)?;
        if !result.user_verified() {
            return Err(PasskeyError::CeremonyFailed);
        }
        let current = self
            .credentials
            .load(&user_id)
            .await
            .map_err(|_| PasskeyError::Unavailable)?
            .filter(|record| record.user_handle == user_handle)
            .ok_or(PasskeyError::CeremonyFailed)?;
        if !current
            .credentials
            .iter()
            .any(|credential| credential.cred_id() == result.cred_id())
        {
            return Err(PasskeyError::CeremonyFailed);
        }
        let updated = self
            .credentials
            .update_credential(&user_id, user_handle, &result)
            .await
            .map_err(|_| PasskeyError::Unavailable)?;
        if !updated {
            return Err(PasskeyError::CeremonyFailed);
        }
        Ok(user_id)
    }

    /// Revokes a credential from the exact business user and `WebAuthn` handle.
    ///
    /// # Errors
    ///
    /// Owner/handle/credential mismatch is deliberately indistinguishable.
    pub async fn revoke_credential(
        &self,
        user_id: &UserId,
        user_handle: WebauthnUserHandle,
        credential_id: &CredentialID,
    ) -> Result<(), PasskeyError> {
        let current = self
            .credentials
            .load(user_id)
            .await
            .map_err(|_| PasskeyError::Unavailable)?
            .filter(|record| record.user_handle == user_handle)
            .ok_or(PasskeyError::CeremonyFailed)?;
        if !current
            .credentials
            .iter()
            .any(|credential| credential.cred_id() == credential_id)
        {
            return Err(PasskeyError::CeremonyFailed);
        }
        self.credentials
            .revoke_credential(user_id, user_handle, credential_id)
            .await
            .map_err(|_| PasskeyError::Unavailable)?
            .then_some(())
            .ok_or(PasskeyError::CeremonyFailed)
    }

    /// Deletes expired ceremony states.
    ///
    /// # Errors
    ///
    /// Returns the consumer storage failure.
    pub async fn cleanup(&self, now: DateTime<Utc>) -> Result<usize, PasskeyStorageError> {
        self.ceremonies.cleanup(now).await
    }

    async fn store_state(&self, state: CeremonyState) -> Result<CeremonyToken, PasskeyError> {
        let mut bytes = [0_u8; 32];
        fill(&mut bytes).map_err(|_| PasskeyError::Unavailable)?;
        let token = CeremonyToken(URL_SAFE_NO_PAD.encode(bytes));
        let digest = self.token_digest(token.expose_for_cookie());
        self.ceremonies
            .create(digest, state)
            .await
            .map_err(|_| PasskeyError::Unavailable)?;
        Ok(token)
    }

    async fn consume_state(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<CeremonyState, PasskeyError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(token)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(PasskeyError::CeremonyFailed)?;
        let canonical = URL_SAFE_NO_PAD.encode(decoded);
        let digest = self.token_digest(&canonical);
        self.ceremonies
            .consume_and_delete(&digest, now)
            .await
            .map_err(|_| PasskeyError::Unavailable)?
            .filter(|state| state.is_available_at(now))
            .ok_or(PasskeyError::CeremonyFailed)
    }

    fn token_digest(&self, token: &str) -> CeremonyTokenDigest {
        let mut mac = HmacSha256::new_from_slice(&self.config.token_digest_key)
            .expect("HMAC accepts a 32-byte key");
        mac.update(b"passkey-ceremony-token");
        mac.update(&[0]);
        mac.update(token.as_bytes());
        CeremonyTokenDigest(mac.finalize().into_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use webauthn_rs_core::proto::{
        AttestationFormat, AttestationMetadata, COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType,
        Credential, ECDSACurve, ParsedAttestation, ParsedAttestationData, RegisteredExtensions,
        UserVerificationPolicy,
    };

    #[derive(Default)]
    struct MemoryCeremonies {
        states: Mutex<HashMap<CeremonyTokenDigest, CeremonyState>>,
    }

    #[async_trait]
    impl CeremonyStore for MemoryCeremonies {
        async fn create(
            &self,
            digest: CeremonyTokenDigest,
            state: CeremonyState,
        ) -> Result<(), PasskeyStorageError> {
            let mut states = self.states.lock().map_err(|_| PasskeyStorageError)?;
            if states.insert(digest, state).is_some() {
                return Err(PasskeyStorageError);
            }
            Ok(())
        }

        async fn consume_and_delete(
            &self,
            digest: &CeremonyTokenDigest,
            now: DateTime<Utc>,
        ) -> Result<Option<CeremonyState>, PasskeyStorageError> {
            let state = self
                .states
                .lock()
                .map_err(|_| PasskeyStorageError)?
                .remove(digest);
            Ok(state.filter(|state| state.is_available_at(now)))
        }

        async fn cleanup(&self, now: DateTime<Utc>) -> Result<usize, PasskeyStorageError> {
            let mut states = self.states.lock().map_err(|_| PasskeyStorageError)?;
            let before = states.len();
            states.retain(|_, state| state.is_available_at(now));
            Ok(before - states.len())
        }
    }

    struct EmptyCredentials;

    #[async_trait]
    impl PasskeyCredentialStore for EmptyCredentials {
        async fn load(
            &self,
            _user_id: &UserId,
        ) -> Result<Option<UserPasskeys>, PasskeyStorageError> {
            Ok(None)
        }

        async fn save_registered(
            &self,
            _user_id: &UserId,
            _user_handle: WebauthnUserHandle,
            _passkey: Passkey,
        ) -> Result<PasskeyRegistrationOutcome, PasskeyStorageError> {
            Ok(PasskeyRegistrationOutcome::Saved)
        }

        async fn update_credential(
            &self,
            _user_id: &UserId,
            _user_handle: WebauthnUserHandle,
            _result: &AuthenticationResult,
        ) -> Result<bool, PasskeyStorageError> {
            Ok(false)
        }

        async fn revoke_credential(
            &self,
            _user_id: &UserId,
            _user_handle: WebauthnUserHandle,
            _credential_id: &CredentialID,
        ) -> Result<bool, PasskeyStorageError> {
            Ok(false)
        }
    }

    #[derive(Default)]
    struct MemoryCredentials {
        users: Mutex<HashMap<UserId, UserPasskeys>>,
    }

    #[async_trait]
    impl PasskeyCredentialStore for MemoryCredentials {
        async fn load(
            &self,
            user_id: &UserId,
        ) -> Result<Option<UserPasskeys>, PasskeyStorageError> {
            Ok(self
                .users
                .lock()
                .map_err(|_| PasskeyStorageError)?
                .get(user_id)
                .cloned())
        }

        async fn save_registered(
            &self,
            user_id: &UserId,
            user_handle: WebauthnUserHandle,
            passkey: Passkey,
        ) -> Result<PasskeyRegistrationOutcome, PasskeyStorageError> {
            let mut users = self.users.lock().map_err(|_| PasskeyStorageError)?;
            if users.values().any(|user| {
                user.credentials
                    .iter()
                    .any(|existing| existing.cred_id() == passkey.cred_id())
            }) {
                return Ok(PasskeyRegistrationOutcome::CredentialConflict);
            }
            let entry = users
                .entry(user_id.clone())
                .or_insert_with(|| UserPasskeys {
                    user_handle,
                    credentials: Vec::new(),
                });
            if entry.user_handle != user_handle
                || entry
                    .credentials
                    .iter()
                    .any(|existing| existing.cred_id() == passkey.cred_id())
            {
                return Err(PasskeyStorageError);
            }
            entry.credentials.push(passkey);
            Ok(PasskeyRegistrationOutcome::Saved)
        }

        async fn update_credential(
            &self,
            user_id: &UserId,
            user_handle: WebauthnUserHandle,
            result: &AuthenticationResult,
        ) -> Result<bool, PasskeyStorageError> {
            let mut users = self.users.lock().map_err(|_| PasskeyStorageError)?;
            let Some(user) = users
                .get_mut(user_id)
                .filter(|user| user.user_handle == user_handle)
            else {
                return Ok(false);
            };
            let Some(passkey) = user
                .credentials
                .iter_mut()
                .find(|passkey| passkey.cred_id() == result.cred_id())
            else {
                return Ok(false);
            };
            Ok(passkey.update_credential(result).is_some())
        }

        async fn revoke_credential(
            &self,
            user_id: &UserId,
            user_handle: WebauthnUserHandle,
            credential_id: &CredentialID,
        ) -> Result<bool, PasskeyStorageError> {
            let mut users = self.users.lock().map_err(|_| PasskeyStorageError)?;
            let Some(user) = users
                .get_mut(user_id)
                .filter(|user| user.user_handle == user_handle)
            else {
                return Ok(false);
            };
            let before = user.credentials.len();
            user.credentials
                .retain(|passkey| passkey.cred_id() != credential_id);
            Ok(user.credentials.len() != before)
        }
    }

    fn config(origin: &str) -> Result<PasskeyConfig, PasskeyError> {
        PasskeyConfig::new("example.com", origin, "Example", [7; 32])
    }

    fn service(ceremonies: Arc<MemoryCeremonies>) -> PasskeyService {
        PasskeyService::new(
            config("https://example.com").expect("valid configuration"),
            ceremonies,
            Arc::new(EmptyCredentials),
        )
        .expect("valid service")
    }

    fn test_passkey(credential_id: &[u8], counter: u32) -> Passkey {
        let credential = Credential {
            cred_id: credential_id.to_vec(),
            cred: COSEKey {
                type_: COSEAlgorithm::ES256,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: vec![1; 32],
                    y: vec![2; 32],
                }),
            },
            counter,
            transports: None,
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            registration_policy: UserVerificationPolicy::Required,
            extensions: RegisteredExtensions::none(),
            attestation: ParsedAttestation {
                data: ParsedAttestationData::None,
                metadata: AttestationMetadata::None,
            },
            attestation_format: AttestationFormat::None,
        };
        let value = serde_json::json!({ "cred": credential });
        serde_json::from_value(value).expect("valid test passkey")
    }

    fn authentication_result(credential_id: &[u8], counter: u32) -> AuthenticationResult {
        serde_json::from_value(serde_json::json!({
            "cred_id": URL_SAFE_NO_PAD.encode(credential_id),
            "needs_update": true,
            "user_verified": true,
            "backup_state": false,
            "backup_eligible": false,
            "counter": counter,
            "extensions": {}
        }))
        .expect("valid authentication result")
    }

    fn stored_counter(passkey: &Passkey) -> u64 {
        serde_json::to_value(passkey)
            .expect("serialize passkey")
            .pointer("/cred/counter")
            .and_then(serde_json::Value::as_u64)
            .expect("counter")
    }

    #[tokio::test]
    async fn ceremony_state_is_atomic_short_lived_and_one_time() {
        let now = Utc::now();
        let ceremonies = Arc::new(MemoryCeremonies::default());
        let service = service(Arc::clone(&ceremonies));
        let token = service
            .store_state(CeremonyState::Test {
                created_at: now,
                expires_at: now + Duration::minutes(5),
            })
            .await
            .expect("state stored");

        let (first, second) = tokio::join!(
            service.consume_state(token.expose_for_cookie(), now),
            service.consume_state(token.expose_for_cookie(), now)
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(matches!(
            service.consume_state(token.expose_for_cookie(), now).await,
            Err(PasskeyError::CeremonyFailed)
        ));
    }

    #[tokio::test]
    async fn expired_state_is_consumed_and_rejected() {
        let now = Utc::now();
        let ceremonies = Arc::new(MemoryCeremonies::default());
        let service = service(Arc::clone(&ceremonies));
        let token = service
            .store_state(CeremonyState::Test {
                created_at: now - Duration::minutes(6),
                expires_at: now - Duration::minutes(1),
            })
            .await
            .expect("state stored");

        assert!(matches!(
            service.consume_state(token.expose_for_cookie(), now).await,
            Err(PasskeyError::CeremonyFailed)
        ));
        assert!(ceremonies.states.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn credential_updates_are_owner_scoped_and_persist_counters() {
        let store = MemoryCredentials::default();
        let alice = UserId::new("alice").expect("user");
        let bob = UserId::new("bob").expect("user");
        let alice_handle = WebauthnUserHandle::new(Uuid::new_v4());
        let bob_handle = WebauthnUserHandle::new(Uuid::new_v4());
        assert_eq!(
            store
                .save_registered(&alice, alice_handle, test_passkey(&[1, 2, 3], 1))
                .await
                .expect("save"),
            PasskeyRegistrationOutcome::Saved
        );
        let result = authentication_result(&[1, 2, 3], 9);

        assert!(
            !store
                .update_credential(&bob, bob_handle, &result)
                .await
                .expect("cross-user update rejected")
        );
        assert!(
            store
                .update_credential(&alice, alice_handle, &result)
                .await
                .expect("owner update")
        );
        let stored = store
            .load(&alice)
            .await
            .expect("load")
            .expect("alice exists");
        assert_eq!(stored_counter(&stored.credentials[0]), 9);
    }

    #[tokio::test]
    async fn credential_revoke_is_owner_scoped() {
        let store = Arc::new(MemoryCredentials::default());
        let alice = UserId::new("alice").expect("user");
        let bob = UserId::new("bob").expect("user");
        let alice_handle = WebauthnUserHandle::new(Uuid::new_v4());
        let bob_handle = WebauthnUserHandle::new(Uuid::new_v4());
        assert_eq!(
            store
                .save_registered(&alice, alice_handle, test_passkey(&[4, 5, 6], 0))
                .await
                .expect("save"),
            PasskeyRegistrationOutcome::Saved
        );
        let service = PasskeyService::new(
            config("https://example.com").expect("config"),
            Arc::new(MemoryCeremonies::default()),
            store.clone(),
        )
        .expect("service");

        assert_eq!(
            service
                .revoke_credential(&bob, bob_handle, &vec![4, 5, 6])
                .await,
            Err(PasskeyError::CeremonyFailed)
        );
        service
            .revoke_credential(&alice, alice_handle, &vec![4, 5, 6])
            .await
            .expect("owner revoke");
        assert!(
            store
                .load(&alice)
                .await
                .expect("load")
                .expect("alice")
                .credentials
                .is_empty()
        );
    }

    #[tokio::test]
    async fn credential_ids_are_globally_unique() {
        let store = MemoryCredentials::default();
        let alice = UserId::new("alice").expect("user");
        let bob = UserId::new("bob").expect("user");
        let alice_handle = WebauthnUserHandle::new(Uuid::new_v4());
        let bob_handle = WebauthnUserHandle::new(Uuid::new_v4());
        assert_eq!(
            store
                .save_registered(&alice, alice_handle, test_passkey(&[9, 9, 9], 0))
                .await
                .expect("save"),
            PasskeyRegistrationOutcome::Saved
        );
        assert_eq!(
            store
                .save_registered(&bob, bob_handle, test_passkey(&[9, 9, 9], 0))
                .await
                .expect("conflict"),
            PasskeyRegistrationOutcome::CredentialConflict
        );
        assert!(store.load(&bob).await.expect("load").is_none());
    }

    #[tokio::test]
    async fn ceremonies_request_required_user_verification() {
        let ceremonies = Arc::new(MemoryCeremonies::default());
        let credentials = Arc::new(MemoryCredentials::default());
        let service = PasskeyService::new(
            config("https://example.com").expect("config"),
            ceremonies,
            credentials.clone(),
        )
        .expect("service");
        let user_id = UserId::new("alice").expect("user");
        let user_handle = WebauthnUserHandle::new(Uuid::new_v4());
        let registration = service
            .start_registration(
                KnownUserRegistration {
                    user_id: user_id.clone(),
                    user_handle,
                    user_name: "alice".to_owned(),
                    user_display_name: "Alice".to_owned(),
                },
                Utc::now(),
            )
            .await
            .expect("registration");
        let registration_json =
            serde_json::to_string(&registration.challenge).expect("registration JSON");
        assert!(registration_json.contains("\"userVerification\":\"required\""));

        assert_eq!(
            credentials
                .save_registered(&user_id, user_handle, test_passkey(&[7, 8, 9], 0))
                .await
                .expect("save"),
            PasskeyRegistrationOutcome::Saved
        );
        let authentication = service
            .start_authentication(user_id, Utc::now())
            .await
            .expect("authentication");
        let authentication_json =
            serde_json::to_string(&authentication.challenge).expect("authentication JSON");
        assert!(authentication_json.contains("\"userVerification\":\"required\""));
    }

    #[test]
    fn configuration_is_fail_closed() {
        assert!(config("https://example.com").is_ok());
        assert!(PasskeyConfig::new("localhost", "http://localhost:3000", "Dev", [1; 32]).is_ok());
        assert!(config("http://example.com").is_err());
        assert!(config("https://login.example.com").is_err());
        assert!(config("https://example.com/path").is_err());
        assert!(
            PasskeyConfig::new("example.com", "https://example.com", "Example", [0; 32]).is_err()
        );
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let token = CeremonyToken("secret".to_owned());
        assert_eq!(format!("{token:?}"), "CeremonyToken([REDACTED])");
        let value = format!("{:?}", config("https://example.com").expect("valid"));
        assert!(!value.contains("[7, 7"));
        assert!(value.contains("[REDACTED]"));
    }
}
