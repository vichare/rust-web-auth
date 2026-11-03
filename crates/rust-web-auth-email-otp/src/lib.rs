#![forbid(unsafe_code)]
//! Generic email one-time-password challenges.
//!
//! The crate knows nothing about application users. Successful verification
//! returns a verified email identity and explicit purpose; the consumer alone
//! decides whether to sign in, create an account, or bind an identity.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use getrandom::fill;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use url::Url;

type HmacSha256 = Hmac<Sha256>;
const OTP_SPACE: u32 = 1_000_000;
const MAX_RANDOM_WITHOUT_BIAS: u32 = u32::MAX - (u32::MAX % OTP_SPACE);

/// Persistence failure safe to expose across the library boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("email OTP persistence failed")]
pub struct EmailOtpStorageError;

/// Mail delivery failure without provider details.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("email OTP delivery failed")]
pub struct EmailDeliveryError;

/// Consumer-controlled, syntactically guarded email address.
///
/// Validation is intentionally transport-oriented. It does not claim that a
/// mailbox exists; successful OTP verification proves mailbox possession.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Creates an address after rejecting controls, whitespace, excessive
    /// length, and structurally unusable values.
    ///
    /// # Errors
    ///
    /// Returns [`EmailOtpError::InvalidRequest`] for invalid input.
    pub fn new(value: impl Into<String>) -> Result<Self, EmailOtpError> {
        let value = value.into();
        let mut parts = value.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        if value.len() > 320
            || local.is_empty()
            || domain.is_empty()
            || parts.next().is_some()
            || domain.starts_with('.')
            || domain.ends_with('.')
            || !domain.contains('.')
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(EmailOtpError::InvalidRequest);
        }
        Ok(Self(value))
    }

    /// Returns the address for the mail-delivery port.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn normalized_for_policy(&self) -> String {
        self.0.to_lowercase()
    }
}

impl fmt::Debug for EmailAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmailAddress([REDACTED])")
    }
}

/// Explicit consumer-defined ceremony purpose.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmailOtpPurpose(String);

impl EmailOtpPurpose {
    /// Creates an ASCII slug such as `sign-in` or `link-account`.
    ///
    /// # Errors
    ///
    /// Returns [`EmailOtpError::InvalidRequest`] for an unsafe slug.
    pub fn new(value: impl Into<String>) -> Result<Self, EmailOtpError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(EmailOtpError::InvalidRequest);
        }
        Ok(Self(value))
    }

    /// Returns the consumer-defined purpose.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque random challenge identifier returned to the browser.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailOtpChallengeId(String);

impl EmailOtpChallengeId {
    /// Returns the challenge ID for the verification request.
    #[must_use]
    pub fn expose_for_client(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EmailOtpChallengeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmailOtpChallengeId([REDACTED])")
    }
}

/// Six-digit code delivered only through the mail adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailOtpCode(String);

impl EmailOtpCode {
    /// Returns the code for the email template.
    ///
    /// Mail adapters must not log this value.
    #[must_use]
    pub fn expose_for_delivery(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EmailOtpCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmailOtpCode([REDACTED])")
    }
}

/// Persisted one-time OTP attempt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailOtpAttempt {
    /// Keyed digest of the opaque challenge ID.
    pub challenge_digest: [u8; 32],
    /// Keyed digest of the normalized mailbox for policy indexing.
    pub email_digest: [u8; 32],
    /// Mailbox to which the code was delivered.
    pub email: EmailAddress,
    /// Explicit sign-in or account-binding purpose.
    pub purpose: EmailOtpPurpose,
    /// Exact allow-listed application-relative continuation.
    pub continue_path: String,
    /// Keyed digest binding the code to this challenge.
    pub code_digest: [u8; 32],
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Exclusive expiry time.
    pub expires_at: DateTime<Utc>,
    /// Earliest time a replacement challenge may be requested.
    pub resend_allowed_at: DateTime<Utc>,
    /// Failed verifications remaining before invalidation.
    pub attempts_remaining: u8,
}

impl fmt::Debug for EmailOtpAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailOtpAttempt")
            .field("challenge_digest", &"[REDACTED]")
            .field("email_digest", &"[REDACTED]")
            .field("email", &"[REDACTED]")
            .field("purpose", &self.purpose)
            .field("continue_path", &self.continue_path)
            .field("code_digest", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("resend_allowed_at", &self.resend_allowed_at)
            .field("attempts_remaining", &self.attempts_remaining)
            .finish()
    }
}

/// Atomic create result enforcing one active challenge and resend cooldown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailOtpCreateOutcome {
    /// New challenge was stored and any previous active challenge invalidated.
    Created,
    /// Existing challenge is still inside its resend cooldown.
    Cooldown,
}

/// Atomic verification result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmailOtpVerifyOutcome {
    /// Matching code consumed and deleted the challenge.
    Verified(Box<EmailOtpAttempt>),
    /// Wrong code decremented the attempt budget.
    Rejected,
    /// Challenge is missing, expired, exhausted, or already consumed.
    Invalid,
}

/// Atomic persistence port for one-time email challenges.
#[async_trait]
pub trait EmailOtpAttemptStore: Send + Sync {
    /// Creates one active challenge per `(email_digest, purpose)`.
    ///
    /// The operation must atomically enforce `resend_allowed_at`; when allowed,
    /// it invalidates any older active challenge before inserting `attempt`.
    async fn create_or_replace(
        &self,
        attempt: EmailOtpAttempt,
        now: DateTime<Utc>,
    ) -> Result<EmailOtpCreateOutcome, EmailOtpStorageError>;

    /// Atomically verifies a keyed code digest and updates challenge state.
    ///
    /// Matching codes delete and return the attempt. Wrong codes decrement
    /// `attempts_remaining`; the fifth failure deletes the challenge. Missing,
    /// expired, exhausted, or replayed challenges return `Invalid`.
    async fn verify_and_consume(
        &self,
        challenge_digest: &[u8; 32],
        code_digest: &[u8; 32],
        now: DateTime<Utc>,
    ) -> Result<EmailOtpVerifyOutcome, EmailOtpStorageError>;

    /// Invalidates a challenge, used when delivery fails.
    async fn invalidate(&self, challenge_digest: &[u8; 32]) -> Result<(), EmailOtpStorageError>;

    /// Removes expired attempts.
    async fn cleanup(&self, now: DateTime<Utc>) -> Result<usize, EmailOtpStorageError>;
}

/// Minimal template data passed to a consumer-provided mail adapter.
pub struct EmailOtpMessage<'a> {
    /// Six-digit one-time code.
    pub code: &'a EmailOtpCode,
    /// Explicit purpose suitable for localized templates.
    pub purpose: &'a EmailOtpPurpose,
    /// Expiry suitable for localized templates.
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for EmailOtpMessage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailOtpMessage")
            .field("code", &"[REDACTED]")
            .field("purpose", self.purpose)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Consumer-provided outbound mail adapter.
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Delivers the OTP. Implementations must not log recipient or code.
    async fn send_email_otp(
        &self,
        recipient: &EmailAddress,
        message: EmailOtpMessage<'_>,
    ) -> Result<(), EmailDeliveryError>;
}

/// Privacy-preserving request-rate-limit context.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailOtpRequestRateLimitContext {
    /// Keyed digest of the normalized mailbox.
    pub email_digest: [u8; 32],
    /// Consumer-defined IP/network partition, preferably already hashed.
    pub ip_partition: String,
}

/// Privacy-preserving verification-rate-limit context.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailOtpVerifyRateLimitContext {
    /// Keyed digest of the opaque challenge ID.
    pub challenge_digest: [u8; 32],
    /// Consumer-defined IP/network partition, preferably already hashed.
    pub ip_partition: String,
}

impl fmt::Debug for EmailOtpRequestRateLimitContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmailOtpRequestRateLimitContext([REDACTED])")
    }
}

impl fmt::Debug for EmailOtpVerifyRateLimitContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmailOtpVerifyRateLimitContext([REDACTED])")
    }
}

/// Rate-limit decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailOtpRateLimitDecision {
    /// Operation may proceed.
    Allowed,
    /// Operation must be rejected.
    Rejected,
}

/// Layered request and verification limiter.
#[async_trait]
pub trait EmailOtpRateLimiter: Send + Sync {
    /// Limits requests by normalized email and IP/network partition.
    async fn check_request(
        &self,
        context: &EmailOtpRequestRateLimitContext,
        now: DateTime<Utc>,
    ) -> Result<EmailOtpRateLimitDecision, EmailOtpStorageError>;

    /// Limits verification by challenge and IP/network partition.
    async fn check_verify(
        &self,
        context: &EmailOtpVerifyRateLimitContext,
        now: DateTime<Utc>,
    ) -> Result<EmailOtpRateLimitDecision, EmailOtpStorageError>;
}

/// Validated email OTP configuration.
#[derive(Clone)]
pub struct EmailOtpConfig {
    digest_key: [u8; 32],
    lifetime: Duration,
    resend_cooldown: Duration,
    max_attempts: u8,
    allowed_continue_paths: HashSet<String>,
}

impl EmailOtpConfig {
    /// Creates defaults: six digits, ten-minute lifetime, one-minute resend
    /// cooldown, and at most five failed verification attempts.
    ///
    /// # Errors
    ///
    /// Returns [`EmailOtpError::InvalidConfiguration`] for an all-zero key or
    /// unsafe/empty continuation allow-list.
    pub fn new(
        digest_key: [u8; 32],
        allowed_continue_paths: impl IntoIterator<Item = String>,
    ) -> Result<Self, EmailOtpError> {
        let allowed_continue_paths = allowed_continue_paths
            .into_iter()
            .map(|path| validate_continue_path(&path).map(|()| path))
            .collect::<Result<HashSet<_>, _>>()?;
        if digest_key == [0; 32] || allowed_continue_paths.is_empty() {
            return Err(EmailOtpError::InvalidConfiguration);
        }
        Ok(Self {
            digest_key,
            lifetime: Duration::minutes(10),
            resend_cooldown: Duration::minutes(1),
            max_attempts: 5,
            allowed_continue_paths,
        })
    }

    /// Overrides timing policy within conservative limits.
    ///
    /// # Errors
    ///
    /// Returns [`EmailOtpError::InvalidConfiguration`] for non-positive,
    /// excessive, or inconsistent values.
    pub fn with_policy(
        mut self,
        lifetime: Duration,
        resend_cooldown: Duration,
        max_attempts: u8,
    ) -> Result<Self, EmailOtpError> {
        if lifetime <= Duration::zero()
            || lifetime > Duration::minutes(10)
            || resend_cooldown <= Duration::zero()
            || resend_cooldown >= lifetime
            || !(1..=5).contains(&max_attempts)
        {
            return Err(EmailOtpError::InvalidConfiguration);
        }
        self.lifetime = lifetime;
        self.resend_cooldown = resend_cooldown;
        self.max_attempts = max_attempts;
        Ok(self)
    }
}

impl fmt::Debug for EmailOtpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailOtpConfig")
            .field("digest_key", &"[REDACTED]")
            .field("lifetime", &self.lifetime)
            .field("resend_cooldown", &self.resend_cooldown)
            .field("max_attempts", &self.max_attempts)
            .field("allowed_continue_paths", &self.allowed_continue_paths)
            .finish()
    }
}

/// Input to an email OTP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailOtpRequest {
    /// Delivery address.
    pub email: EmailAddress,
    /// Explicit consumer purpose.
    pub purpose: EmailOtpPurpose,
    /// Exact allow-listed continuation.
    pub continue_path: String,
    /// Consumer-defined IP/network partition.
    pub ip_partition: String,
}

/// Uniform accepted response suitable for an anti-enumeration HTTP surface.
pub struct EmailOtpChallenge {
    /// Opaque challenge ID sent back with the user's code.
    pub challenge_id: EmailOtpChallengeId,
    /// Exclusive verification deadline.
    pub expires_at: DateTime<Utc>,
    /// Earliest time a replacement may be requested.
    pub resend_allowed_at: DateTime<Utc>,
}

impl fmt::Debug for EmailOtpChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailOtpChallenge")
            .field("challenge_id", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("resend_allowed_at", &self.resend_allowed_at)
            .finish()
    }
}

/// Input to OTP verification.
#[derive(Clone, Copy)]
pub struct EmailOtpVerification<'a> {
    /// Opaque challenge ID returned by [`EmailOtpService::request`].
    pub challenge_id: &'a str,
    /// User-entered six-digit code.
    pub code: &'a str,
    /// Consumer-defined IP/network partition.
    pub ip_partition: &'a str,
}

impl fmt::Debug for EmailOtpVerification<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailOtpVerification")
            .field("challenge_id", &"[REDACTED]")
            .field("code", &"[REDACTED]")
            .field("ip_partition", &"[REDACTED]")
            .finish()
    }
}

/// Identity proven by a successful OTP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEmailIdentity {
    /// Verified mailbox.
    pub email: EmailAddress,
    /// Original explicit ceremony purpose.
    pub purpose: EmailOtpPurpose,
    /// Exact allow-listed post-verification continuation.
    pub continue_path: String,
    /// Verification time.
    pub verified_at: DateTime<Utc>,
}

/// Classified OTP failure without account-existence information.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EmailOtpError {
    /// Digest key, timing, attempt, or continuation policy is unsafe.
    #[error("invalid email OTP configuration")]
    InvalidConfiguration,
    /// Request syntax or allow-listed continuation is invalid.
    #[error("invalid email OTP request")]
    InvalidRequest,
    /// Layered limiter or resend cooldown rejected the operation.
    #[error("email OTP rate limited")]
    RateLimited,
    /// Storage, randomness, or delivery is unavailable.
    #[error("email OTP service unavailable")]
    Unavailable,
    /// Code, challenge, expiry, replay, or attempt budget is invalid.
    #[error("email OTP verification failed")]
    VerificationFailed,
}

/// Storage- and mail-provider-independent email OTP service.
pub struct EmailOtpService {
    config: EmailOtpConfig,
    attempts: Arc<dyn EmailOtpAttemptStore>,
    sender: Arc<dyn EmailSender>,
    limiter: Arc<dyn EmailOtpRateLimiter>,
}

impl EmailOtpService {
    /// Creates a service from consumer-owned ports.
    #[must_use]
    pub fn new(
        config: EmailOtpConfig,
        attempts: Arc<dyn EmailOtpAttemptStore>,
        sender: Arc<dyn EmailSender>,
        limiter: Arc<dyn EmailOtpRateLimiter>,
    ) -> Self {
        Self {
            config,
            attempts,
            sender,
            limiter,
        }
    }

    /// Creates one active challenge and sends a six-digit code.
    ///
    /// The service performs no account lookup. Consumers should return the
    /// same status and body for every accepted request, regardless of whether
    /// an application account exists.
    ///
    /// # Errors
    ///
    /// Returns a classified [`EmailOtpError`].
    pub async fn request(
        &self,
        request: EmailOtpRequest,
        now: DateTime<Utc>,
    ) -> Result<EmailOtpChallenge, EmailOtpError> {
        validate_partition(&request.ip_partition)?;
        if !self
            .config
            .allowed_continue_paths
            .contains(&request.continue_path)
        {
            return Err(EmailOtpError::InvalidRequest);
        }
        let email_digest = domain_digest(
            &self.config.digest_key,
            b"email-policy",
            request.email.normalized_for_policy().as_bytes(),
        );
        let request_context = EmailOtpRequestRateLimitContext {
            email_digest,
            ip_partition: request.ip_partition,
        };
        match self.limiter.check_request(&request_context, now).await {
            Ok(EmailOtpRateLimitDecision::Allowed) => {}
            Ok(EmailOtpRateLimitDecision::Rejected) => {
                return Err(EmailOtpError::RateLimited);
            }
            Err(_) => return Err(EmailOtpError::Unavailable),
        }

        let challenge_id =
            EmailOtpChallengeId(random_token().map_err(|_| EmailOtpError::Unavailable)?);
        let code = EmailOtpCode(random_code().map_err(|_| EmailOtpError::Unavailable)?);
        let challenge_digest = domain_digest(
            &self.config.digest_key,
            b"email-otp-challenge",
            challenge_id.0.as_bytes(),
        );
        let code_digest = code_digest(&self.config.digest_key, &challenge_digest, &code.0);
        let expires_at = now + self.config.lifetime;
        let resend_allowed_at = now + self.config.resend_cooldown;
        let attempt = EmailOtpAttempt {
            challenge_digest,
            email_digest,
            email: request.email.clone(),
            purpose: request.purpose.clone(),
            continue_path: request.continue_path,
            code_digest,
            created_at: now,
            expires_at,
            resend_allowed_at,
            attempts_remaining: self.config.max_attempts,
        };
        match self.attempts.create_or_replace(attempt, now).await {
            Ok(EmailOtpCreateOutcome::Created) => {}
            Ok(EmailOtpCreateOutcome::Cooldown) => return Err(EmailOtpError::RateLimited),
            Err(_) => return Err(EmailOtpError::Unavailable),
        }
        let message = EmailOtpMessage {
            code: &code,
            purpose: &request.purpose,
            expires_at,
        };
        if self
            .sender
            .send_email_otp(&request.email, message)
            .await
            .is_err()
        {
            let _ = self.attempts.invalidate(&challenge_digest).await;
            return Err(EmailOtpError::Unavailable);
        }
        Ok(EmailOtpChallenge {
            challenge_id,
            expires_at,
            resend_allowed_at,
        })
    }

    /// Atomically verifies a code and returns a verified email identity.
    ///
    /// # Errors
    ///
    /// Wrong code, unknown challenge, expiry, replay, and exhausted attempt
    /// budget all use [`EmailOtpError::VerificationFailed`].
    pub async fn verify(
        &self,
        verification: EmailOtpVerification<'_>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedEmailIdentity, EmailOtpError> {
        validate_partition(verification.ip_partition)?;
        if parse_challenge_id(verification.challenge_id).is_none() || !valid_code(verification.code)
        {
            return Err(EmailOtpError::VerificationFailed);
        }
        let challenge_digest = domain_digest(
            &self.config.digest_key,
            b"email-otp-challenge",
            verification.challenge_id.as_bytes(),
        );
        let context = EmailOtpVerifyRateLimitContext {
            challenge_digest,
            ip_partition: verification.ip_partition.to_owned(),
        };
        match self.limiter.check_verify(&context, now).await {
            Ok(EmailOtpRateLimitDecision::Allowed) => {}
            Ok(EmailOtpRateLimitDecision::Rejected) => {
                return Err(EmailOtpError::RateLimited);
            }
            Err(_) => return Err(EmailOtpError::Unavailable),
        }
        let presented_digest = code_digest(
            &self.config.digest_key,
            &challenge_digest,
            verification.code,
        );
        match self
            .attempts
            .verify_and_consume(&challenge_digest, &presented_digest, now)
            .await
            .map_err(|_| EmailOtpError::Unavailable)?
        {
            EmailOtpVerifyOutcome::Verified(attempt) => {
                let attempt = *attempt;
                Ok(VerifiedEmailIdentity {
                    email: attempt.email,
                    purpose: attempt.purpose,
                    continue_path: attempt.continue_path,
                    verified_at: now,
                })
            }
            EmailOtpVerifyOutcome::Rejected | EmailOtpVerifyOutcome::Invalid => {
                Err(EmailOtpError::VerificationFailed)
            }
        }
    }

    /// Removes expired challenges.
    ///
    /// # Errors
    ///
    /// Returns the consumer storage failure.
    pub async fn cleanup(&self, now: DateTime<Utc>) -> Result<usize, EmailOtpStorageError> {
        self.attempts.cleanup(now).await
    }
}

fn validate_continue_path(value: &str) -> Result<(), EmailOtpError> {
    if value.is_empty()
        || value.len() > 2048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.contains('#')
        || value.chars().any(char::is_control)
    {
        return Err(EmailOtpError::InvalidConfiguration);
    }
    let base = Url::parse("https://continuation.invalid/")
        .map_err(|_| EmailOtpError::InvalidConfiguration)?;
    let joined = base
        .join(value)
        .map_err(|_| EmailOtpError::InvalidConfiguration)?;
    if joined.origin() != base.origin() {
        return Err(EmailOtpError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_partition(value: &str) -> Result<(), EmailOtpError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(EmailOtpError::InvalidRequest);
    }
    Ok(())
}

fn random_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 32];
    fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn parse_challenge_id(value: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

fn random_code() -> Result<String, getrandom::Error> {
    loop {
        let mut bytes = [0_u8; 4];
        fill(&mut bytes)?;
        let value = u32::from_le_bytes(bytes);
        if value < MAX_RANDOM_WITHOUT_BIAS {
            return Ok(format!("{:06}", value % OTP_SPACE));
        }
    }
}

fn valid_code(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn code_digest(key: &[u8; 32], challenge_digest: &[u8; 32], code: &str) -> [u8; 32] {
    let mut value = Vec::with_capacity(challenge_digest.len() + code.len());
    value.extend_from_slice(challenge_digest);
    value.extend_from_slice(code.as_bytes());
    domain_digest(key, b"email-otp-code", &value)
}

fn domain_digest(key: &[u8; 32], domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(domain);
    mac.update(&[0]);
    mac.update(value);
    mac.finalize().into_bytes().into()
}
