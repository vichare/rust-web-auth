#![forbid(unsafe_code)]
//! Framework-neutral cookie, request-redaction, and authenticated-context helpers.

use cookie::{Cookie, SameSite, time::Duration};
use http::{HeaderValue, Uri, header::HeaderName};
use rust_web_auth_core::{AuthenticatedContext, UserId};
use thiserror::Error;

/// Deployment environment controlling cookie invariants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    /// Enforces `Secure` and the `__Host-` prefix.
    Production,
    /// Permits an insecure host-only cookie for loopback development.
    Development,
}

/// Validated host-only cookie policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CookiePolicy {
    name: String,
    secure: bool,
}

impl CookiePolicy {
    /// Creates a host-only cookie policy.
    ///
    /// Production automatically emits `__Host-{name}` and cannot disable
    /// `Secure`. Neither mode ever emits `Domain`.
    ///
    /// # Errors
    ///
    /// Returns [`CookieError::InvalidName`] for an unsafe cookie name.
    pub fn new(environment: Environment, name: impl Into<String>) -> Result<Self, CookieError> {
        let name = name.into();
        if name.is_empty()
            || name.starts_with("__Host-")
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CookieError::InvalidName);
        }
        Ok(match environment {
            Environment::Production => Self {
                name: format!("__Host-{name}"),
                secure: true,
            },
            Environment::Development => Self {
                name,
                secure: false,
            },
        })
    }

    /// Returns the exact cookie name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether `Secure` is enabled.
    #[must_use]
    pub const fn secure(&self) -> bool {
        self.secure
    }
}

/// Cookie construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CookieError {
    /// Cookie name contains unsafe bytes or a caller-supplied prefix.
    #[error("invalid cookie name")]
    InvalidName,
    /// Value cannot be represented as an HTTP header.
    #[error("cookie cannot be represented as an HTTP header")]
    InvalidHeader,
    /// Max age does not fit the cookie representation.
    #[error("cookie max age is invalid")]
    InvalidMaxAge,
}

/// Builds an issued session or OAuth-state cookie.
///
/// The result is always `HttpOnly`, `SameSite=Lax`, `Path=/`, and host-only.
///
/// # Errors
///
/// Returns [`CookieError`] for an invalid value or lifetime.
pub fn issued_cookie(
    policy: &CookiePolicy,
    value: &str,
    max_age_seconds: u64,
) -> Result<HeaderValue, CookieError> {
    cookie_header(policy, value, max_age_seconds)
}

/// Builds a cookie that deletes the session or OAuth state.
///
/// # Errors
///
/// Returns [`CookieError`] when the header cannot be represented.
pub fn expired_cookie(policy: &CookiePolicy) -> Result<HeaderValue, CookieError> {
    cookie_header(policy, "", 0)
}

fn cookie_header(
    policy: &CookiePolicy,
    value: &str,
    max_age_seconds: u64,
) -> Result<HeaderValue, CookieError> {
    let seconds = i64::try_from(max_age_seconds).map_err(|_| CookieError::InvalidMaxAge)?;
    let cookie = Cookie::build((policy.name.clone(), value.to_owned()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(policy.secure)
        .max_age(Duration::seconds(seconds))
        .build();
    HeaderValue::from_str(&cookie.to_string()).map_err(|_| CookieError::InvalidHeader)
}

/// Returns only the path suitable for request logs.
///
/// Query strings are discarded wholesale because callback parameters and
/// future parameters may contain codes, state, nonce, verifiers, or tokens.
#[must_use]
pub fn safe_request_target(uri: &Uri) -> &str {
    uri.path()
}

/// Returns whether a header value must never be logged.
#[must_use]
pub fn is_sensitive_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization" | "cookie" | "proxy-authorization" | "set-cookie"
    )
}

/// Trusted request extension for business handlers.
#[derive(Clone, Debug)]
pub struct AuthenticatedRequest {
    context: AuthenticatedContext,
}

impl AuthenticatedRequest {
    /// Wraps a context produced by [`rust_web_auth_core::SessionService`].
    #[must_use]
    pub const fn new(context: AuthenticatedContext) -> Self {
        Self { context }
    }

    /// Returns the only user identifier business handlers should trust.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.context.user_id
    }

    /// Returns the complete trusted context.
    #[must_use]
    pub const fn context(&self) -> &AuthenticatedContext {
        &self.context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_cookie_enforces_host_prefix_and_attributes() {
        let policy = CookiePolicy::new(Environment::Production, "cook_session").unwrap();
        let value = issued_cookie(&policy, "secret", 30 * 24 * 60 * 60)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        for expected in [
            "__Host-cook_session=secret",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Path=/",
            "Max-Age=2592000",
        ] {
            assert!(value.contains(expected), "{value} lacks {expected}");
        }
        assert!(!value.contains("Domain="));
    }

    #[test]
    fn production_secure_cannot_be_disabled() {
        let production = CookiePolicy::new(Environment::Production, "session").unwrap();
        let development = CookiePolicy::new(Environment::Development, "session").unwrap();
        assert!(production.secure());
        assert!(!development.secure());
        assert_eq!(production.name(), "__Host-session");
        assert_eq!(development.name(), "session");
    }

    #[test]
    fn request_logging_drops_query_and_sensitive_headers() {
        let uri: Uri = "/auth/google/callback?code=secret&state=secret&nonce=secret"
            .parse()
            .unwrap();
        assert_eq!(safe_request_target(&uri), "/auth/google/callback");
        assert!(is_sensitive_header(&http::header::COOKIE));
        assert!(is_sensitive_header(&http::header::AUTHORIZATION));
        assert!(!is_sensitive_header(&http::header::USER_AGENT));
    }
}
