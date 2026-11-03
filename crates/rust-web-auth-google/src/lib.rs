#![forbid(unsafe_code)]
//! Google `OpenID` Connect adapter with lazy discovery and rotating JWKS.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeVerifier, RedirectUrl, RequestTokenError, TokenResponse,
    core::{CoreClient, CoreErrorResponseType, CoreProviderMetadata, CoreTokenResponse},
    reqwest,
};
use rust_web_auth_core::{IdentityKey, OidcProvider, ProviderError, VerifiedIdentity};
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;

const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const GOOGLE_AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

type ProviderClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Provider metadata/JWKS refresh policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRefreshPolicy {
    /// Cache age that triggers a scheduled refresh.
    pub max_age: Duration,
    /// Minimum interval between fetch attempts, including failed attempts.
    pub min_attempt_interval: Duration,
}

impl Default for KeyRefreshPolicy {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(60 * 60),
            min_attempt_interval: Duration::from_secs(60),
        }
    }
}

/// Google client construction error.
#[derive(Debug, Error)]
pub enum GoogleClientError {
    /// Issuer URL is invalid.
    #[error("invalid OIDC issuer")]
    InvalidIssuer,
    /// HTTP client could not be built.
    #[error("OIDC HTTP client could not be built")]
    HttpClient,
}

struct CachedMetadata {
    metadata: CoreProviderMetadata,
    fetched_at: Instant,
}

#[derive(Default)]
struct MetadataCache {
    current: Option<Arc<CachedMetadata>>,
    last_attempt_at: Option<Instant>,
}

#[derive(Clone, Copy)]
enum VerificationFailure {
    Signature,
    Rejected,
    Incomplete,
}

/// Backend-only Google relying-party implementation.
///
/// Construction performs no network access. Discovery and JWKS load lazily on
/// first callback, then refresh approximately hourly. The mutex intentionally
/// covers refresh I/O to provide single-flight behavior.
pub struct GoogleOidcClient {
    issuer: IssuerUrl,
    authorization_endpoint: Url,
    http_client: reqwest::Client,
    client_id: ClientId,
    client_secret: ClientSecret,
    refresh_policy: KeyRefreshPolicy,
    cache: Mutex<MetadataCache>,
}

impl GoogleOidcClient {
    /// Creates a production Google client without network access.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleClientError`] when client construction fails.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, GoogleClientError> {
        Self::with_issuer_and_authorization_endpoint(
            GOOGLE_ISSUER,
            GOOGLE_AUTHORIZATION_ENDPOINT,
            client_id,
            client_secret,
        )
    }

    /// Creates a client for a test/private issuer.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleClientError`] for invalid URLs or HTTP setup.
    pub fn with_issuer(
        issuer: &str,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, GoogleClientError> {
        let authorization_endpoint = format!("{}/authorize", issuer.trim_end_matches('/'));
        Self::with_issuer_and_authorization_endpoint(
            issuer,
            &authorization_endpoint,
            client_id,
            client_secret,
        )
    }

    fn with_issuer_and_authorization_endpoint(
        issuer: &str,
        authorization_endpoint: &str,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, GoogleClientError> {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|_| GoogleClientError::HttpClient)?;
        Ok(Self {
            issuer: IssuerUrl::new(issuer.to_owned())
                .map_err(|_| GoogleClientError::InvalidIssuer)?,
            authorization_endpoint: Url::parse(authorization_endpoint)
                .map_err(|_| GoogleClientError::InvalidIssuer)?,
            http_client,
            client_id: ClientId::new(client_id.into()),
            client_secret: ClientSecret::new(client_secret.into()),
            refresh_policy: KeyRefreshPolicy::default(),
            cache: Mutex::new(MetadataCache::default()),
        })
    }

    /// Overrides refresh timing, primarily for deterministic tests.
    #[must_use]
    pub const fn with_key_refresh_policy(mut self, policy: KeyRefreshPolicy) -> Self {
        self.refresh_policy = policy;
        self
    }

    async fn fetch_metadata(&self) -> Result<Arc<CachedMetadata>, ProviderError> {
        CoreProviderMetadata::discover_async(self.issuer.clone(), &self.http_client)
            .await
            .map(|metadata| {
                Arc::new(CachedMetadata {
                    metadata,
                    fetched_at: Instant::now(),
                })
            })
            .map_err(|_| ProviderError::ProviderUnavailable)
    }

    async fn metadata(&self) -> Result<Arc<CachedMetadata>, ProviderError> {
        let mut cache = self.cache.lock().await;
        let now = Instant::now();
        if let Some(current) = &cache.current
            && !(now.duration_since(current.fetched_at) >= self.refresh_policy.max_age
                && attempt_allowed(
                    self.refresh_policy,
                    cache
                        .last_attempt_at
                        .map(|attempt| now.duration_since(attempt)),
                ))
        {
            return Ok(current.clone());
        }
        cache.last_attempt_at = Some(now);
        match self.fetch_metadata().await {
            Ok(fresh) => {
                cache.current = Some(fresh.clone());
                Ok(fresh)
            }
            Err(error) => {
                if let Some(stale) = &cache.current {
                    tracing::warn!("OIDC metadata refresh failed; using cached metadata");
                    Ok(stale.clone())
                } else {
                    Err(error)
                }
            }
        }
    }

    async fn refresh_after_signature_failure(
        &self,
        used: &Arc<CachedMetadata>,
    ) -> Option<Arc<CachedMetadata>> {
        let mut cache = self.cache.lock().await;
        if let Some(current) = &cache.current
            && current.fetched_at > used.fetched_at
        {
            return Some(current.clone());
        }
        let now = Instant::now();
        if !attempt_allowed(
            self.refresh_policy,
            cache
                .last_attempt_at
                .map(|attempt| now.duration_since(attempt)),
        ) {
            return None;
        }
        cache.last_attempt_at = Some(now);
        if let Ok(fresh) = self.fetch_metadata().await {
            cache.current = Some(fresh.clone());
            Some(fresh)
        } else {
            tracing::warn!("OIDC JWKS refresh after signature failure failed");
            None
        }
    }

    fn client(&self, metadata: &CoreProviderMetadata) -> ProviderClient {
        CoreClient::from_provider_metadata(
            metadata.clone(),
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
    }

    async fn exchange_code(
        &self,
        metadata: &CoreProviderMetadata,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
    ) -> Result<CoreTokenResponse, ProviderError> {
        let redirect_uri =
            RedirectUrl::new(redirect_uri.to_owned()).map_err(|_| ProviderError::TokenRejected)?;
        self.client(metadata)
            .set_redirect_uri(redirect_uri)
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| ProviderError::ProviderUnavailable)?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_owned()))
            .request_async(&self.http_client)
            .await
            .map_err(|error| match error {
                RequestTokenError::ServerResponse(response) => {
                    classify_token_server_error(response.error())
                }
                _ => ProviderError::ProviderUnavailable,
            })
    }

    fn verify(
        &self,
        metadata: &CoreProviderMetadata,
        response: &CoreTokenResponse,
        nonce: &str,
    ) -> Result<VerifiedIdentity, VerificationFailure> {
        let client = self.client(metadata);
        let id_token = response.id_token().ok_or(VerificationFailure::Rejected)?;
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &Nonce::new(nonce.to_owned()))
            .map_err(|error| match error {
                ClaimsVerificationError::SignatureVerification(_) => VerificationFailure::Signature,
                _ => VerificationFailure::Rejected,
            })?;
        if let Some(expected_hash) = claims.access_token_hash() {
            let algorithm = id_token
                .signing_alg()
                .map_err(|_| VerificationFailure::Rejected)?;
            let signing_key = id_token
                .signing_key(&verifier)
                .map_err(|_| VerificationFailure::Signature)?;
            let actual_hash =
                AccessTokenHash::from_token(response.access_token(), algorithm, signing_key)
                    .map_err(|_| VerificationFailure::Rejected)?;
            if actual_hash != *expected_hash {
                return Err(VerificationFailure::Rejected);
            }
        }
        if claims.email_verified() != Some(true) {
            return Err(VerificationFailure::Incomplete);
        }
        let verified_email = claims
            .email()
            .ok_or(VerificationFailure::Incomplete)?
            .as_str()
            .to_owned();
        let display_name = claims
            .name()
            .and_then(|name| {
                name.get(None)
                    .or_else(|| name.iter().next().map(|(_, value)| value))
            })
            .map(|value| value.as_str().to_owned())
            .filter(|value| !value.trim().is_empty());
        Ok(VerifiedIdentity {
            key: IdentityKey {
                issuer: claims.issuer().as_str().to_owned(),
                subject: claims.subject().as_str().to_owned(),
            },
            verified_email,
            display_name,
        })
    }
}

fn attempt_allowed(policy: KeyRefreshPolicy, elapsed: Option<Duration>) -> bool {
    elapsed.is_none_or(|elapsed| elapsed >= policy.min_attempt_interval)
}

fn map_verification_failure(failure: VerificationFailure) -> ProviderError {
    match failure {
        VerificationFailure::Signature | VerificationFailure::Rejected => {
            ProviderError::TokenRejected
        }
        VerificationFailure::Incomplete => ProviderError::IdentityIncomplete,
    }
}

fn classify_token_server_error(error: &CoreErrorResponseType) -> ProviderError {
    match error {
        CoreErrorResponseType::InvalidGrant => ProviderError::TokenRejected,
        CoreErrorResponseType::InvalidClient
        | CoreErrorResponseType::InvalidRequest
        | CoreErrorResponseType::InvalidScope
        | CoreErrorResponseType::UnauthorizedClient
        | CoreErrorResponseType::UnsupportedGrantType
        | CoreErrorResponseType::Extension(_) => ProviderError::ProviderUnavailable,
    }
}

#[async_trait]
impl OidcProvider for GoogleOidcClient {
    fn authorization_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: &str,
    ) -> Url {
        let mut url = self.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("client_id", self.client_id.as_str())
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email profile")
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("access_type", "online")
            .append_pair("prompt", "select_account");
        url
    }

    async fn redeem_code(
        &self,
        authorization_code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ProviderError> {
        let metadata = self.metadata().await?;
        let response = self
            .exchange_code(
                &metadata.metadata,
                authorization_code,
                redirect_uri,
                pkce_verifier,
            )
            .await?;
        match self.verify(&metadata.metadata, &response, nonce) {
            Err(VerificationFailure::Signature) => {
                let Some(refreshed) = self.refresh_after_signature_failure(&metadata).await else {
                    return Err(ProviderError::TokenRejected);
                };
                // Reverify the same ID token. The authorization code is never exchanged again.
                self.verify(&refreshed.metadata, &response, nonce)
                    .map_err(map_verification_failure)
            }
            other => other.map_err(map_verification_failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_url_has_minimal_scopes_and_security_parameters() {
        let client = GoogleOidcClient::new("client", "secret").unwrap();
        let url = client.authorization_url(
            "https://app.example/callback",
            "state",
            "nonce",
            "challenge",
        );
        let parameters: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(parameters["response_type"], "code");
        assert_eq!(parameters["scope"], "openid email profile");
        assert_eq!(parameters["code_challenge_method"], "S256");
        assert_eq!(parameters["state"], "state");
        assert_eq!(parameters["nonce"], "nonce");
    }

    #[test]
    fn refresh_throttle_is_enforced() {
        let policy = KeyRefreshPolicy::default();
        assert!(attempt_allowed(policy, None));
        assert!(!attempt_allowed(policy, Some(Duration::from_secs(59))));
        assert!(attempt_allowed(policy, Some(Duration::from_secs(60))));
    }

    #[test]
    fn token_endpoint_errors_preserve_retryability() {
        assert_eq!(
            classify_token_server_error(&CoreErrorResponseType::InvalidGrant),
            ProviderError::TokenRejected
        );
        assert_eq!(
            classify_token_server_error(&CoreErrorResponseType::Extension(
                "temporarily_unavailable".to_owned()
            )),
            ProviderError::ProviderUnavailable
        );
        assert_eq!(
            classify_token_server_error(&CoreErrorResponseType::Extension(
                "server_error".to_owned()
            )),
            ProviderError::ProviderUnavailable
        );
    }
}
