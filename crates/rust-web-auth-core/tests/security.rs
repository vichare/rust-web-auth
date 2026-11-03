//! Security invariants exercised against in-memory consumer ports.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use rust_web_auth_core::{
    AttemptStore, CasOutcome, IdentityKey, IdentityMapper, LoginAttempt, LoginCallback,
    LoginConfig, LoginError, LoginRateLimiter, LoginService, OidcProvider, ProviderError,
    RateLimitDecision, SessionConfig, SessionId, SessionRecord, SessionService, SessionStore,
    StorageError, UserId, VerifiedIdentity,
};
use url::Url;

#[derive(Default)]
struct MemoryAttempts(Mutex<HashMap<[u8; 32], LoginAttempt>>);

#[async_trait]
impl AttemptStore for MemoryAttempts {
    async fn create(&self, attempt: LoginAttempt) -> Result<(), StorageError> {
        let mut records = self.0.lock().unwrap();
        if records.insert(attempt.state_digest, attempt).is_some() {
            return Err(StorageError);
        }
        Ok(())
    }

    async fn consume_and_delete(
        &self,
        digest: &[u8; 32],
        now: chrono::DateTime<Utc>,
    ) -> Result<Option<LoginAttempt>, StorageError> {
        let mut records = self.0.lock().unwrap();
        Ok(records
            .get(digest)
            .filter(|attempt| attempt.is_available_at(now))
            .cloned()
            .and_then(|attempt| records.remove(digest).map(|_| attempt)))
    }

    async fn cleanup(&self, now: chrono::DateTime<Utc>) -> Result<usize, StorageError> {
        let mut records = self.0.lock().unwrap();
        let before = records.len();
        records.retain(|_, attempt| attempt.is_available_at(now));
        Ok(before - records.len())
    }
}

#[derive(Default)]
struct MemorySessions {
    by_id: Mutex<HashMap<SessionId, SessionRecord>>,
}

#[async_trait]
impl SessionStore for MemorySessions {
    async fn create(&self, session: SessionRecord) -> Result<(), StorageError> {
        self.by_id
            .lock()
            .unwrap()
            .insert(session.session_id, session);
        Ok(())
    }

    async fn find_by_token_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<Option<SessionRecord>, StorageError> {
        Ok(self
            .by_id
            .lock()
            .unwrap()
            .values()
            .find(|record| &record.token_digest == digest)
            .cloned())
    }

    async fn find_by_id(&self, id: SessionId) -> Result<Option<SessionRecord>, StorageError> {
        Ok(self.by_id.lock().unwrap().get(&id).cloned())
    }

    async fn replace_if_unchanged(
        &self,
        expected: &SessionRecord,
        replacement: SessionRecord,
    ) -> Result<CasOutcome, StorageError> {
        let mut records = self.by_id.lock().unwrap();
        if records.get(&expected.session_id) != Some(expected) {
            return Ok(CasOutcome::Stale);
        }
        records.insert(expected.session_id, replacement);
        Ok(CasOutcome::Updated)
    }

    async fn revoke_all_for_user(
        &self,
        user_id: &UserId,
        revoked_at: chrono::DateTime<Utc>,
    ) -> Result<usize, StorageError> {
        let mut count = 0;
        for session in self.by_id.lock().unwrap().values_mut() {
            if &session.user_id == user_id && session.revoked_at.is_none() {
                session.revoked_at = Some(revoked_at);
                session.version += 1;
                count += 1;
            }
        }
        Ok(count)
    }
}

#[derive(Default)]
struct Mapper(Mutex<HashMap<IdentityKey, UserId>>);

#[async_trait]
impl IdentityMapper for Mapper {
    async fn resolve_user(&self, identity: &VerifiedIdentity) -> Result<UserId, StorageError> {
        let mut mappings = self.0.lock().unwrap();
        let next_id = UserId::new(format!("user-{}", mappings.len() + 1)).unwrap();
        Ok(mappings
            .entry(identity.key.clone())
            .or_insert(next_id)
            .clone())
    }

    async fn find_user(&self, key: &IdentityKey) -> Result<Option<UserId>, StorageError> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
}

struct Allow;

#[async_trait]
impl LoginRateLimiter for Allow {
    async fn check(
        &self,
        _key: &str,
        _now: chrono::DateTime<Utc>,
    ) -> Result<RateLimitDecision, StorageError> {
        Ok(RateLimitDecision::Allowed)
    }
}

#[derive(Default)]
struct FakeProvider {
    redemptions: Mutex<Vec<(String, String, String, String)>>,
    failure: Mutex<Option<ProviderError>>,
}

#[async_trait]
impl OidcProvider for FakeProvider {
    fn authorization_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        challenge: &str,
    ) -> Url {
        let mut url = Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        url
    }

    async fn redeem_code(
        &self,
        code: &str,
        redirect_uri: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ProviderError> {
        self.redemptions.lock().unwrap().push((
            code.to_owned(),
            redirect_uri.to_owned(),
            verifier.to_owned(),
            nonce.to_owned(),
        ));
        if let Some(error) = *self.failure.lock().unwrap() {
            return Err(error);
        }
        Ok(VerifiedIdentity {
            key: IdentityKey {
                issuer: "https://accounts.google.com".into(),
                subject: "subject-1".into(),
            },
            verified_email: "first@example.com".into(),
            display_name: Some("Example".into()),
        })
    }
}

struct TestContext {
    login: Arc<LoginService>,
    sessions: Arc<SessionService>,
    session_store: Arc<MemorySessions>,
    provider: Arc<FakeProvider>,
}

fn services() -> TestContext {
    let attempts = Arc::new(MemoryAttempts::default());
    let sessions = Arc::new(MemorySessions::default());
    let session_service =
        Arc::new(SessionService::new(SessionConfig::default(), sessions.clone(), [4; 32]).unwrap());
    let provider = Arc::new(FakeProvider::default());
    let login = Arc::new(LoginService::new(
        LoginConfig::new("https://app.example/auth/google/callback", [3; 32]).unwrap(),
        provider.clone(),
        attempts.clone(),
        Arc::new(Mapper::default()),
        Arc::new(Allow),
        session_service.clone(),
    ));
    TestContext {
        login,
        sessions: session_service,
        session_store: sessions,
        provider,
    }
}

#[tokio::test]
async fn login_uses_state_nonce_s256_and_consumes_attempt_once() {
    let context = services();
    let login = context.login;
    let provider = context.provider;
    let now = Utc::now();
    let start = login.begin("client", now).await.unwrap();
    let parameters: HashMap<_, _> = start.authorization_url.query_pairs().into_owned().collect();
    assert_eq!(parameters["code_challenge_method"], "S256");
    assert_eq!(parameters["state"], start.state_cookie_value);
    assert!(!parameters["nonce"].is_empty());
    assert_eq!(parameters["code_challenge"].len(), 43);

    let callback = LoginCallback {
        state: Some(&start.state_cookie_value),
        state_cookie: Some(&start.state_cookie_value),
        authorization_code: Some("backend-code"),
        provider_reported_error: false,
    };
    let completed = login.complete(callback, now).await.unwrap();
    assert_eq!(completed.user_id.as_str(), "user-1");
    assert_eq!(provider.redemptions.lock().unwrap().len(), 1);
    assert_eq!(
        login.complete(callback, now).await,
        Err(LoginError::InvalidAttempt)
    );
    assert_eq!(provider.redemptions.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn state_mismatch_does_not_consume_the_attempt() {
    let context = services();
    let login = context.login;
    let provider = context.provider;
    let now = Utc::now();
    let start = login.begin("client", now).await.unwrap();
    let mismatch = LoginCallback {
        state: Some(&start.state_cookie_value),
        state_cookie: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        authorization_code: Some("code"),
        provider_reported_error: false,
    };
    assert_eq!(
        login.complete(mismatch, now).await,
        Err(LoginError::InvalidAttempt)
    );
    assert!(provider.redemptions.lock().unwrap().is_empty());

    let valid = LoginCallback {
        state: Some(&start.state_cookie_value),
        state_cookie: Some(&start.state_cookie_value),
        authorization_code: Some("code"),
        provider_reported_error: false,
    };
    assert!(login.complete(valid, now).await.is_ok());
}

#[tokio::test]
async fn concurrent_callback_replay_has_exactly_one_winner() {
    let context = services();
    let now = Utc::now();
    let start = context.login.begin("client", now).await.unwrap();
    let state_a = start.state_cookie_value.clone();
    let state_b = start.state_cookie_value;
    let login_a = context.login.clone();
    let login_b = context.login.clone();
    let first = async move {
        login_a
            .complete(
                LoginCallback {
                    state: Some(&state_a),
                    state_cookie: Some(&state_a),
                    authorization_code: Some("code-a"),
                    provider_reported_error: false,
                },
                now,
            )
            .await
    };
    let second = async move {
        login_b
            .complete(
                LoginCallback {
                    state: Some(&state_b),
                    state_cookie: Some(&state_b),
                    authorization_code: Some("code-b"),
                    provider_reported_error: false,
                },
                now,
            )
            .await
    };
    let (first, second) = tokio::join!(first, second);
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(first == Err(LoginError::InvalidAttempt) || second == Err(LoginError::InvalidAttempt));
    assert_eq!(context.provider.redemptions.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn provider_error_classes_are_preserved() {
    for (provider_error, login_error) in [
        (
            ProviderError::ProviderUnavailable,
            LoginError::ProviderUnavailable,
        ),
        (ProviderError::TokenRejected, LoginError::TokenRejected),
        (
            ProviderError::IdentityIncomplete,
            LoginError::IdentityIncomplete,
        ),
    ] {
        let context = services();
        *context.provider.failure.lock().unwrap() = Some(provider_error);
        let now = Utc::now();
        let start = context.login.begin("client", now).await.unwrap();
        let result = context
            .login
            .complete(
                LoginCallback {
                    state: Some(&start.state_cookie_value),
                    state_cookie: Some(&start.state_cookie_value),
                    authorization_code: Some("code"),
                    provider_reported_error: false,
                },
                now,
            )
            .await;
        assert_eq!(result, Err(login_error));
    }
}

#[tokio::test]
async fn session_store_receives_digest_not_raw_token_and_renews_throttled() {
    let context = services();
    let service = context.sessions;
    let sessions = context.session_store;
    let now = Utc::now();
    let issued = service
        .issue(UserId::new("business-user").unwrap(), now)
        .await
        .unwrap();
    let stored = sessions
        .by_id
        .lock()
        .unwrap()
        .get(&issued.session_id)
        .unwrap()
        .clone();
    assert_ne!(
        stored.token_digest.as_slice(),
        issued.cookie_value.as_bytes()
    );
    assert_eq!(issued.cookie_value.len(), 43);

    let before = service
        .authenticate(&issued.cookie_value, now + Duration::hours(23))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.renewed_expires_at, None);
    let renewed = service
        .authenticate(&issued.cookie_value, now + Duration::hours(24))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        renewed.renewed_expires_at,
        Some(now + Duration::hours(24) + Duration::days(30))
    );
    let repeated = service
        .authenticate(&issued.cookie_value, now + Duration::hours(25))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repeated.renewed_expires_at, None);
}

#[tokio::test]
async fn current_and_all_device_revocation_use_authenticated_context() {
    let service = services().sessions;
    let now = Utc::now();
    let user = UserId::new("business-user").unwrap();
    let first = service.issue(user.clone(), now).await.unwrap();
    let second = service.issue(user, now).await.unwrap();
    let context = service
        .authenticate(&second.cookie_value, now)
        .await
        .unwrap()
        .unwrap();

    assert!(
        service
            .revoke_current(&first.cookie_value, now)
            .await
            .unwrap()
    );
    assert_eq!(service.revoke_all(&context, now).await.unwrap(), 1);
    assert!(
        service
            .authenticate(&second.cookie_value, now)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn redirect_uri_validation_is_strict() {
    assert!(LoginConfig::new("https://app.example/auth/callback", [0; 32]).is_ok());
    assert!(LoginConfig::new("http://localhost:3000/auth/callback", [0; 32]).is_ok());
    for rejected in [
        "http://app.example/auth/callback",
        "https://user@app.example/auth/callback",
        "https://app.example/auth/callback?next=/",
        "https://app.example/auth/callback#fragment",
        "not-a-url",
    ] {
        assert_eq!(
            LoginConfig::new(rejected, [0; 32]).err(),
            Some(LoginError::InvalidConfiguration),
            "{rejected}"
        );
    }
}

#[test]
fn debug_output_redacts_session_token() {
    let completion = rust_web_auth_core::LoginCompletion {
        cookie_value: "secret-session-token".into(),
        user_id: UserId::new("user").unwrap(),
        session_id: uuid::Uuid::now_v7(),
        expires_at: Utc::now(),
    };
    let debug = format!("{completion:?}");
    assert!(!debug.contains("secret-session-token"));
    assert!(debug.contains("[REDACTED]"));

    let callback = LoginCallback {
        state: Some("secret-state"),
        state_cookie: Some("secret-cookie"),
        authorization_code: Some("secret-code"),
        provider_reported_error: false,
    };
    let debug = format!("{callback:?}");
    assert!(!debug.contains("secret-"));
}
