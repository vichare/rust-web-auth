//! End-to-end rotating-JWKS verification against a local OIDC provider.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration as ChronoDuration, Utc};
use openidconnect::{
    AccessToken, Audience, EmptyAdditionalClaims, EmptyExtraTokenFields, EndUserEmail, EndUserName,
    IssuerUrl, JsonWebKeyId, Nonce, PrivateSigningKey, StandardClaims, SubjectIdentifier,
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey, CoreTokenResponse, CoreTokenType,
    },
};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, pkcs8::LineEnding, rand_core::OsRng};
use rust_web_auth_core::OidcProvider;
use rust_web_auth_google::{GoogleOidcClient, KeyRefreshPolicy};
use tokio::net::TcpListener;

const CLIENT_ID: &str = "test-client";

fn signing_key(id: &str) -> Arc<CoreRsaPrivateSigningKey> {
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let pem = key.to_pkcs1_pem(LineEnding::LF).unwrap();
    Arc::new(
        CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new(id.to_owned()))).unwrap(),
    )
}

struct TestProvider {
    base_url: String,
    discovery_count: AtomicUsize,
    token_count: AtomicUsize,
    keys: Mutex<Vec<Arc<CoreRsaPrivateSigningKey>>>,
    nonce: Mutex<String>,
}

type SharedProvider = Arc<TestProvider>;

async fn discovery(State(provider): State<SharedProvider>) -> Response {
    provider.discovery_count.fetch_add(1, Ordering::SeqCst);
    let base = &provider.base_url;
    Json(serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
    .into_response()
}

async fn jwks(State(provider): State<SharedProvider>) -> Response {
    let keys = provider
        .keys
        .lock()
        .unwrap()
        .iter()
        .map(|key| key.as_verification_key())
        .collect();
    Json(CoreJsonWebKeySet::new(keys)).into_response()
}

async fn token(State(provider): State<SharedProvider>) -> Response {
    provider.token_count.fetch_add(1, Ordering::SeqCst);
    let key = provider.keys.lock().unwrap().last().unwrap().clone();
    let access_token = AccessToken::new("access-token".into());
    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(provider.base_url.clone()).unwrap(),
        vec![Audience::new(CLIENT_ID.into())],
        Utc::now() + ChronoDuration::minutes(5),
        Utc::now(),
        StandardClaims::new(SubjectIdentifier::new("subject-1".into()))
            .set_email(Some(EndUserEmail::new("user@example.com".into())))
            .set_email_verified(Some(true))
            .set_name(Some(EndUserName::new("Test User".into()).into())),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(provider.nonce.lock().unwrap().clone())));
    let id_token = CoreIdToken::new(
        claims,
        &*key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        Some(&access_token),
        None,
    )
    .unwrap();
    Json(CoreTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    ))
    .into_response()
}

async fn start_provider() -> SharedProvider {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = Arc::new(TestProvider {
        base_url: format!("http://{}", listener.local_addr().unwrap()),
        discovery_count: AtomicUsize::new(0),
        token_count: AtomicUsize::new(0),
        keys: Mutex::new(vec![signing_key("key-1")]),
        nonce: Mutex::new(String::new()),
    });
    let router = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(provider.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    provider
}

async fn redeem(
    client: &GoogleOidcClient,
    provider: &SharedProvider,
    nonce: &str,
) -> rust_web_auth_core::VerifiedIdentity {
    nonce.clone_into(&mut provider.nonce.lock().unwrap());
    client
        .redeem_code(
            "authorization-code",
            "https://app.example/callback",
            "pkce-verifier",
            nonce,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn signature_failure_refreshes_once_and_reverifies_without_code_reexchange() {
    let provider = start_provider().await;
    let client = GoogleOidcClient::with_issuer(&provider.base_url, CLIENT_ID, "secret")
        .unwrap()
        .with_key_refresh_policy(KeyRefreshPolicy {
            max_age: Duration::from_secs(3600),
            min_attempt_interval: Duration::ZERO,
        });
    assert_eq!(
        redeem(&client, &provider, "nonce-1").await.key.subject,
        "subject-1"
    );
    *provider.keys.lock().unwrap() = vec![signing_key("key-2")];
    assert_eq!(
        redeem(&client, &provider, "nonce-2").await.key.subject,
        "subject-1"
    );
    assert_eq!(provider.discovery_count.load(Ordering::SeqCst), 2);
    assert_eq!(provider.token_count.load(Ordering::SeqCst), 2);
}
