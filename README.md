# rust-web-auth

Reusable, storage-independent Rust web authentication for Cook, SOP-Node, and
other first-party applications. It supports backend Google OIDC, email OTP,
passkeys, and browser application sessions; there is no desktop channel.

## Status

- **updated:** 2026-11-04
- **status:** active
- **progress:** Core login/session services, Google adapter, mainland-China
  phase 1 email-OTP/passkey foundations, HTTP helpers, security tests, and
  consumer documentation are implemented.
- **decisions:** Each consumer owns its users, identity mappings, sessions,
  database, keys, rate limits, and host-only cookies. Consumers pin an exact Git
  revision. `(issuer, subject)` is the only external identity key.
- **next actions:** Upgrade Cook to the new pinned revision, implement its
  storage/mail adapters and explicit account-linking UI, then validate real
  passkeys and mail delivery in staging.

### Facts and unverified assumptions

- **Fact:** This workspace has no SOP domain, protobuf, or
  `vichare_data_store` dependency.
- **Fact:** Ports require atomic one-time attempt consumption and CAS session
  updates, but consumers choose the database.
- **Fact:** Google discovery/JWKS are lazy, cached for one hour by default, and
  refreshed single-flight after a signature failure.
- **Fact:** Email-OTP and passkey support are independent crates, so existing
  Google consumers do not compile their heavier dependencies.
- **Fact:** Shared services return verified identities or consumer user IDs but
  never merge accounts by matching email.
- **Unverified:** Cook's final user identifier representation, database
  transaction API, route layout, and rate-limit key.
- **Unverified:** SOP-Node's existing records can be migrated without a
  compatibility reader. Confirm during consumer adaptation.
- **Unverified:** Cook and SOP-Node have not yet pinned the revision containing
  email OTP and passkey support in their manifests.

## Workspace boundaries

| Crate | Responsibility |
|---|---|
| `rust-web-auth-core` | Domain models, ports, Authorization Code + S256 PKCE orchestration, identity mapping boundary, and application sessions |
| `rust-web-auth-google` | Google discovery, token exchange, ID-token verification, JWKS caching/rotation |
| `rust-web-auth-http` | Secure host-only cookie construction, log-safe request metadata, trusted request context wrapper |
| `rust-web-auth-email-otp` | CSPRNG six-digit email codes, opaque challenge IDs, atomic attempt policy, layered rate limits, and verified email completion |
| `rust-web-auth-passkey` | Typed `webauthn-rs` registration/authentication ceremonies, challenge state, credential persistence ports, counter updates, and revocation |

The HTTP crate deliberately does not choose Axum, Actix, or another framework.
An application handler reads the state cookie/query, calls the core service,
and translates the classified result into its own response.

## Security properties

- The backend is the sole Google relying party. Frontend JavaScript receives
  only redirects and the application's opaque session cookie, never a Google
  code, access token, or ID token.
- Google login uses Authorization Code, S256 PKCE, nonce, and state. Attempts
  default to 10 minutes and the `AttemptStore` contract requires atomic
  consume-and-delete.
- Verified identity is keyed by `(issuer, subject)`. Email is profile data only,
  and the Google adapter requires `email_verified=true`.
- Discovery/JWKS load lazily. Cached metadata refreshes after about one hour.
  Signature failure may trigger a rate-limited, single-flight refresh and
  reverification of the same ID token. It never exchanges the code again.
- Session tokens contain 256 random bits. Persistence receives only an
  HMAC-SHA-256 digest.
- Sessions use 30-day sliding expiry and a 24-hour persistence throttle.
  Optimistic CAS prevents a stale request overwriting newer session state.
- Production cookies are always `HttpOnly; Secure; SameSite=Lax; Path=/`, use
  the `__Host-` prefix, and never contain `Domain`.
- Request-log helpers discard the complete query and identify
  `Cookie`, `Set-Cookie`, `Authorization`, and `Proxy-Authorization` as
  sensitive.
- Email OTP uses an unbiased CSPRNG six-digit code and independent 256-bit
  challenge ID. Only challenge-bound, server-secret HMAC digests are persisted.
- OTP attempts expire after 10 minutes, enforce a resend cooldown and five
  guesses, keep one active challenge per email/purpose, and atomically
  invalidate on success, expiry, exhaustion, or replacement.
- OTP request completion has no account lookup, and therefore no
  account-existence result. Consumers render one uniform accepted response.
- Passkey RP ID/origin configuration fails closed, user verification is
  required, and challenge state is short-lived and one-time.
- Passkey registration requires an authenticated user. Authentication returns
  the consumer user recorded in the ceremony and never links by email.

See [SECURITY.md](SECURITY.md) for the threat model.

## Consumer dependency

Pin a reviewed commit; never consume a moving branch:

```toml
[dependencies]
rust-web-auth-core = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }
rust-web-auth-google = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }
rust-web-auth-http = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }
rust-web-auth-email-otp = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }
rust-web-auth-passkey = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }
```

Select only the crates the application uses. Existing Google-only consumers
remain source compatible and do not inherit email or WebAuthn dependencies.
The existing core/Google/HTTP/email crates retain Rust 1.85 compatibility;
`rust-web-auth-passkey` requires Rust 1.89 to use maintained
`webauthn-rs 0.6.2`.

## Quick integration

Implement consumer storage and mapping ports, then compose services in server
startup:

```rust,no_run
use std::sync::Arc;
use rust_web_auth_core::{
    AttemptStore, IdentityMapper, LoginConfig, LoginRateLimiter, LoginService,
    SessionConfig, SessionService, SessionStore,
};
use rust_web_auth_google::GoogleOidcClient;
use rust_web_auth_http::{CookiePolicy, Environment};

# fn build(
# attempts: Arc<dyn AttemptStore>,
# identities: Arc<dyn IdentityMapper>,
# limiter: Arc<dyn LoginRateLimiter>,
# session_store: Arc<dyn SessionStore>,
# client_id: String,
# client_secret: String,
# ) -> Result<(), Box<dyn std::error::Error>> {
let sessions = Arc::new(SessionService::new(
    SessionConfig::default(),
    session_store,
    load_32_byte_key("APP_SESSION_DIGEST_KEY")?,
)?);
let login = LoginService::new(
    LoginConfig::new(
        "https://cook.example/auth/google/callback",
        load_32_byte_key("OAUTH_STATE_DIGEST_KEY")?,
    )?,
    Arc::new(GoogleOidcClient::new(client_id, client_secret)?),
    attempts,
    identities,
    limiter,
    sessions,
);
let session_cookie = CookiePolicy::new(Environment::Production, "cook_session")?;
let state_cookie = CookiePolicy::new(Environment::Production, "cook_oauth_state")?;

// GET /auth/google/start:
// let start = login.begin(&rate_limit_key, now).await?;
// Set state_cookie with start.state_cookie_value and redirect to authorization_url.
//
// GET /auth/google/callback:
// Pass query state/code plus the state cookie to login.complete(...).
// Set only completion.cookie_value in session_cookie; clear state_cookie.
#
# fn load_32_byte_key(_: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
#     Ok([0; 32])
# }
# Ok(())
# }
```

On authenticated routes, call `SessionService::authenticate`, insert the
returned `AuthenticatedContext` into request extensions, and derive business
ownership only from `context.user_id`. Never accept `user_id` from untrusted
request data.

## Required persistence semantics

The library cannot make a weak database atomic. Implementations must provide:

1. `AttemptStore::create` as insert-if-absent.
2. `AttemptStore::consume_and_delete` as one transaction/CAS; exactly one
   caller receives the verifier and nonce.
3. `SessionStore::create` with token and user indexes atomically.
4. `SessionStore::replace_if_unchanged` comparing the complete expected record
   or at least an equivalent version predicate.
5. `SessionStore::revoke_all_for_user` atomically enough that the consumer's
   logout-all guarantee is documented.
6. A periodic call to `LoginService::cleanup_attempts`.

See [docs/consumer-ports-checklist.md](docs/consumer-ports-checklist.md) for
Cook/SOP adaptation work and
[docs/china-auth-integration.md](docs/china-auth-integration.md) for the
mainland-China phase 1 migration.

## Development

```console
cargo fmt --check
cargo test --all
cargo clippy --all-targets --all-features -- -D warnings
```
