# Mainland China authentication integration

Updated: 2026-11-04

Google OIDC remains available, but `accounts.google.com` is not a dependable
primary authentication path from mainland China. Phase 1 consumers should add
email OTP and passkeys while retaining Google as an optional provider.

The shared crates never merge accounts. Cook and SOP-Node must implement an
explicit account-linking screen while already authenticated. A matching email
address from Google or an email OTP is not authority to merge two user records.

## Dependency selection

Pin one reviewed revision and include only the mechanisms the application uses:

```toml
[dependencies]
rust-web-auth-core = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }
rust-web-auth-http = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }
rust-web-auth-email-otp = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }
rust-web-auth-passkey = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }

# Optional where Google is offered:
rust-web-auth-google = { git = "https://github.com/vichare/rust-web-auth", rev = "<REVIEWED_COMMIT_SHA>" }
```

Independent crates prevent Google-only consumers from compiling email or
WebAuthn dependencies. Existing crates retain Rust 1.85 compatibility;
`rust-web-auth-passkey` alone requires Rust 1.89 because maintained
[`webauthn-rs 0.6.2`](https://crates.io/crates/webauthn-rs/0.6.2) requires it.
The dependency is
[MPL-2.0 licensed](https://github.com/kanidm/webauthn-rs) and the upstream
repository was active when checked on 2026-11-04.

## Email OTP flow

Email OTP was selected instead of magic links because users can copy a code
across devices and automated mail-security link scanners cannot consume it.

Implement:

- `EmailOtpAttemptStore` with atomic single-active replacement, resend
  cooldown, attempt decrement, success/exhaustion/expiry invalidation, and
  cleanup;
- `EmailSender` using the application's mail provider;
- `EmailOtpRateLimiter` with normalized-email + IP request limits and
  challenge + IP verification limits.

The service generates an unbiased CSPRNG six-digit code and an independent
256-bit opaque challenge ID. Six digits balance mobile entry and delivery UX;
the ten-minute lifetime, layered rate limits, resend cooldown, and five-attempt
maximum compensate for the one-million-value code space. The database receives
only server-secret HMAC digests, including a code digest bound to its challenge.

One active challenge exists per normalized email and purpose. A permitted
resend atomically invalidates the previous challenge. Successful verification
returns `VerifiedEmailIdentity`; it does not create, find, merge, or bind a
user.

Request handlers should return the same accepted status/body regardless of
whether an application account exists. The shared service intentionally has no
account lookup during request delivery. Do not log email addresses, codes,
challenge IDs, mail template data, or verification request bodies.

The browser sends the opaque challenge ID and user-entered code to the verify
endpoint. Purpose, email, and continuation remain authenticated server-side
attempt data and must not be trusted from the verification request.

Composition sketch:

```rust,no_run
use std::sync::Arc;
use rust_web_auth_email_otp::{
    EmailOtpAttemptStore, EmailOtpConfig, EmailOtpRateLimiter, EmailOtpService,
    EmailSender,
};

# fn build(
# attempts: Arc<dyn EmailOtpAttemptStore>,
# sender: Arc<dyn EmailSender>,
# limiter: Arc<dyn EmailOtpRateLimiter>,
# ) -> Result<EmailOtpService, Box<dyn std::error::Error>> {
let config = EmailOtpConfig::new(
    load_32_byte_key("EMAIL_OTP_DIGEST_KEY")?,
    ["/recipes".to_owned(), "/settings/security".to_owned()],
)?;
Ok(EmailOtpService::new(config, attempts, sender, limiter))
# }
# fn load_32_byte_key(_: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
#     unimplemented!()
# }
```

## Passkey flow

`rust-web-auth-passkey` wraps `webauthn-rs 0.6.2` ceremony types rather than
reproducing WebAuthn validation. The dependency is MPL-2.0 licensed and actively
maintained. Consumers persist credentials and stable opaque user handles, while
short-lived registration/authentication challenge state is stored through an
atomic consume-and-delete port.

The `webauthn-rs` ceremony state types are intentionally non-serializable unless
a dangerous feature is enabled. This crate does not enable it. Consumers must
use a server-side store capable of retaining the opaque typed state and place
only the crate's random ceremony token in an `HttpOnly`, `Secure`, `SameSite`
cookie.

Registration must begin from an authenticated context. Authentication returns
the consumer `UserId` recorded in the consumed ceremony. It never uses an email
address to select or merge an account.

Consumers should:

- configure one exact HTTPS origin and its matching RP ID;
- use a stable random opaque WebAuthn UUID user handle, not an email address;
- permit multiple credentials per user and present credential management;
- persist signature-counter/backup-state updates after authentication;
- enforce credential-ID uniqueness across every application user;
- support credential revocation without deleting the application user;
- map unknown users, missing credentials, replay, and invalid assertions to
  the same public error surface.

Phase 1 uses username-first, non-discoverable credentials for predictable
account selection and broad authenticator support. Discoverable credentials
improve identifier privacy and passwordless UX but require a deliberate
user-handle lookup and recovery design; they are not silently enabled. User
verification is required. Registration attestation is not used as an identity
source.

Composition sketch:

```rust,no_run
use std::sync::Arc;
use rust_web_auth_passkey::{
    CeremonyStore, PasskeyConfig, PasskeyCredentialStore, PasskeyService,
};

# fn build(
# ceremonies: Arc<dyn CeremonyStore>,
# credentials: Arc<dyn PasskeyCredentialStore>,
# ) -> Result<PasskeyService, Box<dyn std::error::Error>> {
let config = PasskeyConfig::new(
    "cook.example",
    "https://cook.example",
    "Cook",
    load_32_byte_key("PASSKEY_CEREMONY_DIGEST_KEY")?,
)?;
Ok(PasskeyService::new(config, ceremonies, credentials)?)
# }
# fn load_32_byte_key(_: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
#     unimplemented!()
# }
```

## Consumer migration

1. Keep the existing Google integration unchanged.
2. Add independent storage for email OTP attempts, passkey ceremony state,
   WebAuthn user handles, and credentials.
3. Add OTP request/verify endpoints with uniform request responses.
4. Add authenticated passkey registration and credential-revocation routes.
5. Add passkey login routes and insert the returned `UserId` into the existing
   `SessionService`.
6. Add an authenticated explicit-linking workflow. Never link because email
   strings happen to match.
7. Test from a mainland-China network and with real platform/cross-platform
   authenticators before making Google optional.

Real browser authenticator UI, platform policy, mail delivery/reputation, and
mainland network reachability cannot be proven by this repository's headless
unit tests; they require consumer staging validation.
