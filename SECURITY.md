# Security policy and threat model

Updated: 2026-11-04

## Boundary

`rust-web-auth` supplies authentication protocol and session lifecycle logic.
Each consuming application remains a separate security principal and owns its
users, identity mappings, database, encryption/HMAC keys, cookies, routes,
rate limits, telemetry, deployment, and incident response. SOP-Node and Cook
must never share a cookie, cookie name, signing/digest key, session table, or
database.

## Protected assets

- Google authorization code, PKCE verifier, nonce, state, access token, and ID
  token.
- Raw application-session tokens and digest keys.
- Raw email OTP codes/challenge IDs and passkey challenge state.
- Passkey credential public keys, signature counters, backup state, and opaque
  user handles.
- Stable `(issuer, subject) -> user_id` mappings.
- Consumer user/session records and authenticated request context.

## Threats and controls

| Threat | Control |
|---|---|
| Login CSRF / callback injection | 256-bit state, state cookie comparison, keyed state digest, one-time atomic consume |
| Authorization-code interception | S256 PKCE and exact stored redirect URI |
| ID-token replay/substitution | nonce, issuer, audience, expiry, signature, and optional access-token hash verification |
| Email reassignment/account takeover | email is never an identity key; Google `email_verified=true` is mandatory |
| Attempt replay/race | 10-minute default, atomic consume-and-delete port, cleanup |
| Signing-key rotation | lazy discovery/JWKS, one-hour refresh, rate-limited single-flight refresh on signature failure, same-token reverification only |
| Session database disclosure | random 256-bit bearer token; only keyed HMAC digest persisted |
| Cookie injection/leakage | production `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` |
| Sliding-session write race | 24-hour throttle and compare-and-swap renewal |
| Cross-device persistence after logout | current-device and all-device revocation |
| User impersonation through request fields | business `user_id` comes only from `AuthenticatedContext` |
| Credential leakage in logs | query discarded; credential-bearing headers marked sensitive; secret-bearing structs redact debug output |
| Login-start abuse | mandatory consumer `LoginRateLimiter` port before secret generation |
| Open redirect | callback URI is configured, exact, and strictly validated; applications must separately allowlist post-login redirects |
| OTP database disclosure/offline guessing | code digest is server-secret HMAC bound to a random 256-bit challenge; plaintext code is never persisted |
| OTP online guessing | unbiased six-digit code, ten-minute expiry, layered email/IP/challenge rate limits, and five-attempt maximum |
| OTP replay/race | verification atomically consumes success and invalidates expiry/exhaustion; resend atomically replaces the previous challenge |
| Account enumeration | no account lookup during OTP delivery; consumers return one accepted response and one generic verification failure |
| Unsafe account linking | OTP completion returns verified email only; passkey completion returns the ceremony's consumer user; matching email never merges users |
| WebAuthn phishing/origin confusion | fail-closed RP ID/origin configuration and `webauthn-rs` challenge/origin/RP validation |
| WebAuthn challenge replay | short-lived atomic consume-and-delete ceremony state |
| Passkey cloning/counter regression | consumer persistence port must apply successful authentication counter/backup-state updates and surface suspicious regressions |
| Cross-user credential use | ceremony records bind one consumer user and credential updates require the same owner |
| Credential ID registered to two users | registration storage atomically enforces global credential-ID uniqueness |
| Passkey removal | consumer-owned credential IDs support per-credential revocation without deleting the user |

## Provider failure classification

Provider errors deliberately expose only:

- `ProviderUnavailable`: discovery, JWKS, transport, or token endpoint
  availability failure.
- `TokenRejected`: authorization code rejection or invalid ID token.
- `IdentityIncomplete`: verified token lacks a verified email.

Detailed provider payloads, codes, tokens, and claims must not be sent to
clients or routine logs.

## Consumer obligations

- Use independent high-entropy 32-byte state/session digest keys per
  application and environment; load them from secret management.
- Implement the persistence port atomicity documented in Rustdoc and README.
- Terminate TLS correctly and reject production startup if the externally
  visible callback is not HTTPS.
- Never log request query strings, cookies, authorization headers, callback
  bodies, provider responses, or raw library results containing cookie values.
- Apply CSRF protection to state-changing authenticated application routes;
  `SameSite=Lax` is defense in depth, not a complete CSRF system.
- Rotate digest keys with an explicit migration or global-session revocation
  plan. The library does not retain previous keys.
- Pin a reviewed Git revision and run this workspace's tests in consumer CI.
- Keep email delivery, account lookup, and account linking separate. A verified
  mailbox proves mailbox possession, not that two existing users are the same.
- Never log OTP email addresses, codes, challenge IDs, verification bodies, or
  mail template data in CDN, proxy, application, analytics, or error systems.
- Use one exact HTTPS WebAuthn origin and matching RP ID. Test proxy-derived
  origins rather than trusting arbitrary forwarding headers.
- Store opaque random WebAuthn user handles, not email addresses. Require user
  verification and support more than one credential per user.
- Treat credential private keys as authenticator-owned. The server stores only
  public credential material and must never request or log private keys.

## Out of scope

- Password authentication, MFA policy composition, authorization/roles,
  desktop/native loopback login, cross-domain SSO, shared sessions, account
  recovery, and database encryption.
- Framework-specific middleware and a concrete database adapter.
- Google client-secret storage and cloud deployment configuration.

## Reporting

Report vulnerabilities privately to the repository owner. Do not include
tokens, credentials, personal data, or production request captures in an issue.
