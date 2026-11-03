# Security policy and threat model

Updated: 2026-11-03

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

## Out of scope

- Password authentication, MFA, authorization/roles, desktop/native loopback
  login, cross-domain SSO, shared sessions, account recovery, and database
  encryption.
- Framework-specific middleware and a concrete database adapter.
- Google client-secret storage and cloud deployment configuration.

## Reporting

Report vulnerabilities privately to the repository owner. Do not include
tokens, credentials, personal data, or production request captures in an issue.
