# Cook and SOP-Node consumer checklist

Updated: 2026-11-03

## Required for both consumers

- [ ] Pin the same reviewed `rust-web-auth` Git commit in `Cargo.toml` and lock
  it in `Cargo.lock`.
- [ ] Implement `AttemptStore` with insert-if-absent, atomic
  consume-and-delete, expiry checks, and cleanup.
- [ ] Implement `IdentityMapper` keyed only by `(issuer, subject)`. Store
  verified email as mutable profile data.
- [ ] Implement `SessionStore` with keyed-digest lookup, stable ID lookup, CAS
  replacement, per-user index, and all-device revocation.
- [ ] Implement `LoginRateLimiter` before exposing the login-start route.
- [ ] Generate independent 32-byte state/session digest keys for each
  application and environment.
- [ ] Configure an exact HTTPS callback; register that exact URI in Google.
- [ ] Use independent `__Host-` production cookie names and databases.
- [ ] Schedule attempt cleanup.
- [ ] Log route templates or paths only; redact query, cookies, authorization,
  session/token/code/state/nonce/verifier fields.
- [ ] Put `AuthenticatedContext` into request extensions and remove business
  endpoints that accept an ownership `user_id`.
- [ ] Exercise current-device and all-device logout.
- [ ] Add end-to-end tests proving frontend JavaScript never receives Google
  code, access token, or ID token.

## Cook

- **Fact:** Cook is a planned consumer through a pinned Git revision.
- **Unverified:** User ID type, persistence transaction primitives, HTTP
  framework, production origin, callback path, and existing session schema.
- [ ] Decide and document those values in Cook's authoritative repository.
- [ ] Confirm first-login user creation and identity mapping are one atomic
  consumer operation.
- [ ] Name cookies distinctly, for example `__Host-cook_session` and
  `__Host-cook_oauth_state`.

## SOP-Node

- **Fact:** SOP-Node has an existing Google OIDC/session implementation and is
  planned to migrate to this library.
- **Fact:** This library has no SOP protobuf, domain, or
  `vichare_data_store` dependency.
- **Unverified:** Whether existing session/attempt records require a
  compatibility reader during rollout.
- [ ] Adapt current repositories to these ports without moving SOP record types
  into this workspace.
- [ ] Preserve SOP account lifecycle checks around `IdentityMapper` and session
  issuance/authentication.
- [ ] Keep SOP's own `__Host-` cookie names, keys, and database; never reuse
  Cook values.
- [ ] Compare existing rotating-key, callback, cookie, request-logging, logout,
  and concurrency tests before removing duplicate code.
