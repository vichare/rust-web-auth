#![forbid(unsafe_code)]
//! Storage- and framework-independent web authentication services.
//!
//! Consumers implement the exported ports such as [`AttemptStore`],
//! [`IdentityMapper`], and [`SessionStore`]. The crate never owns a user
//! database and never treats an email address as an identity key.

mod model;
mod ports;
mod secrets;
mod service;

pub use model::{
    AuthenticatedContext, IdentityKey, LoginAttempt, SessionId, SessionRecord, UserId,
    VerifiedIdentity,
};
pub use ports::{
    AttemptStore, CasOutcome, IdentityMapper, LoginRateLimiter, OidcProvider, ProviderError,
    RateLimitDecision, SessionStore, StorageError,
};
pub use service::{
    LoginCallback, LoginCompletion, LoginConfig, LoginError, LoginService, LoginStart,
    SessionConfig, SessionError, SessionService,
};
