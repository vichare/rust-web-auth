//! Security invariant tests for email OTP.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, TimeZone as _, Utc};
use rust_web_auth_email_otp::{
    EmailAddress, EmailDeliveryError, EmailOtpAttempt, EmailOtpAttemptStore, EmailOtpConfig,
    EmailOtpCreateOutcome, EmailOtpError, EmailOtpMessage, EmailOtpPurpose,
    EmailOtpRateLimitDecision, EmailOtpRateLimiter, EmailOtpRequest,
    EmailOtpRequestRateLimitContext, EmailOtpService, EmailOtpStorageError, EmailOtpVerification,
    EmailOtpVerifyOutcome, EmailOtpVerifyRateLimitContext, EmailSender,
};

#[derive(Default)]
struct MemoryAttempts {
    values: Mutex<HashMap<[u8; 32], EmailOtpAttempt>>,
}

#[async_trait]
impl EmailOtpAttemptStore for MemoryAttempts {
    async fn create_or_replace(
        &self,
        attempt: EmailOtpAttempt,
        now: chrono::DateTime<Utc>,
    ) -> Result<EmailOtpCreateOutcome, EmailOtpStorageError> {
        let mut values = self.values.lock().unwrap();
        if values.values().any(|existing| {
            existing.email_digest == attempt.email_digest
                && existing.purpose == attempt.purpose
                && existing.resend_allowed_at > now
                && existing.expires_at > now
        }) {
            return Ok(EmailOtpCreateOutcome::Cooldown);
        }
        values.retain(|_, existing| {
            existing.email_digest != attempt.email_digest || existing.purpose != attempt.purpose
        });
        values.insert(attempt.challenge_digest, attempt);
        Ok(EmailOtpCreateOutcome::Created)
    }

    async fn verify_and_consume(
        &self,
        challenge_digest: &[u8; 32],
        code_digest: &[u8; 32],
        now: chrono::DateTime<Utc>,
    ) -> Result<EmailOtpVerifyOutcome, EmailOtpStorageError> {
        let mut values = self.values.lock().unwrap();
        let Some(attempt) = values.get_mut(challenge_digest) else {
            return Ok(EmailOtpVerifyOutcome::Invalid);
        };
        if attempt.expires_at <= now || attempt.attempts_remaining == 0 {
            values.remove(challenge_digest);
            return Ok(EmailOtpVerifyOutcome::Invalid);
        }
        if attempt.code_digest == *code_digest {
            return Ok(EmailOtpVerifyOutcome::Verified(Box::new(
                values.remove(challenge_digest).unwrap(),
            )));
        }
        attempt.attempts_remaining -= 1;
        if attempt.attempts_remaining == 0 {
            values.remove(challenge_digest);
            return Ok(EmailOtpVerifyOutcome::Invalid);
        }
        Ok(EmailOtpVerifyOutcome::Rejected)
    }

    async fn invalidate(&self, challenge_digest: &[u8; 32]) -> Result<(), EmailOtpStorageError> {
        self.values.lock().unwrap().remove(challenge_digest);
        Ok(())
    }

    async fn cleanup(&self, now: chrono::DateTime<Utc>) -> Result<usize, EmailOtpStorageError> {
        let mut values = self.values.lock().unwrap();
        let before = values.len();
        values.retain(|_, attempt| attempt.expires_at > now);
        Ok(before - values.len())
    }
}

#[derive(Clone)]
struct SentOtp {
    email: EmailAddress,
    code: String,
}

#[derive(Default)]
struct CapturingSender {
    messages: Mutex<Vec<SentOtp>>,
}

#[async_trait]
impl EmailSender for CapturingSender {
    async fn send_email_otp(
        &self,
        recipient: &EmailAddress,
        message: EmailOtpMessage<'_>,
    ) -> Result<(), EmailDeliveryError> {
        self.messages.lock().unwrap().push(SentOtp {
            email: recipient.clone(),
            code: message.code.expose_for_delivery().to_owned(),
        });
        Ok(())
    }
}

struct AllowLimiter;

#[async_trait]
impl EmailOtpRateLimiter for AllowLimiter {
    async fn check_request(
        &self,
        _: &EmailOtpRequestRateLimitContext,
        _: chrono::DateTime<Utc>,
    ) -> Result<EmailOtpRateLimitDecision, EmailOtpStorageError> {
        Ok(EmailOtpRateLimitDecision::Allowed)
    }

    async fn check_verify(
        &self,
        _: &EmailOtpVerifyRateLimitContext,
        _: chrono::DateTime<Utc>,
    ) -> Result<EmailOtpRateLimitDecision, EmailOtpStorageError> {
        Ok(EmailOtpRateLimitDecision::Allowed)
    }
}

fn service() -> (Arc<MemoryAttempts>, Arc<CapturingSender>, EmailOtpService) {
    let attempts = Arc::new(MemoryAttempts::default());
    let sender = Arc::new(CapturingSender::default());
    let config = EmailOtpConfig::new(
        [7; 32],
        ["/recipes".to_owned(), "/settings/security".to_owned()],
    )
    .unwrap();
    let service = EmailOtpService::new(
        config,
        attempts.clone(),
        sender.clone(),
        Arc::new(AllowLimiter),
    );
    (attempts, sender, service)
}

fn request(email: &str) -> EmailOtpRequest {
    EmailOtpRequest {
        email: EmailAddress::new(email).unwrap(),
        purpose: EmailOtpPurpose::new("sign-in").unwrap(),
        continue_path: "/recipes".to_owned(),
        ip_partition: "network-digest".to_owned(),
    }
}

fn verify<'a>(challenge_id: &'a str, code: &'a str) -> EmailOtpVerification<'a> {
    EmailOtpVerification {
        challenge_id,
        code,
        ip_partition: "network-digest",
    }
}

#[tokio::test]
async fn code_is_six_digits_digest_only_and_single_use() {
    let (attempts, sender, service) = service();
    let now = Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap();
    let challenge = service
        .request(request("person@example.cn"), now)
        .await
        .unwrap();
    let (email, code) = {
        let messages = sender.messages.lock().unwrap();
        (messages[0].email.clone(), messages[0].code.clone())
    };
    assert_eq!(email.as_str(), "person@example.cn");
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
    assert!(!format!("{challenge:?}").contains(challenge.challenge_id.expose_for_client()));

    {
        let stored = attempts.values.lock().unwrap();
        let attempt = stored.values().next().unwrap();
        assert!(!format!("{attempt:?}").contains(&code));
        assert_ne!(attempt.code_digest.as_slice(), code.as_bytes());
    }

    let identity = service
        .verify(
            verify(challenge.challenge_id.expose_for_client(), &code),
            now + Duration::seconds(1),
        )
        .await
        .unwrap();
    assert_eq!(identity.email.as_str(), "person@example.cn");
    assert_eq!(
        service
            .verify(
                verify(challenge.challenge_id.expose_for_client(), &code),
                now + Duration::seconds(2)
            )
            .await,
        Err(EmailOtpError::VerificationFailed)
    );
}

#[tokio::test]
async fn wrong_code_exhausts_five_attempts_and_invalidates() {
    let (_, sender, service) = service();
    let now = Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap();
    let challenge = service
        .request(request("person@example.cn"), now)
        .await
        .unwrap();
    let real_code = sender.messages.lock().unwrap()[0].code.clone();
    let wrong = if real_code == "000000" {
        "000001"
    } else {
        "000000"
    };
    for _ in 0..5 {
        assert_eq!(
            service
                .verify(
                    verify(challenge.challenge_id.expose_for_client(), wrong),
                    now
                )
                .await,
            Err(EmailOtpError::VerificationFailed)
        );
    }
    assert_eq!(
        service
            .verify(
                verify(challenge.challenge_id.expose_for_client(), &real_code),
                now
            )
            .await,
        Err(EmailOtpError::VerificationFailed)
    );
}

#[tokio::test]
async fn resend_cooldown_and_single_active_challenge_are_atomic() {
    let (_, sender, service) = service();
    let now = Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap();
    let first = service
        .request(request("person@example.cn"), now)
        .await
        .unwrap();
    assert_eq!(
        service
            .request(request("PERSON@example.cn"), now + Duration::seconds(30))
            .await
            .unwrap_err(),
        EmailOtpError::RateLimited
    );
    let second = service
        .request(request("person@example.cn"), now + Duration::minutes(1))
        .await
        .unwrap();
    let codes = sender
        .messages
        .lock()
        .unwrap()
        .iter()
        .map(|message| message.code.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        service
            .verify(
                verify(first.challenge_id.expose_for_client(), &codes[0]),
                now + Duration::minutes(1)
            )
            .await,
        Err(EmailOtpError::VerificationFailed)
    );
    assert!(
        service
            .verify(
                verify(second.challenge_id.expose_for_client(), &codes[1]),
                now + Duration::minutes(1)
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn expiry_wrong_digest_and_concurrent_replay_share_safe_failures() {
    let (_, sender, service) = service();
    let service = Arc::new(service);
    let now = Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap();
    let challenge = service
        .request(request("person@example.cn"), now)
        .await
        .unwrap();
    let code = sender.messages.lock().unwrap()[0].code.clone();
    assert_eq!(
        service
            .verify(
                verify(challenge.challenge_id.expose_for_client(), &code),
                now + Duration::minutes(10)
            )
            .await,
        Err(EmailOtpError::VerificationFailed)
    );

    let challenge = service
        .request(request("person@example.cn"), now + Duration::minutes(11))
        .await
        .unwrap();
    let code = sender.messages.lock().unwrap()[1].code.clone();
    let first = {
        let service = service.clone();
        let challenge_id = challenge.challenge_id.expose_for_client().to_owned();
        let code = code.clone();
        tokio::spawn(async move {
            service
                .verify(verify(&challenge_id, &code), now + Duration::minutes(11))
                .await
        })
    };
    let second = {
        let service = service.clone();
        let challenge_id = challenge.challenge_id.expose_for_client().to_owned();
        let code = code.clone();
        tokio::spawn(async move {
            service
                .verify(verify(&challenge_id, &code), now + Duration::minutes(11))
                .await
        })
    };
    let results = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
}

#[tokio::test]
async fn request_surface_has_no_account_existence_lookup() {
    let (_, _, service) = service();
    let now = Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap();
    let known = service
        .request(request("known@example.cn"), now)
        .await
        .unwrap();
    let unknown = service
        .request(request("unknown@example.cn"), now)
        .await
        .unwrap();
    assert_eq!(known.expires_at, unknown.expires_at);
    assert_eq!(known.resend_allowed_at, unknown.resend_allowed_at);
}

#[test]
fn configuration_and_debug_fail_closed() {
    assert!(EmailOtpConfig::new([0; 32], ["/recipes".to_owned()]).is_err());
    assert!(EmailOtpConfig::new([1; 32], ["//evil.example".to_owned()]).is_err());
    let verification = EmailOtpVerification {
        challenge_id: "challenge-secret",
        code: "123456",
        ip_partition: "network",
    };
    let debug = format!("{verification:?}");
    assert!(!debug.contains("123456"));
    assert!(!debug.contains("challenge-secret"));
}
