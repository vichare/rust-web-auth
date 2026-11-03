use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use getrandom::fill;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn random_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 32];
    fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn parse_token(value: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

pub(crate) fn keyed_digest(key: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(value);
    mac.finalize().into_bytes().into()
}

pub(crate) fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(crate) fn secrets_equal(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}
