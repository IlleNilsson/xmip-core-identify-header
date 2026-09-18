//! The `Authorization` header, read by scheme.
//!
//! RFC 7235: a scheme, whitespace, then either a token68 or a list of
//! `name=value` parameters. The scheme is compared without regard to case.
//! What each scheme presents is the crate doc's table; this is the reading.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use identify::{IdentifyError, Presented};
use xcore::mechanism;

/// The proof name a Basic credential travels under: the base64 text after
/// `Basic `, exactly as it arrived.
pub const BASIC_CREDENTIAL: &str = "basic.credential";
/// The proof name a bearer token travels under: the whole token.
pub const BEARER_TOKEN: &str = "bearer.token";
/// The proof name a Digest response travels under: the whole parameter list.
pub const DIGEST_RESPONSE: &str = "digest.response";

/// The claim an `Authorization` value makes, by its scheme.
///
/// # Errors
///
/// Where the scheme is recognised and the credential after it cannot be read.
pub fn present(value: &str) -> Result<Option<Presented>, IdentifyError> {
    let value = value.trim();
    let (scheme, credential) = value
        .split_once(|character: char| character.is_ascii_whitespace())
        .map_or((value, ""), |(scheme, rest)| (scheme, rest.trim()));

    let claim = match scheme.to_ascii_lowercase().as_str() {
        "basic" => basic(credential)?,
        "bearer" => bearer(credential)?,
        "digest" => digest(credential)?,
        "ntlm" | "negotiate" => return Ok(None),
        _ => Presented::passed(mechanism::header(), value)
            .with_evidence("header.name", "authorization"),
    };

    Ok(Some(claim.with_evidence("authorization.scheme", scheme)))
}

/// RFC 7617: base64 of `user:password`. The user is the claim, the base64
/// text the proof.
fn basic(credential: &str) -> Result<Presented, IdentifyError> {
    let decoded = STANDARD
        .decode(credential)
        .map_err(|_| IdentifyError::new("the Basic credential is not base64"))?;
    let text = String::from_utf8(decoded)
        .map_err(|_| IdentifyError::new("the Basic credential is not UTF-8"))?;
    let Some((user, _)) = text.split_once(':') else {
        return Err(IdentifyError::new(
            "the Basic credential has no colon between user and password",
        ));
    };

    Ok(Presented::passed(mechanism::username(), user).with_proof(BASIC_CREDENTIAL, credential))
}

/// RFC 6750: an opaque token. Eight characters of it are the claim, so the
/// record can tell two tokens apart without holding either.
fn bearer(token: &str) -> Result<Presented, IdentifyError> {
    if token.is_empty() {
        return Err(IdentifyError::new("the Bearer authorization has no token"));
    }

    let short: String = token.chars().take(8).chain(std::iter::once('…')).collect();

    Ok(Presented::passed(mechanism::bearer(), short).with_proof(BEARER_TOKEN, token))
}

/// RFC 7616: a parameter list whose `username` is the claim and whose whole
/// text is the proof the digest authenticator recomputes.
fn digest(parameters: &str) -> Result<Presented, IdentifyError> {
    let username = parameter(parameters, "username")
        .ok_or_else(|| IdentifyError::new("the Digest authorization names no username"))?;

    Ok(Presented::passed(mechanism::username(), username).with_proof(DIGEST_RESPONSE, parameters))
}

/// One `name=value` from a comma-separated parameter list, unquoted.
#[must_use]
pub fn parameter<'a>(list: &'a str, name: &str) -> Option<&'a str> {
    list.split(',').find_map(|pair| {
        let (candidate, value) = pair.trim().split_once('=')?;
        candidate
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().trim_matches('"'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_response_presents_its_username_and_carries_the_whole_list() {
        let list = r#"username="Mufasa", realm="http-auth@example.org", nonce="7ypf", uri="/dir/index.html", response="8ca5"#;

        let claim = present(&format!("Digest {list}"))
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.mechanism.name(), "username");
        assert_eq!(claim.value, "Mufasa");
        assert_eq!(claim.proof(DIGEST_RESPONSE), Some(list));
        assert_eq!(
            claim.evidence,
            vec![("authorization.scheme".to_string(), "Digest".to_string())]
        );
    }

    #[test]
    fn a_digest_without_a_username_and_a_bearer_without_a_token_are_errors() {
        assert_eq!(
            present("Digest realm=\"x\"")
                .expect_err("no username")
                .to_string(),
            "the Digest authorization names no username"
        );
        assert_eq!(
            present("Bearer").expect_err("no token").to_string(),
            "the Bearer authorization has no token"
        );
    }

    #[test]
    fn an_unknown_scheme_is_a_header_like_any_other() {
        let claim = present("Hawk id=\"dh37fgj492je\"")
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.mechanism.name(), "header");
        assert_eq!(claim.value, "Hawk id=\"dh37fgj492je\"");
    }
}
