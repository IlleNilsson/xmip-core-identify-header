//! The `Authorization` header, presented by scheme.
//!
//! What each scheme presents is the crate doc's table. The reading — the
//! scheme, Basic's two halves, a Digest list, a bearer token's short form —
//! is the capability's (`identify::authorization`), so this gate and the
//! second read one header alike.

use identify::authorization::{self, bearer_short, parameter};
use identify::evidence;
use identify::{IdentifyError, Presented};
use xcore::mechanism;

/// The claim an `Authorization` value makes, by its scheme.
///
/// # Errors
///
/// Where the scheme is recognised and the credential after it cannot be read.
pub fn present(value: &str) -> Result<Option<Presented>, IdentifyError> {
    let (scheme, credential) = authorization::scheme(value);

    let claim = match scheme.to_ascii_lowercase().as_str() {
        "basic" => {
            let (user, _) = authorization::basic(credential)?;
            Presented::passed(mechanism::username(), user)
                .with_proof(evidence::BASIC_CREDENTIAL, credential)
        }
        "bearer" => bearer(credential)?,
        "digest" => digest(credential)?,
        "ntlm" | "negotiate" => return Ok(None),
        _ => Presented::passed(mechanism::header(), value.trim())
            .with_evidence("header.name", "authorization"),
    };

    Ok(Some(claim.with_evidence("authorization.scheme", scheme)))
}

/// RFC 6750: an opaque token, claimed by its short form.
fn bearer(token: &str) -> Result<Presented, IdentifyError> {
    if token.is_empty() {
        return Err(IdentifyError::new("the Bearer authorization has no token"));
    }

    Ok(Presented::passed(mechanism::bearer(), bearer_short(token))
        .with_proof(evidence::BEARER_TOKEN, token))
}

/// RFC 7616: a parameter list whose `username` is the claim and whose whole
/// text is the proof the digest authenticator recomputes.
fn digest(parameters: &str) -> Result<Presented, IdentifyError> {
    let username = parameter(parameters, "username")
        .ok_or_else(|| IdentifyError::new("the Digest authorization names no username"))?;

    Ok(Presented::passed(mechanism::username(), username)
        .with_proof(evidence::DIGEST_RESPONSE, parameters))
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
        assert_eq!(claim.proof(evidence::DIGEST_RESPONSE), Some(list));
        assert_eq!(
            claim.evidence,
            vec![("authorization.scheme".to_string(), "Digest".to_string())]
        );
    }

    #[test]
    fn a_quoted_comma_in_a_digest_list_does_not_change_the_username() {
        let list = r#"uri="/a,username=eve", username="Mufasa", response="8ca5""#;

        let claim = present(&format!("Digest {list}"))
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "Mufasa");
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
