#![forbid(unsafe_code)]

//! Identify by header: one named transport header is the claim.
//!
//! The transport puts each request header on the arrival as
//! `http.header.<name>`, the name lowercased, and the identifier is built
//! naming one of them. For most headers the value is the claim as written —
//! an `X-Partner-Id`, an `X-Client-Name` — under
//! [`xcore::mechanism::header`], passed and nothing behind it.
//!
//! `Authorization` is the exception, and the identifier is scheme-aware for
//! it because the header is not a name but a credential whose scheme says
//! which mechanism is being used:
//!
//! ```text
//! Basic <base64>        mechanism username, value the user, proof basic.credential
//! Bearer <token>        mechanism bearer, value a short opaque form, proof bearer.token
//! Digest <parameters>   mechanism username, value the username= parameter, proof digest.response
//! NTLM, Negotiate       nothing: the ntlm and kerberos technologies read those
//! anything else         mechanism header, the raw value
//! ```
//!
//! The proof rides on [`Presented::proof`] and never on the record; the
//! authenticator of the same mechanism reads it there. The value is what may
//! be recorded — a user name, or eight characters of a token — so a
//! credential never reaches the identity.
//!
//! Only a pushed Stream carries headers; a detected or scheduled arrival
//! presents nothing here.
//!
//! Property names this technology reads: `http.header.<name>`. Evidence it
//! writes: `header.name`, and `authorization.scheme` for `Authorization`.
//! Proof names it writes: `basic.credential`, `bearer.token`,
//! `digest.response`.

pub mod authorization;

use context::property::HTTP_HEADER_PREFIX;
use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
use xcore::{Arriving, Mechanism};

/// Reads one named header.
#[derive(Clone, Debug)]
pub struct HeaderIdentifier {
    name: String,
    property: String,
}

impl HeaderIdentifier {
    /// Read this header. The name is matched without regard to case, as
    /// HTTP compares it.
    #[must_use]
    pub fn named(name: &str) -> Self {
        let name = name.trim().to_ascii_lowercase();
        Self {
            property: format!("{HTTP_HEADER_PREFIX}{name}"),
            name,
        }
    }

    /// The header this reads, lowercased.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl TransportIdentifier for HeaderIdentifier {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::header()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let Some(value) = arrival.property(&self.property) else {
            return Ok(None);
        };

        if self.name == "authorization" {
            return authorization::present(value);
        }

        Ok(Some(
            Presented::passed(self.mechanism(), value.trim())
                .with_evidence("header.name", &self.name),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stream::Stream;
    use xcore::StreamId;

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn facts(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn a_named_header_is_the_claim_as_written() {
        let stream = stream();
        let facts = facts(&[("http.header.x-partner-id", "partner-x")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = HeaderIdentifier::named("X-Partner-Id")
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.mechanism.name(), "header");
        assert_eq!(claim.value, "partner-x");
        assert_eq!(
            claim.evidence,
            vec![("header.name".to_string(), "x-partner-id".to_string())]
        );
    }

    #[test]
    fn a_basic_authorization_presents_the_user_and_keeps_the_credential_as_proof() {
        let stream = stream();
        let facts = facts(&[(
            "http.header.authorization",
            "Basic cGFydG5lci14OnMzY3IzdA==",
        )]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = HeaderIdentifier::named("Authorization")
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.mechanism.name(), "username");
        assert_eq!(claim.value, "partner-x");
        assert_eq!(
            claim.proof("basic.credential"),
            Some("cGFydG5lci14OnMzY3IzdA==")
        );
        assert!(
            !format!("{claim:?}").contains("cGFydG5lci14"),
            "the credential is not printed"
        );
    }

    #[test]
    fn a_bearer_token_is_presented_short_and_carried_whole_as_proof() {
        let stream = stream();
        let facts = facts(&[("http.header.authorization", "Bearer mF_9.B5f-4.1JqM")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = HeaderIdentifier::named("authorization")
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.mechanism.name(), "bearer");
        assert_eq!(claim.value, "mF_9.B5f…");
        assert_eq!(claim.proof("bearer.token"), Some("mF_9.B5f-4.1JqM"));
    }

    #[test]
    fn a_negotiate_or_ntlm_authorization_is_somebody_elses_to_read() {
        let stream = stream();
        for value in ["Negotiate YIIB...", "NTLM TlRMTVNTUAAD..."] {
            let facts = facts(&[("http.header.authorization", value)]);
            let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

            assert!(
                HeaderIdentifier::named("Authorization")
                    .identify(&arrival)
                    .expect("read")
                    .is_none()
            );
        }
    }

    #[test]
    fn an_arrival_without_the_header_presents_nothing() {
        let stream = stream();
        let facts = facts(&[("http.header.x-other", "value")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        assert!(
            HeaderIdentifier::named("X-Partner-Id")
                .identify(&arrival)
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_basic_credential_that_does_not_decode_is_an_error() {
        let stream = stream();
        let facts = facts(&[("http.header.authorization", "Basic not*base64")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let failure = HeaderIdentifier::named("Authorization")
            .identify(&arrival)
            .expect_err("not base64");

        assert_eq!(failure.to_string(), "the Basic credential is not base64");
    }

    #[test]
    fn a_scheduled_pickup_carries_no_request_headers() {
        let stream = stream();
        let facts = facts(&[("http.header.x-partner-id", "partner-x")]);
        let arrival =
            StreamArrival::new(&stream, Arriving::Scheduled, "https://partner/out", &facts);

        assert!(
            HeaderIdentifier::named("X-Partner-Id")
                .identify(&arrival)
                .expect("read")
                .is_none()
        );
    }
}
