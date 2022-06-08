use std::{fmt, time::SystemTime};

use hyper::Uri;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use tracing::trace;

use crate::{
    auth::oauth2::{http::Client, token},
    credentials,
};

// If client machine's time is in the future according
// to Google servers, an access token will not be issued.
fn issued_at() -> u64 {
    SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 10
}

// https://cloud.google.com/iot/docs/concepts/device-security#security_standards
fn header(typ: impl Into<String>, key_id: impl Into<String>) -> Header {
    Header {
        typ: Some(typ.into()),
        alg: Algorithm::RS256,
        kid: Some(key_id.into()),
        ..Default::default()
    }
}

#[derive(serde::Serialize)]
struct Claims<'a> {
    iss: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    aud: &'a str,
    iat: u64,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_audience: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct Payload<'a> {
    grant_type: &'a str,
    assertion: &'a str,
}

// https://cloud.google.com/docs/authentication/production
pub struct ServiceAccount {
    inner: Client,
    header: Header,
    private_key: EncodingKey,
    token_uri: Uri,
    token_uri_str: String,
    scopes: String,
    client_email: String,
    audience: Option<String>,
}

impl ServiceAccount {
    pub(crate) fn new(sa: credentials::ServiceAccount) -> Self {
        Self {
            inner: Client::new(),
            header: header("JWT", sa.private_key_id),
            private_key: EncodingKey::from_rsa_pem(sa.private_key.as_bytes()).unwrap(),
            token_uri: Uri::from_maybe_shared(sa.token_uri.clone()).unwrap(),
            token_uri_str: sa.token_uri,
            scopes: sa.scopes.join(" "),
            client_email: sa.client_email,
            audience: sa.audience.map(Into::into),
        }
    }
}

impl fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccount").finish()
    }
}

impl token::Fetcher for ServiceAccount {
    fn fetch(&self) -> token::ResponseFuture {
        const EXPIRE: u64 = 60 * 60;

        let iat = issued_at();
        let claims = Claims {
            iss: &self.client_email,
            scope: if self.audience.is_some() {
                None
            } else {
                Some(&self.scopes)
            },
            aud: &self.token_uri_str,
            iat,
            exp: iat + EXPIRE,
            target_audience: self.audience.as_deref(),
            sub: if self.audience.is_some() {
                Some(&self.client_email)
            } else {
                None
            },
        };

        let assertion = encode(&self.header, &claims, &self.private_key).unwrap();
        trace!(%assertion);

        let req = self.inner.request(
            &self.token_uri,
            &Payload {
                grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
                assertion: &assertion,
            },
        );
        Box::pin(self.inner.send(req))
    }
}
