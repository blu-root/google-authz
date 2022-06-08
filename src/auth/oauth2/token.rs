use std::{
    convert::TryFrom,
    fmt,
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use hyper::header::HeaderValue;

use crate::auth;

#[derive(Clone)]
pub(crate) struct Token {
    pub value: HeaderValue,
    pub expiry: Instant,
}

impl Token {
    pub fn new(value: HeaderValue, expiry: Instant) -> Self {
        Self { value, expiry }
    }

    pub fn expired(&self, at: Instant) -> bool {
        const EXPIRY_DELTA: Duration = Duration::from_secs(10);
        self.expiry
            .checked_duration_since(at)
            .map(|dur| dur < EXPIRY_DELTA)
            .unwrap_or(true)
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum Response {
    AccessToken {
        token_type: String,
        access_token: String,
        expires_in: u64,
    },
    IdToken {
        id_token: String,
    },
}

impl TryFrom<Response> for Token {
    type Error = auth::Error;

    fn try_from(response: Response) -> Result<Self, Self::Error> {
        match response {
            Response::AccessToken {
                ref token_type,
                ref access_token,
                expires_in,
            } => {
                if !token_type.is_empty() && !access_token.is_empty() && expires_in > 0 {
                    let value = format!("{} {}", token_type, access_token);
                    HeaderValue::from_str(&value)
                        .map(|hv| {
                            let expiry = Instant::now() + Duration::from_secs(expires_in);
                            Token::new(hv, expiry)
                        })
                        .map_err(|_| auth::Error::TokenFormat(response))
                } else {
                    Err(auth::Error::TokenFormat(response))
                }
            }
            Response::IdToken { ref id_token } => {
                if !id_token.is_empty() {
                    let value = format!("Bearer {}", id_token);
                    HeaderValue::from_str(&value)
                        .map(|hv| {
                            let expiry = Instant::now() + Duration::from_secs(60 * 60);
                            Token::new(hv, expiry)
                        })
                        .map_err(|_| auth::Error::TokenFormat(response))
                } else {
                    Err(auth::Error::TokenFormat(response))
                }
            }
        }
    }
}

pub(crate) type ResponseFuture = BoxFuture<'static, auth::Result<Response>>;

pub(crate) trait Fetcher: fmt::Debug + Send + Sync + 'static {
    fn fetch(&self) -> ResponseFuture;
}
