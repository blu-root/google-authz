use std::path::Path;

use hyper::client::HttpConnector;

mod error;
mod impls;

pub use error::*;

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub enum Credentials {
    None,
    ApiKey(String),
    User(User),
    ServiceAccount(ServiceAccount),
    Metadata(Box<Metadata>),
}

impl Credentials {
    pub async fn new() -> Self {
        Self::builder().build().await.expect("Credentials::new()")
    }

    pub fn builder<'a>() -> Builder<'a> {
        Builder::default()
    }
}

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug, serde::Deserialize)]
pub struct User {
    #[serde(skip)]
    pub(crate) scopes: &'static [&'static str],
    // json fields
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) refresh_token: String,
}

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug, serde::Deserialize)]
pub struct ServiceAccount {
    #[serde(skip)]
    pub(crate) scopes: &'static [&'static str],
    #[serde(skip)]
    pub(crate) audience: Option<&'static str>,
    // json fields
    pub(crate) client_email: String,
    pub(crate) private_key_id: String,
    pub(crate) private_key: String,
    pub(crate) token_uri: String,
}

#[derive(Debug)]
pub struct Metadata {
    pub(crate) client: gcemeta::Client<HttpConnector>,
    pub(crate) scopes: &'static [&'static str],
    pub(crate) account: Option<String>,
}

#[cfg(test)]
impl PartialEq for Metadata {
    fn eq(&self, other: &Self) -> bool {
        self.scopes == other.scopes && self.account == other.account
    }
}

enum Source<'a> {
    None,
    Default,
    ApiKey { key: String },
    Json { data: &'a [u8] },
    JsonFile { path: &'a Path },
    Metadata { account: Option<String> },
}

impl<'a> Default for Source<'a> {
    fn default() -> Self {
        Self::Default
    }
}

pub struct Builder<'a> {
    scopes: &'static [&'static str],
    audience: Option<&'static str>,
    source: Source<'a>,
}

impl<'a> Default for Builder<'a> {
    fn default() -> Self {
        Self {
            scopes: &["https://www.googleapis.com/auth/cloud-platform"],
            source: Default::default(),
            audience: Default::default(),
        }
    }
}

impl<'a> Builder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn no_credentials(mut self) -> Self {
        self.source = Source::None;
        self
    }

    #[must_use]
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.source = Source::ApiKey { key: key.into() };
        self
    }

    #[must_use]
    pub fn json<'b: 'a>(mut self, data: &'b [u8]) -> Self {
        self.source = Source::Json { data };
        self
    }

    #[must_use]
    pub fn json_file<'b: 'a>(mut self, path: &'b Path) -> Self {
        self.source = Source::JsonFile { path };
        self
    }

    #[must_use]
    pub fn metadata(mut self, account: impl Into<Option<String>>) -> Self {
        self.source = Source::Metadata { account: account.into() };
        self
    }

    #[must_use]
    pub fn scopes(mut self, scopes: &'static [&'static str]) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn audience(mut self, audience: &'static str) -> Self {
        self.audience = Some(audience);
        self
    }

    pub async fn build(self) -> Result<Credentials> {
        match self.source {
            Source::None => Ok(Credentials::None),
            Source::Default => impls::find_default(self.scopes, self.audience).await,
            Source::ApiKey { key } => impls::from_api_key(key),
            Source::Json { data } => impls::from_json(data, self.scopes, self.audience),
            Source::JsonFile { path } => impls::from_json_file(path, self.scopes, self.audience),
            Source::Metadata { account } => Ok(impls::from_metadata(account, self.scopes)
                .await?
                .expect("this process must be running on GCE")),
        }
    }
}
