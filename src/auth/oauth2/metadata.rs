use std::{fmt, str::FromStr as _};

use futures_util::TryFutureExt as _;
use hyper::{client::HttpConnector, http::uri::PathAndQuery, Body};

use crate::{
    auth::{self, oauth2::token},
    credentials,
};

use super::token::Response;

#[derive(serde::Serialize)]
struct Query<'a> {
    scopes: &'a str,
}

#[derive(serde::Serialize)]
struct AudienceQuery<'a> {
    audience: &'a str,
}

pub struct Metadata {
    inner: gcemeta::Client<HttpConnector, Body>,
    path_and_query: PathAndQuery,
    is_service_to_service: bool,
}

impl Metadata {
    pub(crate) fn new(meta: Box<credentials::Metadata>) -> Self {
        let is_service_to_service = meta.audience.is_some();
        let path_and_query = path_and_query(meta.account, meta.scopes, meta.audience);
        let path_and_query = PathAndQuery::from_str(&path_and_query).unwrap();
        Self {
            inner: meta.client,
            path_and_query,
            is_service_to_service,
        }
    }
}

fn path_and_query(
    account: Option<String>,
    scopes: Vec<String>,
    audience: Option<String>,
) -> String {
    let mut path_and_query = "/computeMetadata/v1/instance/service-accounts/".to_owned();
    path_and_query.push_str(account.as_ref().map_or("default", String::as_str));
    if audience.is_some() {
        path_and_query.push_str("/identity");
    } else {
        path_and_query.push_str("/token");
    }
    if let Some(aud) = audience {
        path_and_query.push('?');
        let query = AudienceQuery {
            audience: aud.as_str(),
        };
        path_and_query.push_str(&serde_urlencoded::to_string(&query).unwrap());
    } else if !scopes.is_empty() {
        path_and_query.push('?');
        let query = Query {
            scopes: &scopes.join(","),
        };
        path_and_query.push_str(&serde_urlencoded::to_string(&query).unwrap());
    }
    path_and_query
}

impl fmt::Debug for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metadata").finish()
    }
}

impl token::Fetcher for Metadata {
    fn fetch(&self) -> token::ResponseFuture {
        // Already checked that this process is running on GCE.
        if self.is_service_to_service {
            let fut = self
                .inner
                .get(self.path_and_query.clone(), true)
                .map_ok(|s| Response::IdToken { id_token: s })
                .map_err(auth::Error::Gcemeta);
            Box::pin(fut)
        } else {
            let fut = self
                .inner
                .get_as(self.path_and_query.clone())
                .map_err(auth::Error::Gcemeta);
            Box::pin(fut)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_path_and_query() {
        assert_eq!(
            &path_and_query(None, vec![], None),
            "/computeMetadata/v1/instance/service-accounts/default/token"
        );

        assert_eq!(
            &path_and_query(None, vec!["https://www.googleapis.com/auth/cloud-platform".to_owned()], None),
            "/computeMetadata/v1/instance/service-accounts/default/token?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform"
        );

        assert_eq!(
            &path_and_query(None, vec!["scope1".to_owned(), "scope2".to_owned()], None),
            "/computeMetadata/v1/instance/service-accounts/default/token?scopes=scope1%2Cscope2"
        );

        assert_eq!(
            &path_and_query(None, vec![], Some("https://some-service.url".to_owned())),
            "/computeMetadata/v1/instance/service-accounts/default/identity?audience=https%3A%2F%2Fsome-service.url"
        )
    }
}
