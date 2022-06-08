use std::{convert::TryFrom as _, env, fs, path::Path, str::FromStr as _};

use hyper::http::uri::PathAndQuery;
use tracing::trace;

use crate::credentials::{Credentials, Error, Metadata, Result, ServiceAccount, User};

pub(super) fn from_api_key(key: String) -> Result<Credentials> {
    let part = PathAndQuery::try_from(&format!("?{}", key)).map_err(Error::ApiKeyFormat)?;
    assert_eq!(part.query().unwrap_or_default(), &key);
    Ok(Credentials::ApiKey(key))
}

/// Looks for credentials in the following places, preferring the first location found:
/// - A JSON file whose path is specified by the `GOOGLE_APPLICATION_CREDENTIALS` environment variable.
/// - A JSON file in a location known to the gcloud command-line tool.
/// - On Google Compute Engine, it fetches credentials from the metadata server.
pub(super) async fn find_default<'a, S, T>(
    scopes: &'a [S],
    audience: &'a Option<T>,
) -> Result<Credentials>
where
    S: AsRef<str>,
    String: From<&'a T>,
{
    let credentials = if let Some(c) = from_env(scopes, audience)? {
        c
    } else if let Some(c) = from_well_known_file(scopes, audience)? {
        c
    } else if let Some(c) = from_metadata(None, scopes).await? {
        c
    } else {
        return Err(Error::CredentialsSource);
    };
    Ok(credentials)
}

pub(super) fn from_env<'a, S, T>(
    scopes: &'a [S],
    audience: &'a Option<T>,
) -> Result<Option<Credentials>>
where
    S: AsRef<str>,
    String: From<&'a T>,
{
    const NAME: &str = "GOOGLE_APPLICATION_CREDENTIALS";
    trace!("try getting `{}` from environment variable", NAME);
    match env::var(NAME) {
        Ok(path) => from_json_file(path, scopes, audience).map(Some),
        Err(err) => {
            trace!("failed to get environment variable: {:?}", err);
            Ok(None)
        }
    }
}

pub(super) fn from_well_known_file<'a, S, T>(
    scopes: &'a [S],
    audience: &'a Option<T>,
) -> Result<Option<Credentials>>
where
    S: AsRef<str>,
    String: From<&'a T>,
{
    let path = {
        let mut buf = {
            #[cfg(target_os = "windows")]
            {
                std::path::PathBuf::from(env::var("APPDATA").unwrap_or_default())
            }
            #[cfg(not(target_os = "windows"))]
            {
                let mut buf = std::path::PathBuf::from(env::var("HOME").unwrap_or_default());
                buf.push(".config");
                buf
            }
        };

        buf.push("gcloud");
        buf.push("application_default_credentials.json");
        buf
    };

    trace!("well known file path is {:?}", path);
    if path.exists() {
        from_json_file(path, scopes, audience).map(Some)
    } else {
        trace!("no file exists at {:?}", path);
        Ok(None)
    }
}

pub(super) fn from_json_file<'a, S, T>(
    path: impl AsRef<Path>,
    scopes: &'a [S],
    audience: &'a Option<T>,
) -> Result<Credentials>
where
    S: AsRef<str>,
    String: From<&'a T>,
{
    trace!("try reading credentials file from {:?}", path.as_ref());
    let json = fs::read_to_string(path).map_err(Error::CredentialsFile)?;
    from_json(json.as_bytes(), scopes, audience)
}

pub(super) fn from_json<'a, S, T>(
    json: &[u8],
    scopes: &'a [S],
    audience: &'a Option<T>,
) -> Result<Credentials>
where
    S: AsRef<str>,
    String: From<&'a T>,
{
    trace!("try deserializing to service account credentials");
    let service_account = match serde_json::from_slice::<ServiceAccount>(json) {
        Ok(mut sa) => {
            sa.scopes = scopes.iter().map(|s| s.as_ref().into()).collect();
            sa.audience = audience.as_ref().map(|s| s.into());
            return Ok(Credentials::ServiceAccount(sa));
        }
        Err(err) => {
            trace!(
                "failed deserialize to service account credentials: {:?}",
                err
            );
            err
        }
    };

    trace!("try deserializing to user credentials");
    let user = match serde_json::from_slice::<User>(json) {
        Ok(mut user) => {
            user.scopes = scopes.iter().map(|s| s.as_ref().into()).collect();
            return Ok(Credentials::User(user));
        }
        Err(err) => {
            trace!("failed deserialize to user credentials: {:?}", err);
            err
        }
    };

    Err(Error::CredentialsFormat {
        user,
        service_account,
    })
}

pub(super) async fn from_metadata<S: AsRef<str>>(
    account: Option<String>,
    scopes: &[S],
) -> Result<Option<Credentials>> {
    let client = gcemeta::Client::new();
    // Check if the account is valid as path string.
    if let Some(ref account) = account {
        let part = PathAndQuery::from_str(account).map_err(gcemeta::Error::Uri)?;
        assert_eq!(part.path(), account);
    }

    trace!("try checking if this process is running on GCE");
    let on = client.on_gce().await?;
    trace!("this process is running on GCE: {}", on);

    if on {
        Ok(Some(Credentials::Metadata(
            Metadata {
                client,
                scopes: scopes.iter().map(|s| s.as_ref().into()).collect(),
                account,
            }
            .into(),
        )))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_api_key() {
        assert!(from_api_key("こんにちは".into()).is_err());
        assert_eq!(
            from_api_key("api-key".into()).unwrap(),
            Credentials::ApiKey("api-key".into())
        );
    }

    #[test]
    fn test_from_json() {
        assert_eq!(
            from_json(
                br#"{
"type": "service_account",
"project_id": "[PROJECT-ID]",
"private_key_id": "[KEY-ID]",
"private_key": "-----BEGIN PRIVATE KEY-----\n[PRIVATE-KEY]\n-----END PRIVATE KEY-----\n",
"client_email": "[SERVICE-ACCOUNT-EMAIL]",
"client_id": "[CLIENT-ID]",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://accounts.google.com/o/oauth2/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/[SERVICE-ACCOUNT-EMAIL]"
}"#,
                &[] as &[String],
                &None as &Option<String>,
            )
            .unwrap(),
            Credentials::ServiceAccount(ServiceAccount {
                scopes: vec![],
                audience: None,
                client_email: "[SERVICE-ACCOUNT-EMAIL]".into(),
                private_key_id: "[KEY-ID]".into(),
                private_key:
                    "-----BEGIN PRIVATE KEY-----\n[PRIVATE-KEY]\n-----END PRIVATE KEY-----\n".into(),
                token_uri: "https://accounts.google.com/o/oauth2/token".into(),
            })
        );

        assert_eq!(
            from_json(
                br#"{
  "client_id": "xxx.apps.googleusercontent.com",
  "client_secret": "secret-xxx",
  "refresh_token": "refresh-xxx",
  "type": "authorized_user"
}"#,
                &[] as &[String],
                &None as &Option<String>,
            )
            .unwrap(),
            Credentials::User(User {
                scopes: vec![],
                client_id: "xxx.apps.googleusercontent.com".into(),
                client_secret: "secret-xxx".into(),
                refresh_token: "refresh-xxx".into(),
            })
        );
    }
}
