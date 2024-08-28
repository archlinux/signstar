//! Module for credentials, user IDs and passphrases.

use std::str::FromStr;

use nethsm_sdk_rs::apis::configuration::BasicAuth;
use secrecy::{ExposeSecret, SecretString};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Unable to convert string slice to Passphrase
    #[error("Unable to convert string to passphrase")]
    Passphrase,
}

/// Credentials for a [`NetHsm`][`crate::NetHsm`]
///
/// Holds a user ID and an accompanying [`Passphrase`].
pub struct Credentials {
    pub user_id: String,
    pub passphrase: Option<Passphrase>,
}

impl Credentials {
    /// Creates a new [`Credentials`]
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Credentials, Passphrase};
    ///
    /// let creds = Credentials::new(
    ///     "operator".to_string(),
    ///     Some(Passphrase::new("passphrase".to_string())),
    /// );
    /// ```
    pub fn new(user_id: String, passphrase: Option<Passphrase>) -> Self {
        Self {
            user_id,
            passphrase,
        }
    }
}

impl From<Credentials> for BasicAuth {
    fn from(value: Credentials) -> Self {
        (value.user_id, value.passphrase.map(|x| x.expose_owned()))
    }
}

impl From<&Credentials> for BasicAuth {
    fn from(value: &Credentials) -> Self {
        (
            value.user_id.clone(),
            value.passphrase.as_ref().map(|x| x.expose_owned()),
        )
    }
}

/// A secret passphrase
///
/// The passphrase is held by a [`SecretString`], which guarantees zeroing of memory on
/// destruct.
#[derive(Clone, Debug)]
pub struct Passphrase(SecretString);

impl Passphrase {
    /// Creates a new [`Passphrase`] from owned [`String`]
    ///
    /// # Examples
    /// ```
    /// use nethsm::Passphrase;
    ///
    /// let passphrase = Passphrase::new("passphrase".to_string());
    /// ```
    pub fn new(passphrase: String) -> Self {
        Self(SecretString::new(passphrase))
    }

    /// Exposes the secret passphrase as owned [`String`]
    ///
    /// This is a convenience function, as much of [`nethsm_sdk_rs`] exclusively deals with owned
    /// strings.
    pub fn expose_owned(&self) -> String {
        self.0.expose_secret().to_owned()
    }
}

impl FromStr for Passphrase {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            SecretString::from_str(s).map_err(|_| Error::Passphrase)?,
        ))
    }
}
