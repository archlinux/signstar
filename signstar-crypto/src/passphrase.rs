//! Passphrase handling.

use std::{fmt::Display, str::FromStr};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// An error that may occur when operating on users.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Unable to convert string slice to Passphrase
    #[error("Unable to convert string to passphrase")]
    Passphrase,
}

/// A secret passphrase
///
/// The passphrase is held by a [`SecretString`], which guarantees zeroing of memory on
/// destruct.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Passphrase(SecretString);

impl Passphrase {
    /// Creates a new [`Passphrase`] from owned [`String`]
    ///
    /// # Examples
    /// ```
    /// use signstar_crypto::passphrase::Passphrase;
    ///
    /// let passphrase = Passphrase::new("passphrase".to_string());
    /// ```
    pub fn new(passphrase: String) -> Self {
        Self(SecretString::new(passphrase.into()))
    }

    /// Exposes the secret passphrase as owned [`String`]
    pub fn expose_owned(&self) -> String {
        self.0.expose_secret().to_owned()
    }

    /// Exposes the secret passphrase as borrowed [`str`]
    pub fn expose_borrowed(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Display for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl FromStr for Passphrase {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(SecretString::from(s.to_string())))
    }
}

impl Serialize for Passphrase {
    /// Serializes a [`Passphrase`].
    ///
    /// # Warning
    ///
    /// This may be used to write a passphrase to file!
    /// Take precautions so that passphrases can not leak to the environment.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.expose_secret().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use testresult::TestResult;

    use super::*;

    #[test]
    fn passphrase_display() -> TestResult {
        let passphrase = Passphrase::new("a-secret-passphrase".to_string());
        assert_eq!(format!("{passphrase}"), "[REDACTED]");
        Ok(())
    }
}
