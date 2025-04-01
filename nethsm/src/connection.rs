//! Components for NetHSM connection handling.

use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

/// An error that may occur when working with NetHSM connections.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The format of a URL is invalid.
    ///
    /// A [`url::Url`] could be created, but one of the additional constraints imposed by [`Url`]
    /// can not be met.
    #[error("The format of URL {url} is invalid because {context}")]
    UrlInvalidFormat {
        /// The [`url::Url`] for which one of the [`Url`] constraints can not be met.
        url: url::Url,

        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "The format of URL {url} is invalid because ".
        context: &'static str,
    },

    /// A URL can not be parsed.
    #[error("URL parser error:\n{0}")]
    UrlParse(#[from] url::ParseError),
}

/// The URL used for connecting to a NetHSM instance.
///
/// Wraps [`url::Url`] but offers stricter constraints.
/// The URL
///
/// * must use https
/// * must have a host
/// * must not contain a password, user or query
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "String")]
pub struct Url(url::Url);

impl Url {
    /// Creates a new Url.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::Url;
    ///
    /// # fn main() -> testresult::TestResult {
    /// Url::new("https://example.org/api/v1")?;
    /// Url::new("https://127.0.0.1:8443/api/v1")?;
    ///
    /// // errors when not using https
    /// assert!(Url::new("http://example.org/api/v1").is_err());
    ///
    /// // errors when using query, user or password
    /// assert!(Url::new("https://example.org/api/v1?something").is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// * https is not used
    /// * a host is not defined
    /// * the URL contains a password, user or query
    pub fn new(url: &str) -> Result<Self, crate::Error> {
        let url = url::Url::parse(url).map_err(Error::UrlParse)?;
        if !url.scheme().eq("https") {
            Err(Error::UrlInvalidFormat {
                url,
                context: "a URL must use TLS",
            }
            .into())
        } else if !url.has_host() {
            Err(Error::UrlInvalidFormat {
                url,
                context: "a URL must have a host component",
            }
            .into())
        } else if url.password().is_some() {
            Err(Error::UrlInvalidFormat {
                url,
                context: "a URL must not have a password component",
            }
            .into())
        } else if !url.username().is_empty() {
            Err(Error::UrlInvalidFormat {
                url,
                context: "a URL must not have a user component",
            }
            .into())
        } else if url.query().is_some() {
            Err(Error::UrlInvalidFormat {
                url,
                context: "a URL must not have a query component",
            }
            .into())
        } else {
            Ok(Self(url))
        }
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<&str> for Url {
    type Error = crate::Error;

    fn try_from(value: &str) -> Result<Self, crate::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for Url {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self, crate::Error> {
        Self::new(&value)
    }
}

impl FromStr for Url {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}
