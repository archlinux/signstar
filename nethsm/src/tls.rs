use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::Duration;
use std::{fmt::Display, str::FromStr};

use log::info;
use nethsm_sdk_rs::ureq::{
    Agent,
    tls::{Certificate, RootCerts, TlsConfig, TlsProvider},
};
use serde::{Deserialize, Serialize};

use crate::Error;
#[cfg(doc)]
use crate::NetHsm;

/// The default maximum idle TLS connections for a [`NetHsm`].
pub const DEFAULT_MAX_IDLE_CONNECTIONS: usize = 100;

/// The default timeout in seconds for a TLS connections for a [`NetHsm`].
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 10;

/// A list of TLS certificates to validate TLS communication with.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RootCertificates(Vec<Vec<u8>>);

impl From<&RootCertificates> for RootCerts {
    fn from(value: &RootCertificates) -> Self {
        let certs = value
            .0
            .iter()
            .map(|cert| Certificate::from_der(cert).to_owned())
            .collect::<Vec<_>>();
        RootCerts::Specific(Arc::new(certs))
    }
}

/// The security model chosen for a [`crate::NetHsm`]'s TLS connection
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ConnectionSecurity {
    /// Always trust the TLS certificate associated with a host
    Unsafe,
    /// Use the native trust store to evaluate the trust of a host
    Native,
    /// Use a list of root certificate objects to verify a host's TLS certificate.
    RootCertificates(RootCertificates),
}

impl Display for ConnectionSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsafe => write!(f, "unsafe"),
            Self::Native => write!(f, "native"),
            Self::RootCertificates(_) => write!(f, "custom root certificates"),
        }
    }
}

impl FromStr for ConnectionSecurity {
    type Err = Error;

    /// Create a ConnectionSecurity from string
    ///
    /// Valid inputs are either "Unsafe" (or "unsafe"), "Native" (or "native") or "sha256:checksum"
    /// where "checksum" denotes 64 ASCII hexadecimal chars.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the input is neither "Unsafe" nor "Native" and also no valid
    /// certificate fingerprint can be derived from the input.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use nethsm::ConnectionSecurity;
    ///
    /// assert!(ConnectionSecurity::from_str("unsafe").is_ok());
    /// assert!(ConnectionSecurity::from_str("native").is_ok());
    /// assert!(ConnectionSecurity::from_str("something").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unsafe" | "Unsafe" => Ok(Self::Unsafe),
            "native" | "Native" => Ok(Self::Native),
            _ => Err(Error::Default(format!("Invalid connection security: {s}"))),
        }
    }
}

/// Creates an [`Agent`] for the use in a [`NetHsm`] connection.
///
/// Takes a [`ConnectionSecurity`] to define the TLS security model for the connection.
/// Allows setting the maximum idle connections per host using the optional
/// `max_idle_connections` (defaults to [`available_parallelism`] and falls back to
/// [`DEFAULT_MAX_IDLE_CONNECTIONS`] if unavailable).
/// Also allows setting the timeout in seconds for a successful socket connection
/// using the optional `timeout_seconds` (defaults to [`DEFAULT_TIMEOUT_SECONDS`]).
///
/// # Errors
///
/// Returns an error if
///
/// - the TLS client configuration can not be created,
/// - [`ConnectionSecurity::Native`] is provided as `tls_security`, but no certification authority
///   certificates are available on the system.
pub(crate) fn create_agent(
    tls_security: ConnectionSecurity,
    max_idle_connections: Option<usize>,
    timeout_seconds: Option<u64>,
) -> Result<Agent, Error> {
    let max_idle_connections = max_idle_connections
        .or_else(|| available_parallelism().ok().map(Into::into))
        .unwrap_or(DEFAULT_MAX_IDLE_CONNECTIONS);
    let timeout_seconds = timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS);
    info!(
        "NetHSM connection configured with \"max_idle_connection\" {max_idle_connections} and \"timeout_seconds\" {timeout_seconds}."
    );
    let tls_config = {
        let mut tls_config_builder = TlsConfig::builder().provider(TlsProvider::Rustls);

        tls_config_builder = match &tls_security {
            ConnectionSecurity::Unsafe => tls_config_builder.disable_verification(true),
            ConnectionSecurity::Native => {
                tls_config_builder.root_certs(RootCerts::PlatformVerifier)
            }
            ConnectionSecurity::RootCertificates(root_certs) => {
                tls_config_builder.root_certs(RootCerts::from(root_certs))
            }
        };

        tls_config_builder.build()
    };
    let agent = Agent::config_builder()
        .max_idle_connections(max_idle_connections)
        .max_idle_connections_per_host(max_idle_connections)
        .timeout_connect(Some(Duration::from_secs(timeout_seconds)))
        .tls_config(tls_config)
        .build()
        .new_agent();

    Ok(agent)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[rstest]
    #[case(ConnectionSecurity::Native, "native")]
    #[case(ConnectionSecurity::Unsafe, "unsafe")]
    #[case(ConnectionSecurity::RootCertificates(RootCertificates(vec![vec![]])), "custom root certificates")]
    fn connectionsecurity_display(
        #[case] connection_security: ConnectionSecurity,
        #[case] expected: &str,
    ) -> TestResult {
        assert_eq!(connection_security.to_string(), expected);
        Ok(())
    }
}
