//! SSH-client for sending signing requests.
//!
//! This module provides Signstar client. The client is used to
//! connect to a Signstar host and request signatures for given files.
//!
//! # Examples
//!
//! ```no_run
//! # async fn sign() -> testresult::TestResult {
//! use signstar_request_signature::Request;
//! use signstar_request_signature::ssh::client::ConnectConfig;
//!
//! let options = ConnectConfig::from_first_system_config()?;
//!
//! let mut session = options.connect("user").await?;
//! let request = Request::for_file("package")?;
//! let response = session.send(&request).await?;
//! // process response
//! #     Ok(()) }
//! ```
use std::collections::{BTreeMap, HashMap};
use std::fs::read;
use std::num::NonZeroU32;
use std::path::Path;
use std::str::FromStr;
use std::{path::PathBuf, sync::Arc, time::Duration};

use garde::Validate;
use rand::seq::SliceRandom;
use rand::thread_rng;
use russh::client::AuthResult;
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::known_hosts::Entry;
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::{ChannelMsg, Disconnect, MethodSet, client};
use serde::{Deserialize, Deserializer};
use tokio::net::UnixStream;

use crate::{Request, Response};

/// SSH communication error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid options used.
    #[error("Invalid options used: {0}")]
    InvalidOptions(String),

    /// Authentication failed.
    #[error("Authentication failed")]
    AuthFailed {
        /// The server suggests to proceed with these authentication methods.
        remaining_methods: MethodSet,

        /// The server says that though authentication method has been accepted, further
        /// authentication is required.
        partial_success: bool,
    },

    /// Invalid user specified.
    #[error("User {user} is not defined in the config file")]
    InvalidUser {
        /// User name that is missing.
        user: String,
    },

    /// Invalid Signstar host specified.
    #[error("Host {host} is not defined in the config file")]
    InvalidSignstarHost {
        /// Host name that is not defined.
        host: String,
    },

    /// I/O error occurred.
    #[error("I/O error: {source} when processing {file}")]
    Io {
        /// File being processed.
        ///
        /// This field will be empty ([`PathBuf::new`]) if the error
        /// was encountered when processing generic I/O streams.
        file: PathBuf,

        /// Source error.
        source: std::io::Error,
    },

    /// The remote program did not exit cleanly.
    #[error("Program did not exit cleanly")]
    UncleanExit,

    /// The remote application returned a non-zero status code.
    #[error("Remote application failed with status code: {status_code}")]
    RemoteApplicationFailure {
        /// Status code returned by the application.
        status_code: NonZeroU32,
    },

    /// Internal `russh` protocol error.
    #[error("SSH protocol error: {0}")]
    SshProtocol(#[from] russh::Error),

    /// SSH format error.
    #[error("SSH format error: {0}")]
    SshFormat(#[from] russh::keys::Error),

    /// Internal `russh` client agent error.
    #[error("SSH agent error: {0}")]
    Agent(#[from] russh::AgentAuthError),

    /// JSON serialization error.
    #[error("Serde serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// The default config file below "/usr/".
pub const DEFAULT_CONFIG: &str = "/usr/share/signstar/request-signature.toml";

/// The override config file below "/run/".
pub const RUN_OVERRIDE_CONFIG: &str = "/run/signstar/request-signature.toml";

/// The override config file below "/etc/".
pub const ETC_OVERRIDE_CONFIG: &str = "/etc/signstar/request-signature.toml";

/// The connection to a Signstar system a specific user can use.
#[derive(Debug, Deserialize, Validate)]
pub struct SignstarHost {
    /// The host name of the Signstar system.
    #[garde(length(min = 1))]
    host: String,

    /// The SSH port of the Signstar system.
    #[garde(range(min = 1))]
    port: u16,

    /// The known_hosts entries for the Signstar system.
    #[serde(deserialize_with = "deserialize_entries")]
    #[garde(length(min = 1))]
    known_hosts: Vec<Entry>,
}

/// Connection configuration for sending a signature request.
///
/// The configuration tracks a list of all valid targets for connecting.
#[derive(Debug, Default, Deserialize, Validate)]
#[garde(custom(validate_host_ids))]
pub struct ConnectConfig {
    /// List of hosts configured.
    #[garde(
        custom(validate_host_port_uniqueness),
        custom(validate_known_hosts_consistency),
        dive
    )]
    pub hosts: BTreeMap<String, SignstarHost>,

    /// List of users.
    #[garde(custom(validate_ssh_public_key_consistency), dive)]
    pub users: BTreeMap<String, ConnectOptions>,
}

impl ConnectConfig {
    /// The order of configuration files.
    ///
    /// The following files are inspected, in descending priority:
    /// - `/etc/signstar/request-signature.toml`
    /// - `/run/signstar/request-signature.toml`
    /// - `/usr/share/signstar/request-signature.toml`
    pub const CONFIG_ORDER: &[&str] = &[ETC_OVERRIDE_CONFIG, RUN_OVERRIDE_CONFIG, DEFAULT_CONFIG];

    /// Connects to a host over SSH and returns a [`Session`] object.
    ///
    /// This function sets up an authenticated, bidirectional channel
    /// between the client and the server. No signing requests are exchanged at this point but any
    /// number of them can be issued later using [`Session::send`] function.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn sign() -> testresult::TestResult {
    /// use signstar_request_signature::ssh::client::ConnectConfig;
    ///
    /// let options = ConnectConfig::from_first_system_config()?;
    ///
    /// let mut session = options.connect("user").await?;
    /// // use session to send signing requests
    /// #     Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the client public key is not set,
    /// - the server public key is not present in the provided SSH `known_hosts` data,
    /// - the client public key is not recognized by the server,
    /// - the client authentication with the agent fails,
    /// - an SSH protocol error is encountered.
    pub async fn connect(&self, username: &str) -> Result<Session> {
        let user = &self.users.get(username).ok_or(Error::InvalidUser {
            user: username.to_string(),
        })?;
        let host_id = user.hosts.choose(&mut thread_rng());
        let target = if let Some(host_id) = host_id {
            &self.hosts.get(host_id).ok_or(Error::InvalidSignstarHost {
                host: host_id.to_string(),
            })?
        } else {
            return Err(Error::InvalidOptions(
                "at least one host must be defined".into(),
            ));
        };
        let client_auth_public_key = &user.user_public_key;

        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        });

        let stream = UnixStream::connect(&user.agent_socket)
            .await
            .map_err(|source| Error::Io {
                file: user.agent_socket.clone(),
                source,
            })?;
        let mut future = AgentClient::connect(stream);
        let mut session = client::connect(
            config,
            (target.host.clone(), target.port),
            KeyValidator {
                host: target.host.clone(),
                port: target.port,
                entries: target.known_hosts.clone(),
            },
        )
        .await?;
        let auth_res = session
            .authenticate_publickey_with(
                username,
                client_auth_public_key.clone(),
                Some(HashAlg::Sha512),
                &mut future,
            )
            .await?;

        if let AuthResult::Failure {
            remaining_methods,
            partial_success,
        } = auth_res
        {
            return Err(Error::AuthFailed {
                remaining_methods,
                partial_success,
            });
        }

        Ok(Session {
            session,
            host: target.host.clone(),
            port: target.port,
        })
    }

    /// Return the first configuration file that exists in the filesystem out of
    /// [`Self::CONFIG_ORDER`] list or returns a [`crate::Error::ConfigMissing`] error.
    ///
    /// # Errors
    ///
    /// Returns an error:
    /// - [`crate::Error::Io`] if checking the config fails
    /// - [`crate::Error::ConfigMissing`] if no configuration files have been found
    fn first_existing_system_config() -> std::result::Result<PathBuf, crate::Error> {
        let candidates = Self::CONFIG_ORDER.iter();
        for file in candidates {
            let file = PathBuf::from(file);
            if std::fs::exists(&file).map_err(|source| crate::Error::Io {
                file: file.clone(),
                source,
            })? {
                return Ok(file);
            }
        }
        Err(crate::Error::ConfigMissing)
    }

    /// Return the configuration created from the first configuration file that exists in the
    /// filesystem out of [`Self::CONFIG_ORDER`] list or returns a
    /// [`crate::Error::ConfigMissing`] error.
    ///
    /// # Errors
    ///
    /// Returns an error:
    /// - [`crate::Error::Io`] if checking the config fails
    /// - [`crate::Error::ConfigMissing`] if no configuration files have been found
    /// - [`crate::Error::Validation`] if the config file has invalid contents
    pub fn from_first_system_config() -> std::result::Result<Self, crate::Error> {
        Self::from_config_file(Self::first_existing_system_config()?)
    }

    /// Reads the configuration file, validates it and returns the [`ConnectConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error:
    /// - [`crate::Error::Io`] if reading the config file fails
    /// - [`crate::Error::Validation`] if the config file has invalid contents
    pub fn from_config_file(file: impl AsRef<Path>) -> std::result::Result<Self, crate::Error> {
        let contents = read(file.as_ref()).map_err(|source| crate::Error::Io {
            file: file.as_ref().into(),
            source,
        })?;
        let config: Self = toml::from_slice(&contents)?;
        config
            .validate()
            .map_err(|source| crate::Error::Validation {
                context: "reading configuration file".to_owned(),
                source,
            })?;
        Ok(config)
    }
}

/// Ensures, that SSH public keys are unique per user.
///
/// # Errors
///
/// Returns an error if an SSH public key is used by more than one user.
fn validate_ssh_public_key_consistency(
    users: &BTreeMap<String, ConnectOptions>,
    _context: &(),
) -> garde::Result {
    let failures = users
        .iter()
        .map(|(user, connect_option)| (user, &connect_option.user_public_key))
        .fold(
            HashMap::<&PublicKey, Vec<&str>>::new(),
            |mut acc, (user, user_public_key)| {
                acc.entry(user_public_key).or_default().push(user);
                acc
            },
        )
        .into_iter()
        .filter(|(_, users)| users.len() > 1)
        .map(|(pk, users)| {
            format!(
                "Public key {pk} is shared by these users: {users}",
                pk = pk.to_string(),
                users = users.join(", ")
            )
        })
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        return Err(garde::Error::new(format!(
            "The SSH public key used for a user cannot be used for another user:\n{failures}",
            failures = failures.join("\n")
        )));
    }

    Ok(())
}

/// Ensures, that the `known_hosts` entries are unique per `host:port` combinations.
///
/// # Errors
///
/// Returns an error if the `known_hosts` entries differ for any instance of a `host:port`
/// combination.
fn validate_known_hosts_consistency(
    connect_options: &BTreeMap<String, SignstarHost>,
    _context: &(),
) -> garde::Result {
    let failures = connect_options
        .iter()
        .map(|(host, config)| (host, &config.known_hosts))
        .fold(
            HashMap::<String, Vec<&str>>::new(),
            |mut acc, (host, known_hosts)| {
                for known_host in known_hosts {
                    acc.entry(known_host.to_string()).or_default().push(host);
                }
                acc
            },
        )
        .into_iter()
        .filter(|(_, hosts)| hosts.len() > 1)
        .map(|(entry, hosts)| {
            format!(
                "Entry {entry} is shared by these hosts: {hosts}",
                hosts = hosts.join(", ")
            )
        })
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        return Err(garde::Error::new(format!(
            "The known host entry used for a host cannot be used for another host:\n{failures}",
            failures = failures.join("\n")
        )));
    }

    Ok(())
}

/// Ensures, that each host:port combination is unique.
///
/// # Errors
///
/// Returns an error if there is a duplicate host:port combination.
fn validate_host_port_uniqueness(
    connect_options: &BTreeMap<String, SignstarHost>,
    _context: &(),
) -> garde::Result {
    let failures = connect_options
        .iter()
        .map(|(host_id, config)| (host_id, &config.host, config.port))
        .fold(
            HashMap::<(&str, u16), Vec<&str>>::new(),
            |mut acc, (host_id, host, port)| {
                acc.entry((host, port)).or_default().push(host_id);

                acc
            },
        )
        .into_iter()
        .filter(|(_, host_ids)| host_ids.len() > 1)
        .map(|((host, port), host_ids)| {
            format!(
                "Host {host}:{port} is shared by these hosts: {host_ids}",
                host_ids = host_ids.join(", ")
            )
        })
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        return Err(garde::Error::new(format!(
            "Two connections cannot have the same host:port combinations:\n{failures}",
            failures = failures.join("\n")
        )));
    }

    Ok(())
}

/// Ensures, that each `host_id` in a [`ConnectConfig`] is defined.
///
/// # Errors
///
/// Returns an error if there are host_ids which are not defined.
fn validate_host_ids(config: &ConnectConfig, _context: &()) -> garde::Result {
    let failures = config
        .users
        .iter()
        .flat_map(|(user_id, options)| {
            options
                .hosts
                .iter()
                .filter(|host| !config.hosts.contains_key(*host))
                .map(move |invalid_host| (user_id, invalid_host))
        })
        .map(|(user, invalid_host)| {
            format!("User {user} is using host_id which is not defined: {invalid_host}",)
        })
        .collect::<Vec<_>>();

    if !failures.is_empty() {
        return Err(garde::Error::new(failures.join("\n")));
    }

    Ok(())
}

/// Connection options for sending a signature request.
///
/// The options capture target host parameters and all necessary
/// information related to authentication for both the client
/// (client's public key and authentication agent) and server (a list
/// of valid and known server public keys).
///
/// # Examples
///
/// ```no_run
/// # fn main() -> testresult::TestResult {
/// use signstar_request_signature::ssh::client::ConnectOptions;
///
/// let options = ConnectOptions::new("localhost".into(), "ssh-ed25519 ...")?
///     .agent_socket(std::env::var("SSH_AUTH_SOCK")?);
/// # Ok(()) }
/// ```
#[derive(Debug, Deserialize, Validate)]
pub struct ConnectOptions {
    /// The path to the SSH agent socket used for the connection to `user` on the Signstar
    /// system(s).
    #[garde(skip)]
    pub agent_socket: PathBuf,

    /// The SSH public key used for the connections to `user` on the Signstar system(s).
    #[garde(skip)]
    pub user_public_key: PublicKey,

    /// The list of Signstar hosts that the `user` can connect to.
    #[garde(length(min = 1))]
    pub hosts: Vec<String>,
}

impl ConnectOptions {
    /// Sets the path to an OpenSSH agent socket for client authentication.
    pub fn agent_socket(mut self, agent_socket: impl Into<PathBuf>) -> Self {
        self.agent_socket = agent_socket.into();
        self
    }

    /// Sets an SSH public key of a client for SSH authentication.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> testresult::TestResult {
    /// use signstar_request_signature::ssh::client::ConnectOptions;
    ///
    /// let client_pk =
    ///     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHCXBJYlPPkrt2WYyP3SZoMx43lDBB5QALjE762EQlc";
    /// let options = ConnectOptions::new("localhost".into(), client_pk)?;
    /// #     Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is not well-formatted. This
    /// function only accepts public keys following the
    /// [`authorized_keys` file format].
    ///
    /// [`authorized_keys` file format]: https://man.archlinux.org/man/core/openssh/sshd.8.en#AUTHORIZED_KEYS_FILE_FORMAT.
    pub fn user_public_key(mut self, user_public_key: impl Into<String>) -> Result<Self> {
        self.user_public_key =
            PublicKey::from_openssh(&user_public_key.into()).map_err(russh::keys::Error::SshKey)?;
        Ok(self)
    }

    /// Constructs a new [`ConnectOptions`] with target host and client public key.
    pub fn new(host: String, client_auth_public_key: impl AsRef<str>) -> Result<Self> {
        let client_auth_public_key = PublicKey::from_openssh(client_auth_public_key.as_ref())
            .map_err(russh::keys::Error::SshKey)?;
        Ok(Self {
            hosts: vec![host],
            agent_socket: Default::default(),
            user_public_key: client_auth_public_key,
        })
    }
}

fn deserialize_entries<'de, D>(deserializer: D) -> std::result::Result<Vec<Entry>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(|entry: String| Entry::from_str(&entry).map_err(serde::de::Error::custom))
        .collect::<std::result::Result<_, _>>()
}

/// Validator for a host's SSH keys and a list of `known_hosts` entries.
///
/// Tracks a `host` and its `port`, as well as a list of `entries` in the [SSH `known_hosts` file
/// format].
///
/// [SSH `known_hosts` file format]: https://man.archlinux.org/man/sshd.8#SSH_KNOWN_HOSTS_FILE_FORMAT
struct KeyValidator {
    host: String,
    port: u16,
    entries: Vec<Entry>,
}

impl client::Handler for KeyValidator {
    type Error = Error;

    /// Checks whether a set of server details can be found in SSH `known_hosts` data.
    ///
    /// Based on a `host` and its `port`, this function evaluates whether a supplied `key` is part
    /// of a list of `entries` in the SSH known_hosts file format. Returns `true`, if the
    /// combination of `key`, `host` and `port` matches an entry in the list of `entries` and that
    /// entry is not a CA key or a revoked key. Returns `false` in all other cases.
    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool> {
        Ok(crate::ssh::known_hosts::is_server_known(
            self.entries.iter(),
            &self.host,
            self.port,
            server_public_key,
        ))
    }
}

/// An open session with a host that can be used to send multiple signing requests.
pub struct Session {
    session: client::Handle<KeyValidator>,
    host: String,
    port: u16,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SSH session for host {} on port {}",
            self.host, self.port
        )
    }
}

impl Session {
    /// Send a signing request to the server and return a signing response.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn sign() -> testresult::TestResult {
    /// use signstar_request_signature::Request;
    /// use signstar_request_signature::ssh::client::ConnectConfig;
    ///
    /// let options = ConnectConfig::from_first_system_config()?;
    ///
    /// let mut session = options.connect("user").await?;
    /// let request = Request::for_file("package")?;
    /// let response = session.send(&request).await?;
    /// // process response
    /// #     Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if sending or processing the signing request fails:
    /// - if the remote server rejects the signing request,
    /// - if the remote application exits unexpectedly,
    /// - the returned data cannot be deserialized into a [`Response`],
    /// - if an SSH protocol error is encountered.
    pub async fn send(&mut self, data: &Request) -> Result<Response> {
        let mut channel = self.session.channel_open_session().await?;
        // the command name is empty as it is assumed that the server will
        // pick correct binary anyway
        let command_name = b"";
        channel.exec(true, command_name).await?;
        let data = serde_json::to_vec(&data)?;
        channel.data(data.as_ref()).await?;
        channel.eof().await?;

        let mut code = None;
        let mut stdout = vec![];

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => {
                    stdout.extend(data.iter());
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                    // cannot leave the loop immediately, there might still be more data to receive
                }
                _ => {}
            }
        }

        if let Some(code) = code {
            if let Some(status_code) = NonZeroU32::new(code) {
                Err(Error::RemoteApplicationFailure { status_code })
            } else {
                Ok(serde_json::from_slice(&stdout)?)
            }
        } else {
            Err(Error::UncleanExit)
        }
    }

    /// Close the authentication session.
    ///
    /// This function cleanly closes the session and informs the
    /// server that no further requests will be sent.
    ///
    /// # Examples
    ///
    /// This example shows that after the [`Session::close`] function is invoked no further requests
    /// can be sent.
    ///
    /// ```compile_fail
    /// # async fn sign() -> testresult::TestResult {
    /// use signstar_request_signature::ssh::client::ConnectConfig;
    ///
    /// let options = ConnectConfig::from_first_system_config();
    ///
    /// let mut session = options.connect("user").await?;
    /// session.close();
    ///
    /// // the session object has been consumed and cannot be reused
    /// let request = Request::for_file("package")?;
    /// let response = session.send(&request).await?;
    /// #     Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if at any stage of the connecting process fails:
    /// - if the client public key is not set,
    /// - if the server public key is not pinned in the known hosts file,
    /// - if the client public key is not recognized by the server,
    /// - if the client authentication with the agent fails,
    /// - if an SSH protocol error is encountered.
    pub async fn close(self) -> Result<()> {
        self.session
            .disconnect(
                Disconnect::ByApplication,
                "Client is closing the connection",
                "en",
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use garde::Validate;
    use insta::assert_snapshot;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn validate_success() -> TestResult {
        let config = ConnectConfig {
                users: [("test-user".into(), ConnectOptions::new(
                    "local".into(),
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?)].into_iter().collect(),
                hosts: [("local".into(), SignstarHost {
                    host: "127.0.0.1".into(),
                    port: 22,
                    known_hosts: vec![Entry::from_str("test1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd")?],
                })].into_iter().collect(),
            };

        config.validate()?;

        Ok(())
    }

    #[test]
    fn validate_ssh_public_key_cannot_be_reused() -> TestResult {
        let config = ConnectConfig {
                users: [("test-user".into(), ConnectOptions::new(
                    "local".into(),
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?),("test-user2".into(), ConnectOptions::new(
                    "local".into(),
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?)].into_iter().collect(),
                hosts: [("local".into(), SignstarHost {
                    host: "127.0.0.1".into(),
                    port: 22,
                    known_hosts: vec![Entry::from_str("test1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd")?],
                })].into_iter().collect(),
            };

        let error_msg = match config.validate() {
            Ok(()) => {
                panic!("Expected to fail with garde::Error, but succeeded instead.")
            }
            Err(error) => error.to_string(),
        };

        assert_snapshot!(error_msg);

        Ok(())
    }

    #[test]
    fn validate_known_hosts_entries_unique_per_host_port_of_the_user() -> TestResult {
        let config = ConnectConfig {
                users: [("test-user".into(), ConnectOptions::new(
                    "local".into(),
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?),("test-user2".into(), ConnectOptions::new(
                    "local2".into(),
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPP",
                )?)].into_iter().collect(),
                hosts: [("local".into(), SignstarHost {
                    host: "127.0.0.1".into(),
                    port: 22,
                    known_hosts: vec![Entry::from_str("test1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd")?],
                }),("local2".into(), SignstarHost {
                    host: "127.0.0.2".into(),
                    port: 22,
                    known_hosts: vec![Entry::from_str("test1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd")?],
                })].into_iter().collect(),
            };

        let error_msg = match config.validate() {
            Ok(()) => {
                panic!("Expected to fail with garde::Error, but succeeded instead.")
            }
            Err(error) => error.to_string(),
        };

        assert_snapshot!(error_msg);

        Ok(())
    }

    #[test]
    fn validate_host_port_uniqueness() -> TestResult {
        let config = ConnectConfig {
                users: [("test-user".into(), ConnectOptions::new(
                    "local".into(),
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?),("test-user2".into(), ConnectOptions::new(
                    "local2".into(),
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPP",
                )?)].into_iter().collect(),
                hosts: [("local".into(), SignstarHost {
                    host: "127.0.0.1".into(),
                    port: 22,
                    known_hosts: vec![Entry::from_str("test1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAD")?],
                }),("local2".into(), SignstarHost {
                    host: "127.0.0.1".into(),
                    port: 22,
                    known_hosts: vec![Entry::from_str("test1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd")?],
                })].into_iter().collect(),
            };

        let error_msg = match config.validate() {
            Ok(()) => {
                panic!("Expected to fail with garde::Error, but succeeded instead.")
            }
            Err(error) => error.to_string(),
        };

        assert_snapshot!(error_msg);

        Ok(())
    }

    #[test]
    fn validate_host_ids() -> TestResult {
        let config = ConnectConfig {
                users: [("test-user".into(), ConnectOptions::new(
                    "test".into(),
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?),("test-user2".into(), ConnectOptions::new(
                    "test".into(),
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPP",
                )?)].into_iter().collect(),
                hosts: [("test2".into(), SignstarHost {
                    host: "127.0.0.1".into(),
                    port: 22,
                    known_hosts: vec![Entry::from_str("test1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd")?],
                })].into_iter().collect(),
            };

        let error_msg = match config.validate() {
            Ok(()) => {
                panic!("Expected to fail with garde::Error, but succeeded instead.")
            }
            Err(error) => error.to_string(),
        };

        assert_snapshot!(error_msg);

        Ok(())
    }
}
