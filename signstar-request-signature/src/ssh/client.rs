//! SSH-client for sending signing requests.
//!
//! This module provides Signstar client. The client is used to
//! connect to a Signstar host and request signatures for given files.
//!
//! # Examples
//!
//! ```no_run
//! # async fn sign() -> testresult::TestResult {
//! # let known_hosts = "/dev/null";
//! use signstar_request_signature::Request;
//! use signstar_request_signature::ssh::client::ConnectOptions;
//!
//! let client_pk =
//!     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHCXBJYlPPkrt2WYyP3SZoMx43lDBB5QALjE762EQlc";
//! let options = ConnectOptions::new("localhost".into(), 22, client_pk)?
//!     .append_known_hosts_from_file(known_hosts)?
//!     .agent_socket(std::env::var("SSH_AUTH_SOCK")?)
//!     .user("signstar");
//!
//! let mut session = options.connect().await?;
//! let request = Request::for_file("package")?;
//! let response = session.send(&request).await?;
//! // process response
//! #     Ok(()) }
//! ```
use std::collections::HashMap;
use std::fs::File;
use std::io::{ErrorKind, Read as _};
use std::path::Path;
use std::str::FromStr;
use std::{path::PathBuf, sync::Arc, time::Duration};

use rand::{Rng, thread_rng};
use russh::client::AuthResult;
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::known_hosts::Entry;
use russh::keys::ssh_key::{HashAlg, KnownHosts, PublicKey};
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
        status_code: u32,
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
pub const DEFAULT_CONFIG: &str = "usr/share/signstar/request-signature.toml";

/// The override config file below "/run/".
pub const RUN_OVERRIDE_CONFIG: &str = "run/signstar/request-signature.toml";

/// The override config file below "/etc/".
pub const ETC_OVERRIDE_CONFIG: &str = "etc/signstar/request-signature.toml";

/// The order of configuration files.
///
/// The following files are inspected, in descending priority:
/// - `/etc/signstar/request-signature.toml`
/// - `/run/signstar/request-signature.toml`
/// - `/usr/share/signstar/request-signature.toml`
pub const CONFIG_ORDER: &[&str] = &[ETC_OVERRIDE_CONFIG, RUN_OVERRIDE_CONFIG, DEFAULT_CONFIG];

/// Connection configuration for sending a signature request.
///
/// The configuration tracks a list of all valid targets for connecting.
#[derive(Debug, Default, Deserialize, garde::Validate)]
pub struct ConnectConfig {
    #[garde(
        custom(validate_ssh_public_key_consistency),
        custom(validate_agent_socket_consistency),
        custom(validate_known_hosts_consistency),
        custom(validate_host_port_uniqueness)
    )]
    targets: Vec<ConnectOptions>,
}

impl ConnectConfig {
    /// Appends connection options to the list of targets.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn sign() -> testresult::TestResult {
    /// use signstar_request_signature::ssh::client::{ConnectConfig, ConnectOptions};
    ///
    /// let local_target = ConnectOptions::new("localhost".into(), 22, "ssh-ed25519 ...")?;
    /// let config = ConnectConfig::default().append_target(local_target);
    /// # Ok(()) }
    /// ```
    pub fn append_target(mut self, target: ConnectOptions) -> Self {
        self.targets.push(target);
        self
    }

    /// Connects to a random target over SSH and returns a [`Session`] object.
    ///
    /// This function sets up an authenticated, bidirectional channel
    /// between the client and the server. No signing requests are exchanged at this point but any
    /// number of them can be issued later using [`Session::send`] function.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn sign() -> testresult::TestResult {
    /// use signstar_request_signature::ssh::client::{ConnectConfig, ConnectOptions};
    ///
    /// let local_target = ConnectOptions::new("localhost".into(), 22, "ssh-ed25519 ...")?;
    /// let config = ConnectConfig::default().append_target(local_target);
    ///
    /// let mut session = config.connect(None).await?;
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
    /// - an SSH protocol error is encountered,
    /// - the list of targets is empty.
    pub async fn connect(self, user: Option<&str>) -> Result<Session> {
        let targets = self.targets;
        if user.is_none() && targets.len() > 1 {
            return Err(Error::InvalidOptions(
                "no user specified and there are multiple targets".into(),
            ));
        }
        let targets = targets
            .into_iter()
            .filter(|target| user.is_none_or(|user| target.user == user))
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Err(Error::InvalidOptions("no targets specified".into()));
        }
        let index = thread_rng().gen_range(0..targets.len());
        let target = {
            let mut targets = targets;
            targets.remove(index)
        };

        target.connect().await
    }

    /// Reads and returns the contents of the configuration file.
    ///
    /// If the `path` parameter is set then it has the highest precedence, otherwise [configuration
    /// paths][`CONFIG_ORDER`] are checked in that order.
    ///
    /// # Errors
    ///
    /// Returns an error ([`Error::Io`]) if reading the config fails or no configuration files exist
    /// ([`crate::Error::ConfigMissing`]).
    pub fn read_config_file(
        root: impl AsRef<Path>,
        path: Option<PathBuf>,
    ) -> std::result::Result<Self, crate::Error> {
        let root = root.as_ref();
        let candidates = path.into_iter().chain(CONFIG_ORDER.iter().map(Into::into));
        for file in candidates {
            let file = root.join(file);
            match File::open(&file) {
                Ok(mut reader) => {
                    let mut buf = vec![];
                    reader
                        .read_to_end(&mut buf)
                        .map_err(|source| Error::Io { file, source })?;
                    return Ok(toml::from_slice(&buf)?);
                }
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(crate::Error::Io { file, source });
                }
            }
        }
        Err(crate::Error::ConfigMissing)
    }
}

/// Validates if the following condition holds: The SSH public key used for a user cannot be used
/// for another user.
fn validate_ssh_public_key_consistency(
    connect_options: &[ConnectOptions],
    _context: &(),
) -> garde::Result {
    for connect_option in connect_options {
        let pk = &connect_option.user_public_key;
        let user = &connect_option.user;
        if let Some(conflicting_option) = connect_options.iter().find(|connect_option| {
            &connect_option.user_public_key == pk && &connect_option.user != user
        }) {
            return Err(garde::Error::new(format!(
                "The SSH public key used for a user cannot be used for another user:\nFirst: {connect_option:?}\nSecond: {conflicting_option:?}"
            )));
        }
    }

    Ok(())
}

/// Validates if the following condition holds: The SSH agent socket location should not be allowed
/// to differ for different target host:port combinations of the same user.
fn validate_agent_socket_consistency(
    connect_options: &[ConnectOptions],
    _context: &(),
) -> garde::Result {
    for connect_option in connect_options {
        let agent_socket = &connect_option.agent_socket;
        let host = &connect_option.host;
        let port = connect_option.port;
        let user = &connect_option.user;
        if let Some(conflicting_option) = connect_options.iter().find(|connect_option| {
            &connect_option.user == user
                && (&connect_option.host != host || connect_option.port != port)
                && &connect_option.agent_socket != agent_socket
        }) {
            return Err(garde::Error::new(format!(
                "The SSH agent socket location should not differ for different target host:port combinations of the same user:\nFirst: {connect_option:?}\nSecond: {conflicting_option:?}"
            )));
        }
    }

    Ok(())
}

/// Validates if the following condition holds: The `known_hosts` entries should be unique per
/// host:port combinations of the same user.
fn validate_known_hosts_consistency(
    connect_options: &[ConnectOptions],
    _context: &(),
) -> garde::Result {
    for connect_option in connect_options {
        let host = &connect_option.host;
        let port = connect_option.port;
        let user = &connect_option.user;
        for known_host_entry in &connect_option.known_hosts {
            if let Some(conflicting_option) = connect_options.iter().find(|connect_option| {
                &connect_option.user == user
                    && (&connect_option.host != host || connect_option.port != port)
                    && connect_option.known_hosts.contains(known_host_entry)
            }) {
                return Err(garde::Error::new(format!(
                    "The known host entry {known_host_entry:?} is present in two different host:port combinations:\nFirst: {connect_option:?}\nSecond: {conflicting_option:?}"
                )));
            }
        }
    }

    Ok(())
}

/// Validates if the following condition holds: Each host:port combination should be unique.
fn validate_host_port_uniqueness(
    connect_options: &[ConnectOptions],
    _context: &(),
) -> garde::Result {
    let mut host_ports = HashMap::new();
    for connect_option in connect_options {
        let host_port = (&connect_option.host, connect_option.port);
        if let Some(conflicting_option) = host_ports.get(&host_port) {
            return Err(garde::Error::new(format!(
                "Two connections have the same host:port combination:\nFirst: {connect_option:?}\nSecond: {conflicting_option:?}"
            )));
        }
        host_ports.insert(host_port, connect_option);
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
/// let options = ConnectOptions::new("localhost".into(), 22, "ssh-ed25519 ...")?
///     .append_known_hosts_from_file("/home/user/.ssh/known_hosts")?
///     .agent_socket(std::env::var("SSH_AUTH_SOCK")?)
///     .user("signstar");
/// # Ok(()) }
/// ```
#[derive(Debug, Deserialize)]
pub struct ConnectOptions {
    #[serde(deserialize_with = "deserialize_entries")]
    known_hosts: Vec<Entry>,

    agent_socket: PathBuf,

    user_public_key: PublicKey,

    user: String,

    host: String,

    port: u16,
}

impl ConnectOptions {
    /// Adds known hosts from a file containing data in the [SSH `known_hosts` file format].
    ///
    /// # Errors
    ///
    /// Returns an error if the file is badly formatted or reading the file fails.
    ///
    /// [SSH `known_hosts` file format]: https://man.archlinux.org/man/core/openssh/sshd.8.en#SSH_KNOWN_HOSTS_FILE_FORMAT
    pub fn append_known_hosts_from_file(
        mut self,
        known_hosts_file: impl AsRef<Path>,
    ) -> Result<Self> {
        let known_hosts_file = known_hosts_file.as_ref();
        let input = std::fs::read_to_string(known_hosts_file).map_err(|source| Error::Io {
            file: known_hosts_file.to_path_buf(),
            source,
        })?;
        self.known_hosts.extend(KnownHosts::new(&input).flatten());
        Ok(self)
    }

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
    /// let options = ConnectOptions::new("localhost".into(), 22, client_pk)?.user("signstar");
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

    /// Sets the username on the remote host for the client.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// Constructs a new [`ConnectOptions`] with target host and client public key.
    pub fn new(host: String, port: u16, client_auth_public_key: impl AsRef<str>) -> Result<Self> {
        let client_auth_public_key = PublicKey::from_openssh(client_auth_public_key.as_ref())
            .map_err(russh::keys::Error::SshKey)?;
        Ok(Self {
            host,
            port,
            known_hosts: Default::default(),
            agent_socket: Default::default(),
            user_public_key: client_auth_public_key,
            user: Default::default(),
        })
    }

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
    /// use signstar_request_signature::ssh::client::ConnectOptions;
    ///
    /// let options = ConnectOptions::new("localhost".into(), 22, "ssh-ed25519 ...")?;
    ///
    /// let mut session = options.connect().await?;
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
    pub async fn connect(self) -> Result<Session> {
        let client_auth_public_key = self.user_public_key;

        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        });

        let stream = UnixStream::connect(&self.agent_socket)
            .await
            .map_err(|source| Error::Io {
                file: self.agent_socket,
                source,
            })?;
        let mut future = AgentClient::connect(stream);
        let mut session = client::connect(
            config,
            (self.host.clone(), self.port),
            KeyValidator {
                host: self.host.clone(),
                port: self.port,
                entries: self.known_hosts,
            },
        )
        .await?;
        let auth_res = session
            .authenticate_publickey_with(
                self.user,
                client_auth_public_key,
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
            host: self.host,
            port: self.port,
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
    /// use signstar_request_signature::ssh::client::ConnectOptions;
    ///
    /// let options = ConnectOptions::new("localhost".into(), 22, "ssh-ed25519 ...")?;
    ///
    /// let mut session = options.connect().await?;
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
            if code != 0 {
                Err(Error::RemoteApplicationFailure { status_code: code })
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
    /// use signstar_request_signature::ssh::client::ConnectOptions;
    ///
    /// let options = ConnectOptions::target("localhost".into(), 22);
    ///
    /// let mut session = options.connect().await?;
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
    use std::{assert_matches, fs::write};

    use garde::Validate;
    use insta::assert_snapshot;
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn parsing_config() -> TestResult {
        let config = r#"host = "127.0.0.1"
port = 2222
user = "signstar-sign"
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]
"#;
        let _: ConnectOptions = toml::from_str(config)?;
        Ok(())
    }

    #[test]
    fn parsing_config_broken_key() -> TestResult {
        let config = r#"host = "127.0.0.1"
port = 2222
user = "signstar-sign"
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 broken"
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]
"#;
        let result: std::result::Result<ConnectOptions, _> = toml::from_str(config);
        let Err(e) = result else {
            panic!("Result was OK when expecting an error");
        };

        let error_msg = e.to_string();
        assert_snapshot!(error_msg);
        Ok(())
    }

    #[test]
    fn parsing_config_known_hosts_bad_format_string_literal() -> TestResult {
        let config = r#"host = "127.0.0.1"
port = 2222
user = "signstar-sign"
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
known_hosts = [yes]
"#;
        let result: std::result::Result<ConnectOptions, _> = toml::from_str(config);
        let Err(e) = result else {
            panic!("Result was OK when expecting an error");
        };

        let error_msg = e.to_string();
        assert_snapshot!(error_msg);
        Ok(())
    }

    #[test]
    fn parsing_config_known_hosts_bad_format_number() -> TestResult {
        let config = r#"host = "127.0.0.1"
port = 2222
user = "signstar-sign"
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
known_hosts = [42]
"#;
        let result: std::result::Result<ConnectOptions, _> = toml::from_str(config);
        let Err(e) = result else {
            panic!("Result was OK when expecting an error");
        };

        let error_msg = e.to_string();
        assert_snapshot!(error_msg);
        Ok(())
    }

    #[test]
    fn reading_missing_config() {
        assert_matches!(
            ConnectConfig::read_config_file("", None),
            Err(crate::Error::ConfigMissing)
        );
    }

    /// Creates directory hierarchy for `usr`, `etc` and `run` subdirectories within a `root`
    /// directory.
    fn create_test_hierarchy(root: impl AsRef<Path>) -> TestResult {
        let root = root.as_ref();
        let etc = root.join(ETC_OVERRIDE_CONFIG);
        let etc_dir = etc
            .parent()
            .expect("etc config override to have a parent dir");
        std::fs::create_dir_all(etc_dir)?;

        let usr = root.join(DEFAULT_CONFIG);
        let usr_dir = usr
            .parent()
            .expect("usr config override to have a parent dir");
        std::fs::create_dir_all(usr_dir)?;

        let run = root.join(RUN_OVERRIDE_CONFIG);
        let run_dir = run
            .parent()
            .expect("run config override to have a parent dir");
        std::fs::create_dir_all(run_dir)?;
        Ok(())
    }

    #[rstest]
    #[case::etc(ETC_OVERRIDE_CONFIG)]
    #[case::usr(DEFAULT_CONFIG)]
    #[case::run(RUN_OVERRIDE_CONFIG)]
    fn reading_single_location_config(#[case] subdir: &str) -> TestResult {
        let root = tempfile::tempdir()?;
        create_test_hierarchy(&root)?;
        let config_file = root.as_ref().join(subdir);

        let config = r#"[[targets]]
host = "127.0.0.1"
port = 2222
user = "signstar-sign"
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]
"#;
        write(config_file, config)?;
        let config = ConnectConfig::read_config_file(root, None)?;
        assert_eq!(1, config.targets.len());
        assert_eq!("signstar-sign", config.targets[0].user);
        Ok(())
    }

    const ETC_CONFIG: &str = r#"[[targets]]
host = "127.0.0.1"
port = 2222
user = "signstar-sign-etc"
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]
"#;

    const USR_CONFIG: &str = r#"[[targets]]
host = "127.0.0.1"
port = 2222
user = "signstar-sign-usr"
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]
"#;

    const RUN_CONFIG: &str = r#"[[targets]]
host = "127.0.0.1"
port = 2222
user = "signstar-sign-run"
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]
"#;

    #[test]
    fn reading_all_locations() -> TestResult {
        let root = tempfile::tempdir()?;
        create_test_hierarchy(&root)?;

        write(root.as_ref().join(ETC_OVERRIDE_CONFIG), ETC_CONFIG)?;
        write(root.as_ref().join(RUN_OVERRIDE_CONFIG), RUN_CONFIG)?;
        write(root.as_ref().join(DEFAULT_CONFIG), USR_CONFIG)?;

        let config = ConnectConfig::read_config_file(root, None)?;
        assert_eq!(1, config.targets.len());
        assert_eq!("signstar-sign-etc", config.targets[0].user);
        Ok(())
    }

    #[test]
    fn override_usr_with_run() -> TestResult {
        let root = tempfile::tempdir()?;
        create_test_hierarchy(&root)?;

        write(root.as_ref().join(RUN_OVERRIDE_CONFIG), RUN_CONFIG)?;
        write(root.as_ref().join(DEFAULT_CONFIG), USR_CONFIG)?;

        let config = ConnectConfig::read_config_file(root, None)?;
        assert_eq!(1, config.targets.len());
        assert_eq!("signstar-sign-run", config.targets[0].user);
        Ok(())
    }

    #[test]
    fn override_usr_with_etc() -> TestResult {
        let root = tempfile::tempdir()?;
        create_test_hierarchy(&root)?;

        write(root.as_ref().join(ETC_OVERRIDE_CONFIG), ETC_CONFIG)?;
        write(root.as_ref().join(DEFAULT_CONFIG), USR_CONFIG)?;

        let config = ConnectConfig::read_config_file(root, None)?;
        assert_eq!(1, config.targets.len());
        assert_eq!("signstar-sign-etc", config.targets[0].user);
        Ok(())
    }

    #[test]
    fn override_run_with_etc() -> TestResult {
        let root = tempfile::tempdir()?;
        create_test_hierarchy(&root)?;

        write(root.as_ref().join(ETC_OVERRIDE_CONFIG), ETC_CONFIG)?;
        write(root.as_ref().join(RUN_OVERRIDE_CONFIG), RUN_CONFIG)?;

        let config = ConnectConfig::read_config_file(root, None)?;
        assert_eq!(1, config.targets.len());
        assert_eq!("signstar-sign-etc", config.targets[0].user);
        Ok(())
    }

    #[test]
    fn mask_etc() -> TestResult {
        let root = tempfile::tempdir()?;
        create_test_hierarchy(&root)?;

        // empty /etc/ masks other configurations
        write(root.as_ref().join(ETC_OVERRIDE_CONFIG), "")?;
        write(root.as_ref().join(RUN_OVERRIDE_CONFIG), RUN_CONFIG)?;
        write(root.as_ref().join(DEFAULT_CONFIG), USR_CONFIG)?;

        // but the targets field is required so it returns an error
        assert_matches!(
            ConnectConfig::read_config_file(root, None),
            Err(crate::Error::Toml(_))
        );
        Ok(())
    }

    #[test]
    fn mask_run() -> TestResult {
        let root = tempfile::tempdir()?;
        create_test_hierarchy(&root)?;

        write(root.as_ref().join(ETC_OVERRIDE_CONFIG), ETC_CONFIG)?;
        // masking /run
        write(root.as_ref().join(RUN_OVERRIDE_CONFIG), "")?;
        write(root.as_ref().join(DEFAULT_CONFIG), USR_CONFIG)?;

        // etc still takes precedence
        let config = ConnectConfig::read_config_file(root, None)?;
        assert_eq!(1, config.targets.len());
        assert_eq!("signstar-sign-etc", config.targets[0].user);
        Ok(())
    }

    #[test]
    fn mask_run_no_etc() -> TestResult {
        let root = tempfile::tempdir()?;
        create_test_hierarchy(&root)?;

        // empty /run/ masks /usr
        write(root.as_ref().join(RUN_OVERRIDE_CONFIG), "")?;
        write(root.as_ref().join(DEFAULT_CONFIG), USR_CONFIG)?;

        // but the targets field is required so it returns an error
        assert_matches!(
            ConnectConfig::read_config_file(root, None),
            Err(crate::Error::Toml(_))
        );
        Ok(())
    }

    #[test]
    fn validate_success() -> TestResult {
        let config = ConnectConfig {
                targets: vec![ConnectOptions::new(
                    "test".into(),
                    1234,
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?.user("test-user"),]
            };

        config.validate()?;

        Ok(())
    }

    #[test]
    fn validate_ssh_public_key_cannot_be_reused() -> TestResult {
        let config = ConnectConfig {
            targets: vec![ConnectOptions::new(
                "test".into(),
                1234,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
            )?.user("test-user"),
            ConnectOptions::new(
                "test".into(),
                1235,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
            )?.user("test-user2")],
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
    fn validate_agent_socket_should_not_differ_for_different_target() -> TestResult {
        let config = ConnectConfig {
                targets: vec![ConnectOptions::new(
                    "test1".into(),
                    1234,
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?.user("test-user").agent_socket("/tmp/a"),
                ConnectOptions::new(
                    "test2".into(),
                    1234,
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?.user("test-user").agent_socket("/tmp/b")
                ],
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
        let first_option = {
            let mut option = ConnectOptions::new(
                "test1".into(),
                1234,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
            )?
            .user("test-user");
            option.known_hosts.push(Entry::from_str("test1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd")?);
            option
        };
        let second_option = {
            let mut option = ConnectOptions::new(
                "test2".into(),
                1234,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
            )?
            .user("test-user");
            option.known_hosts.push(Entry::from_str("test1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd")?);
            option
        };
        let config = ConnectConfig {
            targets: vec![first_option, second_option],
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
                targets: vec![ConnectOptions::new(
                    "test1".into(),
                    1234,
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?.user("test-user").agent_socket("/tmp/a"),
                ConnectOptions::new(
                    "test1".into(),
                    1234,
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp",
                )?.user("test-user").agent_socket("/tmp/b")
                ],
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
