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
//! let options = ConnectOptions::target("localhost".into(), 22)
//!     .append_known_hosts_from_file(known_hosts)?
//!     .client_auth_agent_sock(std::env::var("SSH_AUTH_SOCK")?)
//!     .client_auth_public_key(
//!         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHCXBJYlPPkrt2WYyP3SZoMx43lDBB5QALjE762EQlc",
//!     )?
//!     .user("signstar");
//!
//! let mut session = options.connect().await?;
//! let request = Request::for_file("package")?;
//! let response = session.send(&request).await?;
//! // process response
//! #     Ok(()) }
//! ```
use std::path::Path;
use std::{path::PathBuf, sync::Arc, time::Duration};

use russh::client::AuthResult;
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::known_hosts::Entry;
use russh::keys::ssh_key::{HashAlg, KnownHosts, PublicKey};
use russh::{ChannelMsg, Disconnect, MethodSet, client};
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
/// let options = ConnectOptions::target("localhost".into(), 22)
///     .append_known_hosts_from_file("/home/user/.ssh/known_hosts")?
///     .client_auth_agent_sock(std::env::var("SSH_AUTH_SOCK")?)
///     .client_auth_public_key("ssh-ed25519 ...")?
///     .user("signstar");
/// # Ok(()) }
/// ```
#[derive(Debug, Default)]
pub struct ConnectOptions {
    known_hosts: Vec<Entry>,

    client_auth_agent_sock: PathBuf,

    client_auth_public_key: Option<PublicKey>,

    user: String,

    hostname: String,

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
    pub fn client_auth_agent_sock(mut self, agent_sock: impl Into<PathBuf>) -> Self {
        self.client_auth_agent_sock = agent_sock.into();
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
    /// let options = ConnectOptions::target("localhost".into(), 22)
    ///     .client_auth_public_key(
    ///         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHCXBJYlPPkrt2WYyP3SZoMx43lDBB5QALjE762EQlc",
    ///     )?
    ///     .user("signstar");
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
    pub fn client_auth_public_key(mut self, public_key: impl Into<String>) -> Result<Self> {
        self.client_auth_public_key =
            Some(PublicKey::from_openssh(&public_key.into()).map_err(russh::keys::Error::SshKey)?);
        Ok(self)
    }

    /// Sets the username on the remote host for the client.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// Sets the target host and a port number to use when connecting.
    pub fn target(hostname: String, port: u16) -> Self {
        Self {
            hostname,
            port,
            known_hosts: Default::default(),
            client_auth_agent_sock: Default::default(),
            client_auth_public_key: Default::default(),
            user: Default::default(),
        }
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
    /// let options = ConnectOptions::target("localhost".into(), 22);
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
        let Some(client_auth_public_key) = self.client_auth_public_key else {
            return Err(Error::InvalidOptions(
                "Public key for client authentication has not been set but is required.".into(),
            ));
        };

        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        });

        let stream = UnixStream::connect(&self.client_auth_agent_sock)
            .await
            .map_err(|source| Error::Io {
                file: self.client_auth_agent_sock,
                source,
            })?;
        let mut future = AgentClient::connect(stream);
        let mut session = client::connect(
            config,
            (self.hostname.clone(), self.port),
            KeyValidator {
                host: self.hostname.clone(),
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
            host: self.hostname,
            port: self.port,
        })
    }
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
    /// let options = ConnectOptions::target("localhost".into(), 22);
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
