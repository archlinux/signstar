//! [`SignstarConfig`] for _Signstar hosts_.

use std::{
    collections::HashSet,
    fs::{File, create_dir_all, read_to_string},
    io::Write,
    path::Path,
};

#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::{Connection, NamespaceId};
use serde::{Deserialize, Serialize};
use signstar_common::config::{get_config_file, get_run_override_config_file_path};

use crate::{
    ConfigError as Error,
    SystemUserId,
    config::mapping::{ExtendedUserMapping, UserMapping},
};

/// The handling of administrative secrets.
///
/// Administrative secrets may be handled in different ways (e.g. persistent or non-persistent).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdministrativeSecretHandling {
    /// The administrative secrets are handled in a plaintext file in a non-volatile directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of unencrypted administrative secrets on a file system.
    Plaintext,

    /// The administrative secrets are handled in a file encrypted using [systemd-creds] in a
    /// non-volatile directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of (host-specific) encrypted administrative secrets on a file system, that
    /// could be extracted if the host is compromised.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    SystemdCreds,

    /// The administrative secrets are handled using [Shamir's Secret Sharing] (SSS).
    ///
    /// This variant is the default for production use, as the administrative secrets are only ever
    /// exposed on a volatile filesystem for the time of their use.
    /// The secrets are only made available to the system as shares of a shared secret, split using
    /// SSS.
    /// This way no holder of a share is aware of the administrative secrets and the system only
    /// for as long as it needs to use the administrative secrets.
    ///
    /// [Shamir's Secret Sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
    #[default]
    ShamirsSecretSharing,
}

/// The handling of non-administrative secrets.
///
/// Non-administrative secrets represent passphrases for (non-Administrator) NetHSM users and may be
/// handled in different ways (e.g. encrypted or not encrypted).
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    Eq,
    PartialEq,
    Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum NonAdministrativeSecretHandling {
    /// Each non-administrative secret is handled in a plaintext file in a non-volatile
    /// directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of unencrypted non-administrative secrets on a file system.
    Plaintext,

    /// Each non-administrative secret is encrypted for a specific system user using
    /// [systemd-creds] and the resulting files are stored in a non-volatile directory.
    ///
    /// ## Note
    ///
    /// Although secrets are stored as encrypted strings in dedicated files, they may be extracted
    /// under certain circumstances:
    ///
    /// - the root account is compromised
    ///   - decrypts and exfiltrates _all_ secrets
    ///   - the secret is not encrypted using a [TPM] and the file
    ///     `/var/lib/systemd/credential.secret` as well as _any_ encrypted secret is exfiltrated
    /// - a specific user is compromised, decrypts and exfiltrates its own secret
    ///
    /// It is therefore crucial to follow common best-practices:
    ///
    /// - rely on a [TPM] for encrypting secrets, so that files become host-specific
    /// - heavily guard access to all users, especially root
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    /// [TPM]: https://en.wikipedia.org/wiki/Trusted_Platform_Module
    #[default]
    SystemdCreds,
}

/// A connection to an HSM backend.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum BackendConnection {
    /// The [`Connection`] for a [`NetHsm`] backend.
    #[serde(rename = "nethsm")]
    NetHsm(Connection),
}

/// A configuration for parallel use of connections with a set of system and NetHSM users.
///
/// This configuration type is meant to be used in a read-only fashion and does not support tracking
/// the passphrases for users.
/// As such, it is useful for tools, that create system users, as well as NetHSM users and keys
/// according to it.
///
/// Various mappings of system and NetHSM users exist, that are defined by the variants of
/// [`UserMapping`].
///
/// Some system users require providing SSH authorized key(s), while others do not allow that at
/// all.
/// NetHSM users can be added in namespaces, or system-wide, depending on their use-case.
/// System and NetHSM users must be unique.
///
/// Key IDs must be unique per namespace or system-wide (depending on where they are used).
/// Tags, used to provide access to keys for NetHSM users must be unique per namespace or
/// system-wide (depending on in which scope the user and key are used)
///
/// # Examples
///
/// The below example provides a fully functional TOML configuration, outlining all available
/// functionalities.
///
/// ```
/// # use std::io::Write;
/// #
/// # use signstar_config::{SignstarConfig};
/// #
/// # fn main() -> testresult::TestResult {
/// # let config_file = testdir::testdir!().join("signstar_config_example.conf");
/// # {
/// let config_string = r#"
/// ## A non-negative integer, that describes the iteration of the configuration.
/// ## The iteration should only ever be increased between changes to the config and only under the circumstance,
/// ## that user mappings are removed and should also be removed from the state of the system making use of this
/// ## configuration.
/// ## Applications reading the configuration are thereby enabled to compare existing state on the system with the
/// ## current iteration and remove user mappings and accompanying data accordingly.
/// iteration = 1
///
/// ## The handling of administrative secrets on the system.
/// ## One of:
/// ## - "shamirs-secret-sharing": Administrative secrets are never persisted on the system and only provided as shares of a shared secret.
/// ## - "systemd-creds": Administrative secrets are persisted on the system as host-specific files, encrypted using systemd-creds (only for testing).
/// ## - "plaintext": Administrative secrets are persisted on the system in unencrypted plaintext files (only for testing).
/// admin_secret_handling = "shamirs-secret-sharing"
///
/// ## The handling of non-administrative secrets on the system.
/// ## One of:
/// ## - "systemd-creds": Non-administrative secrets are persisted on the system as host-specific files, encrypted using systemd-creds (the default).
/// ## - "plaintext": Non-administrative secrets are persisted on the system in unencrypted plaintext files (only for testing).
/// non_admin_secret_handling = "systemd-creds"
///
/// [[connections]]
/// nethsm = { url = "https://localhost:8443/api/v1/", tls_security = "Unsafe" }
///
/// ## The NetHSM user "admin" is a system-wide Administrator
/// [[users]]
/// nethsm_only_admin = "admin"
///
/// ## The SSH-accessible system user "ssh-backup1" is used in conjunction with
/// ## the NetHSM user "backup1" (system-wide Backup)
/// [[users]]
///
/// [users.system_nethsm_backup]
/// nethsm_user = "backup1"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host"
/// system_user = "ssh-backup1"
///
/// ## The SSH-accessible system user "ssh-metrics1" is used with several NetHSM users:
/// ## - "metrics1" (system-wide Metrics)
/// ## - "keymetrics1" (system-wide Operator)
/// ## - "ns1~keymetrics1" (namespace Operator)
/// [[users]]
///
/// [users.system_nethsm_metrics]
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host"
/// system_user = "ssh-metrics1"
///
/// [users.system_nethsm_metrics.nethsm_users]
/// metrics_user = "metrics1"
/// operator_users = ["keymetrics1", "ns1~keymetrics1"]
///
/// ## The SSH-accessible system user "ssh-operator1" is used in conjunction with
/// ## the NetHSM user "operator1" (system-wide Operator).
/// ## User "operator1" shares tag "tag1" with key "key1" and can therefore use it
/// ## (for OpenPGP signing).
/// [[users]]
///
/// [users.system_nethsm_operator_signing]
/// nethsm_user = "operator1"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host"
/// system_user = "ssh-operator1"
/// tag = "tag1"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup]
/// key_id = "key1"
/// key_type = "Curve25519"
/// key_mechanisms = ["EdDsaSignature"]
/// signature_type = "EdDsa"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
/// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
/// version = "4"
///
/// ## The SSH-accessible system user "ssh-operator2" is used in conjunction with
/// ## the NetHSM user "operator2" (system-wide Operator).
/// ## User "operator2" shares tag "tag2" with key "key2" and can therefore use it
/// ## (for OpenPGP signing).
/// [[users]]
///
/// [users.system_nethsm_operator_signing]
/// nethsm_user = "operator2"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host"
/// system_user = "ssh-operator2"
/// tag = "tag2"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup]
/// key_id = "key2"
/// key_type = "Curve25519"
/// key_mechanisms = ["EdDsaSignature"]
/// signature_type = "EdDsa"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
/// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
/// version = "4"
///
/// ## The NetHSM user "ns1~admin" is a namespace Administrator
/// [[users]]
/// nethsm_only_admin = "ns1~admin"
///
/// ## The SSH-accessible system user "ns1-ssh-operator1" is used in conjunction with
/// ## the NetHSM user "ns1~operator1" (namespace Operator).
/// ## User "ns1~operator1" shares tag "tag1" with key "key1" and can therefore use it
/// ## in its namespace (for OpenPGP signing).
/// [[users]]
///
/// [users.system_nethsm_operator_signing]
/// nethsm_user = "ns1~operator1"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host"
/// system_user = "ns1-ssh-operator1"
/// tag = "tag1"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup]
/// key_id = "key1"
/// key_type = "Curve25519"
/// key_mechanisms = ["EdDsaSignature"]
/// signature_type = "EdDsa"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
/// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
/// version = "4"
///
/// ## The SSH-accessible system user "ns1-ssh-operator2" is used in conjunction with
/// ## the NetHSM user "ns2~operator1" (namespace Operator).
/// ## User "ns1~operator2" shares tag "tag2" with key "key1" and can therefore use it
/// ## in its namespace (for OpenPGP signing).
/// [[users]]
///
/// [users.system_nethsm_operator_signing]
/// nethsm_user = "ns1~operator2"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrIYA+bfMBThUP5lKbMFEHiytmcCPhpkGrB/85n0mAN user@host"
/// system_user = "ns1-ssh-operator2"
/// tag = "tag2"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup]
/// key_id = "key2"
/// key_type = "Curve25519"
/// key_mechanisms = ["EdDsaSignature"]
/// signature_type = "EdDsa"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
/// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
/// version = "4"
///
/// ## The hermetic system user "local-metrics1" is used with several NetHSM users:
/// ## - "metrics2" (system-wide Metrics)
/// ## - "keymetrics2" (system-wide Operator)
/// ## - "ns1~keymetrics2" (namespace Operator)
/// [[users]]
///
/// [users.hermetic_system_nethsm_metrics]
/// system_user = "local-metrics1"
///
/// [users.hermetic_system_nethsm_metrics.nethsm_users]
/// metrics_user = "metrics2"
/// operator_users = ["keymetrics2", "ns1~keymetrics2"]
///
/// ## The SSH-accessible system user "ssh-share-down" is used for the
/// ## download of shares of a shared secret (divided by Shamir's Secret Sharing).
/// [[users]]
///
/// [users.system_only_share_download]
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host"
/// system_user = "ssh-share-down"
///
/// ## The SSH-accessible system user "ssh-share-up" is used for the
/// ## upload of shares of a shared secret (divided by Shamir's Secret Sharing).
/// [[users]]
///
/// [users.system_only_share_upload]
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host"
/// system_user = "ssh-share-up"
///
/// ## The SSH-accessible system user "ssh-wireguard-down" is used for the
/// ## download of WireGuard configuration, used on the host.
/// [[users]]
///
/// [users.system_only_wireguard_download]
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host"
/// system_user = "ssh-wireguard-down"
/// "#;
/// #
/// #    let mut buffer = std::fs::File::create(&config_file)?;
/// #    buffer.write_all(config_string.as_bytes())?;
/// # }
/// # SignstarConfig::new_from_file(
/// #    Some(&config_file),
/// # )?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SignstarConfig {
    iteration: u32,
    admin_secret_handling: AdministrativeSecretHandling,
    non_admin_secret_handling: NonAdministrativeSecretHandling,
    connections: HashSet<BackendConnection>,
    users: HashSet<UserMapping>,
}

impl SignstarConfig {
    /// Creates a new [`SignstarConfig`] from an optional configuration file path.
    ///
    /// If no configuration file path is provided, attempts to return the first configuration file
    /// location found using [`get_config_file`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - no configuration file path is provided and [`get_config_file`] is unable to find any,
    /// - reading the contents of the configuration file to string fails,
    /// - deserializing the contents of the configuration file as a [`SignstarConfig`],
    /// - or the [`SignstarConfig`] fails to validate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::io::Write;
    ///
    /// use signstar_config::SignstarConfig;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let config_file = testdir::testdir!().join("signstar_config_new.conf");
    /// {
    ///     #[rustfmt::skip]
    ///     let config_string = r#"
    /// iteration = 1
    /// admin_secret_handling = "shamirs-secret-sharing"
    /// non_admin_secret_handling = "systemd-creds"
    /// [[connections]]
    /// nethsm = { url = "https://localhost:8443/api/v1/", tls_security = "Unsafe" }
    ///
    /// [[users]]
    /// nethsm_only_admin = "admin"
    ///
    /// [[users]]
    /// [users.system_nethsm_backup]
    /// nethsm_user = "backup1"
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host"
    /// system_user = "ssh-backup1"
    ///
    /// [[users]]
    ///
    /// [users.system_nethsm_metrics]
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host"
    /// system_user = "ssh-metrics1"
    ///
    /// [users.system_nethsm_metrics.nethsm_users]
    /// metrics_user = "metrics1"
    /// operator_users = ["operator1metrics1"]
    ///
    /// [[users]]
    /// [users.system_nethsm_operator_signing]
    /// nethsm_user = "operator1"
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host"
    /// system_user = "ssh-operator1"
    /// tag = "tag1"
    ///
    /// [users.system_nethsm_operator_signing.nethsm_key_setup]
    /// key_id = "key1"
    /// key_type = "Curve25519"
    /// key_mechanisms = ["EdDsaSignature"]
    /// signature_type = "EdDsa"
    ///
    /// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
    /// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
    /// version = "4"
    ///
    /// [[users]]
    /// [users.system_nethsm_operator_signing]
    /// nethsm_user = "operator2"
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host"
    /// system_user = "ssh-operator2"
    /// tag = "tag2"
    ///
    /// [users.system_nethsm_operator_signing.nethsm_key_setup]
    /// key_id = "key2"
    /// key_type = "Curve25519"
    /// key_mechanisms = ["EdDsaSignature"]
    /// signature_type = "EdDsa"
    ///
    /// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
    /// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
    /// version = "4"
    ///
    /// [[users]]
    ///
    /// [users.hermetic_system_nethsm_metrics]
    /// system_user = "local-metrics1"
    ///
    /// [users.hermetic_system_nethsm_metrics.nethsm_users]
    /// metrics_user = "metrics2"
    /// operator_users = ["operator2metrics1"]
    ///
    /// [[users]]
    /// [users.system_only_share_download]
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host"
    /// system_user = "ssh-share-down"
    ///
    /// [[users]]
    /// [users.system_only_share_upload]
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host"
    /// system_user = "ssh-share-up"
    ///
    /// [[users]]
    /// [users.system_only_wireguard_download]
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host"
    /// system_user = "ssh-wireguard-down"
    /// "#;
    ///     let mut buffer = std::fs::File::create(&config_file)?;
    ///     buffer.write_all(config_string.as_bytes())?;
    /// }
    /// SignstarConfig::new_from_file(Some(&config_file))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_from_file(path: Option<&Path>) -> Result<Self, crate::Error> {
        let path = if let Some(path) = path {
            path.to_path_buf()
        } else {
            let Some(path) = get_config_file() else {
                return Err(Error::ConfigIsMissing.into());
            };
            path
        };

        let config: Self =
            toml::from_str(
                &read_to_string(&path).map_err(|source| crate::Error::IoPath {
                    path: path.clone(),
                    context: "reading it to string",
                    source,
                })?,
            )
            .map_err(|source| crate::Error::TomlRead {
                path,
                context: "reading it as a Signstar config",
                source: Box::new(source),
            })?;
        config.validate()?;

        Ok(config)
    }

    /// Creates a new [`SignstarConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration file can not be loaded.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashSet;
    ///
    /// use nethsm::{Connection, UserRole};
    /// use signstar_config::{
    ///     AdministrativeSecretHandling,
    ///     BackendConnection,
    ///     SignstarConfig,
    ///     NonAdministrativeSecretHandling,
    ///     UserMapping,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// SignstarConfig::new(
    ///     1,
    ///     AdministrativeSecretHandling::ShamirsSecretSharing,
    ///     NonAdministrativeSecretHandling::SystemdCreds,
    ///     HashSet::from([BackendConnection::NetHsm(Connection::new(
    ///         "https://localhost:8443/api/v1/".parse()?,
    ///         "Unsafe".parse()?,
    ///     ))]),
    ///     HashSet::from([
    ///         UserMapping::NetHsmOnlyAdmin("admin".parse()?),
    ///         UserMapping::SystemOnlyShareDownload {
    ///             system_user: "ssh-share-down".parse()?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
    ///         },
    ///         UserMapping::SystemOnlyShareUpload {
    ///             system_user: "ssh-share-up".parse()?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
    ///         }]),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        iteration: u32,
        admin_secret_handling: AdministrativeSecretHandling,
        non_admin_secret_handling: NonAdministrativeSecretHandling,
        connections: HashSet<BackendConnection>,
        users: HashSet<UserMapping>,
    ) -> Result<Self, crate::Error> {
        let config = Self {
            iteration,
            admin_secret_handling,
            non_admin_secret_handling,
            connections,
            users,
        };
        config.validate()?;
        Ok(config)
    }

    /// Writes a [`SignstarConfig`] to file.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the parent directory for the configuration file cannot be created,
    /// - the configuration file cannot be created,
    /// - `self` cannot be serialized into a TOML string,
    /// - or the TOML string cannot be written to the configuration file.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashSet;
    ///
    /// use nethsm::{Connection,CryptographicKeyContext, OpenPgpUserIdList, SigningKeySetup, UserRole};
    /// use signstar_config::{
    ///     AdministrativeSecretHandling,
    ///     BackendConnection,
    ///     NetHsmMetricsUsers,
    ///     NonAdministrativeSecretHandling,
    ///     SignstarConfig,
    ///     UserMapping,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// let config = SignstarConfig::new(
    ///     1,
    ///     AdministrativeSecretHandling::ShamirsSecretSharing,
    ///     NonAdministrativeSecretHandling::SystemdCreds,
    ///     HashSet::from([BackendConnection::NetHsm(Connection::new(
    ///         "https://localhost:8443/api/v1/".parse()?,
    ///         "Unsafe".parse()?,
    ///     ))]),
    ///     HashSet::from([UserMapping::NetHsmOnlyAdmin("admin".parse()?),
    ///         UserMapping::SystemNetHsmBackup {
    ///             nethsm_user: "backup1".parse()?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
    ///             system_user: "ssh-backup1".parse()?,
    ///         },
    ///         UserMapping::SystemNetHsmMetrics {
    ///             nethsm_users: NetHsmMetricsUsers::new("metrics1".parse()?, vec!["operator2metrics1".parse()?])?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIioJ9uvAxUPunFh89T+ENo7OQerqHE8SQ+2v4VWbfUZ user@host".parse()?,
    ///             system_user: "ssh-metrics1".parse()?,
    ///         },
    ///         UserMapping::SystemNetHsmOperatorSigning {
    ///             nethsm_user: "operator1".parse()?,
    ///             nethsm_key_setup: SigningKeySetup::new(
    ///                 "key1".parse()?,
    ///                 "Curve25519".parse()?,
    ///                 vec!["EdDsaSignature".parse()?],
    ///                 None,
    ///                 "EdDsa".parse()?,
    ///                 CryptographicKeyContext::OpenPgp{
    ///                     user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
    ///                     version: "4".parse()?,
    ///                 })?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
    ///             system_user: "ssh-operator1".parse()?,
    ///             tag: "tag1".to_string(),
    ///         },
    ///         UserMapping::HermeticSystemNetHsmMetrics {
    ///             nethsm_users: NetHsmMetricsUsers::new("metrics2".parse()?, vec!["operator1metrics1".parse()?])?,
    ///             system_user: "local-metrics1".parse()?,
    ///         },
    ///         UserMapping::SystemOnlyShareDownload {
    ///             system_user: "ssh-share-down".parse()?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
    ///         },
    ///         UserMapping::SystemOnlyShareUpload {
    ///             system_user: "ssh-share-up".parse()?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
    ///         },
    ///         UserMapping::SystemOnlyWireGuardDownload {
    ///             system_user: "ssh-wireguard-down".parse()?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host".parse()?,
    ///         },
    ///     ]),
    /// )?;
    ///
    /// let config_file = testdir::testdir!().join("signstar_config_store.conf");
    /// config.store(Some(&config_file))?;
    /// # println!("{}", std::fs::read_to_string(&config_file)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn store(&self, path: Option<&Path>) -> Result<(), crate::Error> {
        let path = if let Some(path) = path {
            path.to_path_buf()
        } else {
            get_run_override_config_file_path()
        };

        if let Some(parent) = path.parent() {
            create_dir_all(parent).map_err(|source| crate::Error::IoPath {
                path: parent.to_path_buf(),
                context: "creating the parent directory for a Signstar configuration",
                source,
            })?;
        }
        let mut output = File::create(&path).map_err(|source| crate::Error::IoPath {
            path: path.clone(),
            context: "creating a Signstar configuration file",
            source,
        })?;

        write!(
            output,
            "{}",
            toml::to_string_pretty(self).map_err(|source| crate::Error::TomlWrite {
                path: path.clone(),
                context: "creating a Signstar configuration",
                source,
            })?
        )
        .map_err(|source| crate::Error::IoPath {
            path: path.clone(),
            context: "writing to the Signstar configuration file",
            source,
        })
    }

    /// Returns an Iterator over the available [`BackendConnection`]s.
    pub fn iter_connections(&self) -> impl Iterator<Item = &BackendConnection> {
        self.connections.iter()
    }

    /// Returns an Iterator over the available [`UserMapping`]s.
    pub fn iter_user_mappings(&self) -> impl Iterator<Item = &UserMapping> {
        self.users.iter()
    }

    /// Returns the iteration.
    pub fn get_iteration(&self) -> u32 {
        self.iteration
    }

    /// Returns the [`AdministrativeSecretHandling`].
    pub fn get_administrative_secret_handling(&self) -> AdministrativeSecretHandling {
        self.admin_secret_handling
    }

    /// Returns the [`NonAdministrativeSecretHandling`].
    pub fn get_non_administrative_secret_handling(&self) -> NonAdministrativeSecretHandling {
        self.non_admin_secret_handling
    }

    /// Returns an [`ExtendedUserMapping`] for a system user of `name` if it exists.
    ///
    /// Returns [`None`] if no user of `name` can is found.
    pub fn get_extended_mapping_for_user(&self, name: &str) -> Option<ExtendedUserMapping> {
        for user_mapping in self.users.iter() {
            if user_mapping
                .get_system_user()
                .is_some_and(|system_user| system_user.as_ref() == name)
            {
                return Some(ExtendedUserMapping::new(
                    self.admin_secret_handling,
                    self.non_admin_secret_handling,
                    self.connections.clone(),
                    user_mapping.clone(),
                ));
            }
        }
        None
    }

    /// Validates the components of the [`SignstarConfig`].
    fn validate(&self) -> Result<(), crate::Error> {
        // ensure there are no duplicate system users
        {
            let mut system_users = HashSet::new();
            for system_user_id in self
                .users
                .iter()
                .filter_map(|mapping| mapping.get_system_user())
            {
                if !system_users.insert(system_user_id.clone()) {
                    return Err(Error::DuplicateSystemUserId {
                        system_user_id: system_user_id.clone(),
                    }
                    .into());
                }
            }
        }

        // ensure there are no duplicate NetHsm users
        {
            let mut nethsm_users = HashSet::new();
            for nethsm_user_id in self
                .users
                .iter()
                .flat_map(|mapping| mapping.get_nethsm_users())
            {
                if !nethsm_users.insert(nethsm_user_id.clone()) {
                    return Err(Error::DuplicateNetHsmUserId {
                        nethsm_user_id: nethsm_user_id.clone(),
                    }
                    .into());
                }
            }
        }

        // ensure that there is at least one system-wide administrator
        if self
            .users
            .iter()
            .filter_map(|mapping| {
                if let UserMapping::NetHsmOnlyAdmin(user_id) = mapping {
                    if !user_id.is_namespaced() {
                        Some(user_id)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .next()
            .is_none()
        {
            return Err(Error::MissingAdministrator { namespaces: None }.into());
        }

        // ensure that there is an Administrator in each used namespace
        {
            // namespaces for all users, that are not in the Administrator role
            let namespaces_users = self
                .users
                .iter()
                .filter(|mapping| !matches!(mapping, UserMapping::NetHsmOnlyAdmin(_)))
                .flat_map(|mapping| mapping.get_nethsm_namespaces())
                .collect::<HashSet<NamespaceId>>();
            // namespaces for all users, that are in the Administrator role
            let namespaces_admins = self
                .users
                .iter()
                .filter(|mapping| matches!(mapping, UserMapping::NetHsmOnlyAdmin(_)))
                .flat_map(|mapping| mapping.get_nethsm_namespaces())
                .collect::<HashSet<NamespaceId>>();

            let namespaces = namespaces_users
                .difference(&namespaces_admins)
                .cloned()
                .collect::<Vec<NamespaceId>>();
            if !namespaces.is_empty() {
                return Err(Error::MissingAdministrator {
                    namespaces: Some(namespaces),
                }
                .into());
            }
        }

        if self.admin_secret_handling == AdministrativeSecretHandling::ShamirsSecretSharing {
            // ensure there is at least one system user for downloading shares of a shared
            // secret
            if !self
                .users
                .iter()
                .any(|mapping| matches!(mapping, UserMapping::SystemOnlyShareDownload { .. }))
            {
                return Err(Error::MissingShareDownloadSystemUser.into());
            }

            // ensure there is at least one system user for uploading shares of a shared secret
            if !self
                .users
                .iter()
                .any(|mapping| matches!(mapping, UserMapping::SystemOnlyShareUpload { .. }))
            {
                return Err(Error::MissingShareUploadSystemUser.into());
            }
        } else {
            // ensure there is no system user setup for uploading or downloading of shares of a
            // shared secret
            let share_users: Vec<SystemUserId> = self
                .users
                .iter()
                .filter_map(|mapping| match mapping {
                    UserMapping::SystemOnlyShareUpload {
                        system_user,
                        ssh_authorized_key: _,
                    }
                    | UserMapping::SystemOnlyShareDownload {
                        system_user,
                        ssh_authorized_key: _,
                    } => Some(system_user.clone()),
                    _ => None,
                })
                .collect();
            if !share_users.is_empty() {
                return Err(Error::NoSssButShareUsers { share_users }.into());
            }
        }

        // ensure there are no duplicate authorized SSH keys in the set of uploading shareholders
        // and the rest (minus downloading shareholders)
        {
            let mut public_keys = HashSet::new();
            for ssh_authorized_key in self
                .users
                .iter()
                .filter(|mapping| {
                    !matches!(
                        mapping,
                        UserMapping::SystemOnlyShareDownload {
                            system_user: _,
                            ssh_authorized_key: _,
                        }
                    )
                })
                .flat_map(|mapping| mapping.get_ssh_authorized_key())
                // we know a valid Entry can be created from AuthorizedKeyEntry, because its
                // constructor ensures it, hence we discard Errors
                .filter_map(|authorized_key| {
                    ssh_key::authorized_keys::Entry::try_from(authorized_key).ok()
                })
            {
                if !public_keys.insert(ssh_authorized_key.public_key().clone()) {
                    return Err(Error::DuplicateSshPublicKey {
                        ssh_public_key: ssh_authorized_key.public_key().to_string(),
                    }
                    .into());
                }
            }
        }

        // ensure there are no duplicate authorized SSH keys in the set of downloading shareholders
        // and the rest (minus uploading shareholders)
        {
            let mut public_keys = HashSet::new();
            for ssh_authorized_key in self
                .users
                .iter()
                .filter(|mapping| {
                    !matches!(
                        mapping,
                        UserMapping::SystemOnlyShareUpload {
                            system_user: _,
                            ssh_authorized_key: _,
                        }
                    )
                })
                .flat_map(|mapping| mapping.get_ssh_authorized_key())
                // we know a valid Entry can be created from AuthorizedKeyEntry, because its
                // constructor ensures it, hence we discard Errors
                .filter_map(|authorized_key| {
                    ssh_key::authorized_keys::Entry::try_from(authorized_key).ok()
                })
            {
                if !public_keys.insert(ssh_authorized_key.public_key().clone()) {
                    return Err(Error::DuplicateSshPublicKey {
                        ssh_public_key: ssh_authorized_key.public_key().to_string(),
                    }
                    .into());
                }
            }
        }

        // ensure that only one-to-one relationships between users in the Operator role and keys
        // exist (system-wide and per-namespace)
        {
            // ensure that KeyIds are not reused system-wide
            let mut set = HashSet::new();
            for key_id in self
                .users
                .iter()
                .flat_map(|mapping| mapping.get_key_ids(None))
            {
                if !set.insert(key_id.clone()) {
                    return Err(Error::DuplicateKeyId {
                        key_id,
                        namespace: None,
                    }
                    .into());
                }
            }

            // ensure that KeyIds are not reused per namespace
            for namespace in self
                .users
                .iter()
                .flat_map(|mapping| mapping.get_nethsm_namespaces())
            {
                let mut set = HashSet::new();
                for key_id in self
                    .users
                    .iter()
                    .flat_map(|mapping| mapping.get_key_ids(Some(&namespace)))
                {
                    if !set.insert(key_id.clone()) {
                        return Err(Error::DuplicateKeyId {
                            key_id,
                            namespace: Some(namespace),
                        }
                        .into());
                    }
                }
            }
        }

        // ensure unique tags system-wide and per namespace
        {
            // ensure that tags are unique system-wide
            let mut set = HashSet::new();
            for tag in self
                .users
                .iter()
                .flat_map(|mapping| mapping.get_nethsm_tags(None))
            {
                if !set.insert(tag) {
                    return Err(Error::DuplicateTag {
                        tag: tag.to_string(),
                        namespace: None,
                    }
                    .into());
                }
            }

            // ensure that tags are unique in each namespace
            for namespace in self
                .users
                .iter()
                .flat_map(|mapping| mapping.get_nethsm_namespaces())
            {
                let mut set = HashSet::new();
                for tag in self
                    .users
                    .iter()
                    .flat_map(|mapping| mapping.get_nethsm_tags(Some(&namespace)))
                {
                    if !set.insert(tag) {
                        return Err(Error::DuplicateTag {
                            tag: tag.to_string(),
                            namespace: Some(namespace),
                        }
                        .into());
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::panic;
    use std::path::PathBuf;

    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[rstest]
    fn signstar_config_new_from_file(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/working/"]
        config_file: PathBuf,
    ) -> TestResult {
        SignstarConfig::new_from_file(Some(&config_file))?;

        Ok(())
    }

    #[rstest]
    fn signstar_config_duplicate_system_user(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-system-user/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("{config_file:?}");
        match SignstarConfig::new_from_file(Some(&config_file)) {
            Err(crate::Error::Config(Error::DuplicateSystemUserId { .. })) => Ok(()),
            Ok(_) => panic!("Did not trigger any Error!"),
            Err(error) => panic!("Did not trigger the correct Error: {:?}!", error),
        }
    }

    #[rstest]
    fn signstar_config_duplicate_nethsm_user(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-nethsm-user/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(crate::Error::Config(Error::DuplicateNetHsmUserId { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_missing_administrator(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/missing-administrator/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(crate::Error::Config(Error::MissingAdministrator { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_missing_namespace_administrators(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/missing-namespace-administrator/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(crate::Error::Config(Error::MissingAdministrator { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_duplicate_authorized_keys_share_uploader(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-authorized-keys-share-uploader/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {config_file:?}");
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|e| format!("Can't convert {config_file:?}:\n{e:?}"))?;
        // when using plaintext or systemd-creds for administrative credentials, there are no share
        // uploaders
        if config_file_string.ends_with("ntext.toml")
            || config_file_string.ends_with("emd-creds.toml")
        {
            let _config = SignstarConfig::new_from_file(Some(&config_file))?;
            Ok(())
        } else if let Err(crate::Error::Config(Error::DuplicateSshPublicKey { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_duplicate_authorized_keys_share_downloader(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-authorized-keys-share-downloader/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {config_file:?}");
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_x| format!("Can't convert {config_file:?}"))?;
        // when using plaintext or systemd-creds for administrative credentials, there are no share
        // downloaders
        if config_file_string.ends_with("ntext.toml")
            || config_file_string.ends_with("systemd-creds.toml")
        {
            let _config = SignstarConfig::new_from_file(Some(&config_file))?;
            Ok(())
        } else if let Err(crate::Error::Config(Error::DuplicateSshPublicKey { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_duplicate_authorized_keys_users(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-authorized-keys-users/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(crate::Error::Config(Error::DuplicateSshPublicKey { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_missing_share_download_user(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/missing-share-download-user/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {config_file:?}");
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_x| format!("Can't convert {config_file:?}"))?;
        // when using plaintext or systemd-creds for administrative credentials, there are no share
        // downloaders
        if config_file_string.ends_with("plaintext.toml")
            || config_file_string.ends_with("systemd-creds.toml")
        {
            let _config = SignstarConfig::new_from_file(Some(&config_file))?;
            Ok(())
        } else if let Err(crate::Error::Config(Error::MissingShareDownloadSystemUser)) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_missing_share_upload_user(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/missing-share-upload-user/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {config_file:?}");
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_x| format!("Can't convert {config_file:?}"))?;
        // when using plaintext or systemd-creds for administrative credentials, there are no share
        // downloaders
        if config_file_string.ends_with("plaintext.toml")
            || config_file_string.ends_with("systemd-creds.toml")
        {
            let _config = SignstarConfig::new_from_file(Some(&config_file))?;
            Ok(())
        } else if let Err(crate::Error::Config(Error::MissingShareUploadSystemUser)) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_no_sss_but_shares(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/no-sss-but-shares/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {config_file:?}");
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_x| format!("Can't convert {config_file:?}"))?;
        // when using shamir's secret sharing for administrative credentials, there ought to be
        // share downloaders and uploaders
        if config_file_string.ends_with("irs-secret-sharing.toml") {
            let _config = SignstarConfig::new_from_file(Some(&config_file))?;
            Ok(())
        } else if let Err(crate::Error::Config(Error::NoSssButShareUsers { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_duplicate_key_id(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-key-id/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(crate::Error::Config(Error::DuplicateKeyId { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_duplicate_key_id_in_namespace(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-key-id-in-namespace/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(crate::Error::Config(Error::DuplicateKeyId { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_duplicate_tag(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-tag/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(crate::Error::Config(Error::DuplicateTag { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn signstar_config_duplicate_tag_in_namespace(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-tag-in-namespace/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(crate::Error::Config(Error::DuplicateTag { .. })) =
            SignstarConfig::new_from_file(Some(&config_file))
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    #[case("ssh-backup1")]
    #[case("ssh-metrics1")]
    #[case("ssh-operator1")]
    #[case("ssh-operator2")]
    #[case("ns1-ssh-operator1")]
    #[case("ns1-ssh-operator2")]
    #[case("local-metrics1")]
    #[case("ssh-wireguard-down")]
    fn signstar_config_get_extended_usermapping_succeeds(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/working/"]
        config_file: PathBuf,
        #[case] name: &str,
    ) -> TestResult {
        let config = SignstarConfig::new_from_file(Some(&config_file))?;
        if config.get_extended_mapping_for_user(name).is_none() {
            panic!("The user with name {name} is supposed to exist in the Signstar config");
        }

        Ok(())
    }

    #[rstest]
    fn signstar_config_get_extended_usermapping_fails(
        #[files("signstar-config-*.toml")]
        #[base_dir = "tests/fixtures/working/"]
        config_file: PathBuf,
    ) -> TestResult {
        let config = SignstarConfig::new_from_file(Some(&config_file))?;
        if config.get_extended_mapping_for_user("foo").is_some() {
            panic!("The user \"foo\" should not exist in the Signstar config");
        }

        Ok(())
    }
}
