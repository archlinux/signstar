use std::fmt::Display;

use log::Level;
use nethsm_sdk_rs::models::{Switch, UnattendedBootConfig};
use serde::{Deserialize, Serialize};
use ureq::Response;

/// A representation of a message body in an HTTP response
///
/// This type allows us to deserialize the message body when the NetHSM API triggers the return of a
/// [`nethsm_sdk_rs::apis::Error::Ureq`].
#[derive(Debug, Deserialize)]
pub struct Message {
    message: String,
}

impl From<Response> for Message {
    fn from(value: Response) -> Self {
        if let Ok(message) = value.into_json() {
            message
        } else {
            Message {
                message: "Deserialization error (no message in body)".to_string(),
            }
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[derive(Debug)]
pub struct ApiErrorMessage {
    pub status_code: u16,
    pub message: Message,
}

impl From<(u16, Message)> for ApiErrorMessage {
    fn from(value: (u16, Message)) -> Self {
        Self {
            status_code: value.0,
            message: value.1,
        }
    }
}

impl Display for ApiErrorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "{} (status code {})",
            self.message, self.status_code
        ))
    }
}

/// A helper Error for more readable output for [`nethsm_sdk_rs::apis::Error`]
///
/// This type allows us to create more readable output for [`nethsm_sdk_rs::apis::Error::Ureq`] and
/// reuse the upstream handling otherwise.
pub struct NetHsmApiError<T> {
    error: Option<nethsm_sdk_rs::apis::Error<T>>,
    message: Option<String>,
}

impl<T> From<nethsm_sdk_rs::apis::Error<T>> for NetHsmApiError<T> {
    fn from(value: nethsm_sdk_rs::apis::Error<T>) -> Self {
        match value {
            nethsm_sdk_rs::apis::Error::Ureq(error) => match error {
                nethsm_sdk_rs::ureq::Error::Status(code, response) => Self {
                    error: None,
                    message: Some(ApiErrorMessage::from((code, response.into())).to_string()),
                },
                nethsm_sdk_rs::ureq::Error::Transport(transport) => Self {
                    error: None,
                    message: Some(format!("{transport}")),
                },
            },
            nethsm_sdk_rs::apis::Error::ResponseError(resp) => Self {
                error: None,
                message: Some(format!(
                    "Status code: {}: {}",
                    resp.status,
                    // First, try to deserialize the response as a `Message` object,
                    // which is commonly returned by a majority of failures
                    serde_json::from_slice::<Message>(&resp.content)
                        .map(|m| m.message)
                        // if that fails, as a last resort, try to return the response verbatim.
                        .unwrap_or_else(|_| String::from_utf8_lossy(&resp.content).into())
                )),
            },
            _ => Self {
                error: Some(value),
                message: None,
            },
        }
    }
}

impl<T> Display for NetHsmApiError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(message) = self.message.as_ref() {
            write!(f, "{message}")?;
        } else if let Some(error) = self.error.as_ref() {
            write!(f, "{error}")?;
        }
        Ok(())
    }
}

/// The NetHSM boot mode
///
/// Defines in which state the NetHSM is in during boot after provisioning (see
/// [`crate::NetHsm::provision`]) and whether an unlock passphrase has to be provided for it to be
/// of state [`crate::SystemState::Operational`].
#[derive(
    Clone,
    Copy,
    Debug,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Eq,
    PartialEq,
)]
#[strum(ascii_case_insensitive)]
pub enum BootMode {
    /// The device boots into state [`crate::SystemState::Locked`] and an unlock passphrase has to
    /// be provided
    Attended,
    /// The device boots into state [`crate::SystemState::Operational`] and no unlock passphrase
    /// has to be provided
    Unattended,
}

impl From<UnattendedBootConfig> for BootMode {
    fn from(value: UnattendedBootConfig) -> Self {
        match value.status {
            Switch::On => BootMode::Unattended,
            Switch::Off => BootMode::Attended,
        }
    }
}

impl From<BootMode> for UnattendedBootConfig {
    fn from(value: BootMode) -> Self {
        match value {
            BootMode::Unattended => UnattendedBootConfig { status: Switch::On },
            BootMode::Attended => UnattendedBootConfig {
                status: Switch::Off,
            },
        }
    }
}

/// A device log level
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum LogLevel {
    /// Show debug, error, warning and info messages
    Debug,

    /// Show error, warning and info messages
    Error,

    /// Show info messages
    #[default]
    Info,

    /// Show warning and info messages
    Warning,
}

impl From<LogLevel> for nethsm_sdk_rs::models::LogLevel {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Debug => Self::Debug,
            LogLevel::Error => Self::Error,
            LogLevel::Info => Self::Info,
            LogLevel::Warning => Self::Warning,
        }
    }
}

impl From<Level> for LogLevel {
    /// Creates a new [`LogLevel`] from a [`Level`].
    ///
    /// # Note
    ///
    /// Creates a [`LogLevel::Debug`] from a [`Level::Trace`], as there is no equivalent level.
    fn from(value: Level) -> Self {
        match value {
            Level::Trace => Self::Debug,
            Level::Debug => Self::Debug,
            Level::Error => Self::Error,
            Level::Info => Self::Info,
            Level::Warn => Self::Warning,
        }
    }
}

/// The algorithm type of a key used for TLS
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum TlsKeyType {
    /// A Montgomery curve key over a prime field for the prime number 2^255-19
    Curve25519,

    /// An elliptic-curve key over a prime field for a prime of size 224 bit
    EcP224,

    /// An elliptic-curve key over a prime field for a prime of size 256 bit
    EcP256,

    /// An elliptic-curve key over a prime field for a prime of size 384 bit
    EcP384,

    /// An elliptic-curve key over a prime field for a prime of size 521 bit
    EcP521,

    /// An RSA key
    #[default]
    Rsa,
}

impl From<TlsKeyType> for nethsm_sdk_rs::models::TlsKeyType {
    fn from(value: TlsKeyType) -> Self {
        match value {
            TlsKeyType::Curve25519 => Self::Curve25519,
            TlsKeyType::EcP224 => Self::EcP224,
            TlsKeyType::EcP256 => Self::EcP256,
            TlsKeyType::EcP384 => Self::EcP384,
            TlsKeyType::EcP521 => Self::EcP521,
            TlsKeyType::Rsa => Self::Rsa,
        }
    }
}

/// The role of a user on a NetHSM device
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum UserRole {
    /// A role for administrating a device, its users and keys
    Administrator,
    /// A role for creating backups of a device
    Backup,
    /// A role for reading metrics of a device
    Metrics,
    /// A role for using one or more keys of a device
    #[default]
    Operator,
}

impl From<UserRole> for nethsm_sdk_rs::models::UserRole {
    fn from(value: UserRole) -> Self {
        match value {
            UserRole::Administrator => Self::Administrator,
            UserRole::Backup => Self::Backup,
            UserRole::Metrics => Self::Metrics,
            UserRole::Operator => Self::Operator,
        }
    }
}

impl From<nethsm_sdk_rs::models::UserRole> for UserRole {
    fn from(value: nethsm_sdk_rs::models::UserRole) -> Self {
        match value {
            nethsm_sdk_rs::models::UserRole::Administrator => Self::Administrator,
            nethsm_sdk_rs::models::UserRole::Backup => Self::Backup,
            nethsm_sdk_rs::models::UserRole::Metrics => Self::Metrics,
            nethsm_sdk_rs::models::UserRole::Operator => Self::Operator,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[rstest]
    #[case("rsa", Some(TlsKeyType::Rsa))]
    #[case("curve25519", Some(TlsKeyType::Curve25519))]
    #[case("ecp256", Some(TlsKeyType::EcP256))]
    #[case("ecp384", Some(TlsKeyType::EcP384))]
    #[case("ecp521", Some(TlsKeyType::EcP521))]
    #[case("foo", None)]
    fn tlskeytype_fromstr(#[case] input: &str, #[case] expected: Option<TlsKeyType>) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(TlsKeyType::from_str(input)?, expected);
        } else {
            assert!(TlsKeyType::from_str(input).is_err());
        }
        Ok(())
    }

    #[rstest]
    #[case("administrator", Some(UserRole::Administrator))]
    #[case("backup", Some(UserRole::Backup))]
    #[case("metrics", Some(UserRole::Metrics))]
    #[case("operator", Some(UserRole::Operator))]
    #[case("foo", None)]
    fn userrole_fromstr(#[case] input: &str, #[case] expected: Option<UserRole>) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(UserRole::from_str(input)?, expected);
        } else {
            assert!(UserRole::from_str(input).is_err());
        }
        Ok(())
    }
}
