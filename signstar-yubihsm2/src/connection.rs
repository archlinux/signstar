use std::fmt::Debug;

use log::{debug, error, warn};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use signstar_common::traits::BackendCheck;
use yubihsm::{Client, Connector, Credentials, UsbConfig};

use crate::yubihsm::SerialNumber;

/// A connection to a YubiHSM2.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Connection {
    /// Connection to a Mock HSM.
    #[cfg(feature = "_yubihsm2-mockhsm")]
    Mock,

    /// Connection to a device over USB.
    ///
    /// Each YubiHSM2 is identified by a unique serial number.
    /// This number is printed on the enclosure of the physical device.
    Usb {
        /// Serial number of the connected YubiHSM2.
        serial_number: SerialNumber,
    },
}

impl BackendCheck for Connection {
    fn is_available(&self) -> bool {
        let connector = match self {
            #[cfg(feature = "_yubihsm2-mockhsm")]
            Self::Mock => Connector::mockhsm(),
            Self::Usb { serial_number } => Connector::usb(&UsbConfig {
                serial: Some(*serial_number),
                timeout_ms: 5000,
            }),
        };

        if connector.device_info().is_err() {
            warn!(
                "The YubiHSM2 connection {:?} is not available from this host.",
                self
            );
            return false;
        }

        debug!(
            "The YubiHSM2 connection {:?} is available from this host.",
            self
        );

        true
    }

    fn is_provisioned(&self) -> bool {
        let connector = match self {
            #[cfg(feature = "_yubihsm2-mockhsm")]
            Self::Mock => Connector::mockhsm(),
            Self::Usb { serial_number } => Connector::usb(&UsbConfig {
                serial: Some(*serial_number),
                timeout_ms: 5000,
            }),
        };

        let client = match Client::open(connector, Credentials::default(), false) {
            Err(error) => {
                error!(
                    "The connection to YubiHSM2 backend {:?} cannot be established: {error}",
                    self
                );
                return false;
            }
            Ok(client) => client,
        };

        if client.ping().is_err() {
            debug!(
                "The YubiHSM2 backend {:?} cannot be pinged with its default credentials and thus is considered provisioned.",
                self
            );
            true
        } else {
            warn!(
                "The YubiHSM2 backend {:?} can be pinged using its default credentials and thus is considered unprovisioned.",
                self
            );
            false
        }
    }
}

impl From<&Connection> for Connector {
    fn from(value: &Connection) -> Self {
        match value {
            #[cfg(feature = "_yubihsm2-mockhsm")]
            Connection::Mock => Connector::mockhsm(),
            Connection::Usb { serial_number } => Connector::usb(&UsbConfig {
                serial: Some(*serial_number),
                timeout_ms: UsbConfig::DEFAULT_TIMEOUT_MILLIS,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use log::LevelFilter;
    use signstar_common::logging::setup_logging;
    use testresult::TestResult;

    use super::*;

    /// Ensures, that [`Connection::is_available`] succeeds, when using [`Connection::Mock`].
    #[cfg(feature = "_yubihsm2-mockhsm")]
    #[test]
    fn connection_is_available_succeeds_with_mockhsm() -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let connection = Connection::Mock;
        assert!(connection.is_available());

        Ok(())
    }

    /// Ensures, that [`Connection::is_available`] fails, when using a [`Connection::Usb`] with
    /// serial number `0012345678`.
    #[test]
    fn connection_is_available_fails_with_hardware() -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let connection = Connection::Usb {
            serial_number: "0012345678".parse()?,
        };
        assert!(!connection.is_available());

        Ok(())
    }

    /// Ensures, that [`Connection::uses_default_credentials`] returns `false`, when using
    /// a default [`Connection::Mock`].
    #[cfg(feature = "_yubihsm2-mockhsm")]
    #[test]
    fn connection_uses_default_credentials_returns_false_with_mockhsm() -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let connection = Connection::Mock;
        assert!(!connection.is_provisioned());

        Ok(())
    }

    /// Ensures, that [`Connection::uses_default_credentials`] returns `false`, when using a
    /// [`Connection::Usb`] with serial number `0012345678`.
    #[test]
    fn connection_uses_default_credentials_returns_false_with_hardware() -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let connection = Connection::Usb {
            serial_number: "0012345678".parse()?,
        };
        assert!(!connection.is_provisioned());

        Ok(())
    }
}
