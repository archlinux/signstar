use std::fmt::Debug;

use log::{debug, error, warn};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use signstar_common::traits::BackendCheck;
use yubihsm::{Client, Connector, Credentials, UsbConfig, client::ErrorKind};

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

        if let Err(error) = connector.device_info() {
            warn!(
                "The YubiHSM2 connection {:?} is not available from this host: {error}",
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

        if let Err(error) = Client::open(connector, Credentials::default(), false) {
            if error.kind() == &ErrorKind::AuthenticationError {
                debug!(
                    "Authentication against the YubiHSM2 backend {:?} using the default credentials failed, assuming it to be provisioned: {error}",
                    self
                );
                return true;
            }

            error!(
                "The connection to YubiHSM2 backend {:?} cannot be established due to an error: {error}",
                self
            );
            return false;
        }

        warn!(
            "Authentication against the YubiHSM2 backend {:?} using the default credentials succeeded, assuming it to be unprovisioned.",
            self
        );
        false
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
