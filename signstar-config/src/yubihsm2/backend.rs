//! Backend handling for YubiHSM2.

use serde::{Deserialize, Serialize};

/// A connection to the YubiHSM2 backend.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum YubiHsmConnection {
    /// Connection to a Mock HSM.
    ///
    /// # Note
    ///
    /// MockHSMs are only used for testing.
    Mock,

    /// Connection to a device over USB.
    ///
    /// Each YubiHSM2 is identified by a unique serial number.
    Usb {
        /// Serial number of the connected YubiHSM2.
        serial_number: String,
    },
}
