#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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
