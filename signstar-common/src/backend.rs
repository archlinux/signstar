//! Common components for any type of backend.

use std::collections::HashMap;

/// The [os-release] `ID` for Arch Linux.
///
/// [os-release]: https://man.archlinux.org/man/os-release.5
const OS_ARCH: &str = "arch";

/// The Unix groups required to connect to a YubiHSM2 backend on an Arch Linux system.
const ARCH_YUBIHSM2_GROUPS: &[&str] = &["_yubihsm2"];

/// The type of a supported HSM backend.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BackendType {
    /// The NetHSM backend.
    NetHsm,

    /// The YubiHSM2 backend.
    YubiHsm2,
}

impl BackendType {
    /// Returns the required Unix groups for an operating system to connect to a given backend.
    ///
    /// The returned [`HashMap`] uses the `ID` of an OS in the [os-release] format as key.
    ///
    /// [os-release]: https://man.archlinux.org/man/os-release.5
    pub fn client_unix_groups(&self) -> HashMap<&str, &[&str]> {
        match self {
            Self::NetHsm => HashMap::new(),
            Self::YubiHsm2 => HashMap::from_iter([(OS_ARCH, ARCH_YUBIHSM2_GROUPS)]),
        }
    }
}
