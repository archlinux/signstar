//! Reading and writing of administrative secrets.

use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};

/// The default number of shares for [Shamir's Secret Sharing] (SSS).
///
/// [Shamir's Secret Sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
const SSS_DEFAULT_NUMBER_OF_SHARES: NonZeroUsize =
    NonZeroUsize::new(6).expect("6 is larger than 0");

/// The default number of shares required for decrypting secrets encrypted using [Shamir's Secret
/// Sharing] (SSS).
///
/// [Shamir's Secret Sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
const SSS_DEFAULT_THRESHOLD: NonZeroUsize = NonZeroUsize::new(3).expect("3 is larger than 0");

/// The handling of administrative secrets.
///
/// Administrative secrets may be handled in different ways (e.g. persistent or non-persistent).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdministrativeSecretHandling {
    /// The administrative secrets are handled in a plaintext file in a non-volatile directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of unencrypted administrative secrets on a file system.
    Plaintext,

    /// The administrative secrets are handled in a file encrypted using [systemd-creds(1)] in a
    /// non-volatile directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of (host-specific) encrypted administrative secrets on a file system, that
    /// could be extracted if the host is compromised.
    ///
    /// [systemd-creds(1)]: https://man.archlinux.org/man/systemd-creds.1
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
    ShamirsSecretSharing {
        /// The number of shares used to encrypt the shared secret.
        number_of_shares: NonZeroUsize,

        /// The number of shares (see `number_of_shares`) required to decrypt the shared secret.
        threshold: NonZeroUsize,
    },
}

impl Default for AdministrativeSecretHandling {
    fn default() -> Self {
        Self::ShamirsSecretSharing {
            number_of_shares: SSS_DEFAULT_NUMBER_OF_SHARES,
            threshold: SSS_DEFAULT_THRESHOLD,
        }
    }
}
