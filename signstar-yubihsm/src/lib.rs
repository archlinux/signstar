//! YubiHSM signer interface.

use signstar_crypto::passphrase::Passphrase;
use yubihsm::Credentials as YubiCredentials;

mod error;
pub use error::Error;
mod signing;
pub use signing::YubiHsmSigner;

/// YubiHSM credentials.
#[derive(Debug)]
pub struct Credentials {
    /// The identifier of the authentication key.
    pub auth_key_id: u16,

    /// The passphrase associated with the authentication key.
    pub passphrase: Passphrase,
}

impl From<&Credentials> for YubiCredentials {
    fn from(value: &Credentials) -> Self {
        YubiCredentials::from_password(
            value.auth_key_id,
            value.passphrase.expose_borrowed().as_bytes(),
        )
    }
}
