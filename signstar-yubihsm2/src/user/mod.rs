//! User handling for YubiHSM2 devices.

use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};

/// Credentials for a YubiHSM2 device.
///
/// Credentials are mapped to the authentication key ID and the passphrase used as key derivation
/// function (KDF) for an authentication key.
#[derive(Clone, Debug)]
pub struct Credentials {
    id: u16,
    passphrase: Passphrase,
}

impl Credentials {
    /// Creates a new [`Credentials`].
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_crypto::passphrase::Passphrase;
    /// use signstar_yubihsm2::Credentials;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let creds = Credentials::new(1, "this-is-a-passphrase".parse()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(id: u16, passphrase: Passphrase) -> Self {
        Self { id, passphrase }
    }
}

impl UserWithPassphrase for Credentials {
    fn user(&self) -> String {
        self.id.to_string()
    }

    fn passphrase(&self) -> &Passphrase {
        &self.passphrase
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_user_with_passphrase() {
        let credentials = Credentials::new(1, Passphrase::generate(None));
        assert_eq!(credentials.user(), "1");
        assert_eq!(
            credentials.passphrase().expose_borrowed().len(),
            Passphrase::DEFAULT_LENGTH
        );
    }
}
