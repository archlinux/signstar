//! User handling for YubiHSM2 devices.

use std::path::PathBuf;

use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};

use crate::object::Id;

/// Credentials for a YubiHSM2 device, that are backed by a UTF-8 encoded passphrase file.
///
/// Credentials are mapped to the authentication key ID and the passphrase file.
/// The contents of the passphrase file are meant to be used as key derivation function (KDF) for an
/// authentication key.
#[derive(Debug)]
pub struct FileBackedCredentials {
    pub(crate) id: Id,
    passphrase_file: PathBuf,
}

impl TryFrom<&FileBackedCredentials> for yubihsm::Credentials {
    type Error = crate::Error;

    fn try_from(value: &FileBackedCredentials) -> Result<Self, Self::Error> {
        let passphrase = Passphrase::try_from(value.passphrase_file.as_path())?;

        Ok(yubihsm::Credentials::from_password(
            value.id.into(),
            passphrase.expose_borrowed().as_bytes(),
        ))
    }
}

/// Credentials for a YubiHSM2 device.
///
/// Credentials are mapped to the authentication key ID and the passphrase used as key derivation
/// function (KDF) for an authentication key.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Credentials {
    pub(crate) id: Id,
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
    /// let creds = Credentials::new("1".parse()?, "this-is-a-passphrase".parse()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(id: Id, passphrase: Passphrase) -> Self {
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

impl From<&Credentials> for yubihsm::Credentials {
    fn from(value: &Credentials) -> Self {
        Self::from_password(
            value.id.into(),
            value.passphrase.expose_borrowed().as_bytes(),
        )
    }
}

impl TryFrom<&FileBackedCredentials> for Credentials {
    type Error = crate::Error;

    fn try_from(value: &FileBackedCredentials) -> Result<Self, Self::Error> {
        let passphrase = Passphrase::try_from(value.passphrase_file.as_path())?;

        Ok(Credentials::new(value.id, passphrase))
    }
}

#[cfg(test)]
mod tests {
    use testresult::TestResult;

    use super::*;

    #[test]
    fn credentials_user_with_passphrase() -> TestResult {
        let credentials = Credentials::new("1".parse()?, Passphrase::generate(None));
        assert_eq!(credentials.user(), "1");
        assert_eq!(
            credentials.passphrase().expose_borrowed().len(),
            Passphrase::DEFAULT_LENGTH
        );

        Ok(())
    }
}
