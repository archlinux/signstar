//! User handling for YubiHSM2 devices.

use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};

use crate::object::Id;

/// Credentials for a YubiHSM2 device, that are backed by a UTF-8 encoded passphrase file.
///
/// Credentials are mapped to the authentication key ID and the passphrase file.
/// The contents of the passphrase file are meant to be used as input to the key derivation function
/// (KDF) for an authentication key.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct FileBackedCredentials {
    pub(crate) id: Id,
    passphrase_file: PathBuf,
}

impl TryFrom<&FileBackedCredentials> for yubihsm::Credentials {
    type Error = crate::Error;

    /// Creates a new [`yubihsm::Credentials`] from a [`FileBackedCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if a [`Credentials`] cannot be created from the provided
    /// [`FileBackedCredentials`].
    fn try_from(value: &FileBackedCredentials) -> Result<Self, Self::Error> {
        Ok(Self::from(&Credentials::try_from(value)?))
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

    /// Creates a new [`Credentials`] from a [`FileBackedCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if a [`Passphrase`] cannot be read from the passphrase file path of the
    /// provided [`FileBackedCredentials`].
    fn try_from(value: &FileBackedCredentials) -> Result<Self, Self::Error> {
        Ok(Credentials::new(
            value.id,
            Passphrase::try_from(value.passphrase_file.as_path())?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::{NamedTempFile, TempDir};
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

    /// Ensures, that a [`yubihsm::Credentials`] can be created from a [`FileBackedCredentials`].
    #[test]
    fn yubihsm_credentials_try_from_file_backed_credentials_succeeds() -> TestResult {
        let temp_file = {
            let mut temp_file = NamedTempFile::new()?;
            temp_file.write_all("passphrase".as_bytes())?;
            temp_file
        };
        let file_backed_credentials = FileBackedCredentials {
            id: "1".parse()?,
            passphrase_file: temp_file.path().to_path_buf(),
        };
        let _creds = yubihsm::Credentials::try_from(&file_backed_credentials)?;

        Ok(())
    }

    /// Ensures, that a [`yubihsm::Credentials`] cannot be created from a [`FileBackedCredentials`]
    /// tracking a directory.
    #[test]
    fn yubihsm_credentials_try_from_file_backed_credentials_fails_on_dir() -> TestResult {
        let temp_file = TempDir::new()?;
        let file_backed_credentials = FileBackedCredentials {
            id: "1".parse()?,
            passphrase_file: temp_file.path().to_path_buf(),
        };
        assert!(yubihsm::Credentials::try_from(&file_backed_credentials).is_err());

        Ok(())
    }
}
