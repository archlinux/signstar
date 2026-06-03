//! Passphrase handling.

use std::{fmt::Display, fs::read_to_string, path::Path, str::FromStr};

use rand::{Rng, distributions::Alphanumeric, thread_rng};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// An error that may occur when operating on users.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Unable to convert string slice to Passphrase
    #[error("Unable to convert string to passphrase")]
    Passphrase,

    /// A passphrase is shorter than its required length.
    #[error(
        "The passphrase should be at least {required_length} characters long, but is only {length} characters long."
    )]
    Length {
        /// The length of the passphrase.
        length: usize,

        /// The required length of the passphrase.
        required_length: usize,
    },
}

/// A policy for [`Passphrase`].
///
/// Policies encode e.g. the minimum required length for a passphrase.
#[derive(Clone, Debug)]
pub struct PassphrasePolicy {
    /// The minimum length a passphrase needs to have.
    pub minimum_length: usize,
}

impl Default for PassphrasePolicy {
    fn default() -> Self {
        Self {
            minimum_length: Passphrase::DEFAULT_LENGTH,
        }
    }
}

/// A secret passphrase
///
/// The passphrase is held by a [`SecretString`], which guarantees zeroing of memory on
/// destruct.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Passphrase(SecretString);

impl Passphrase {
    /// The default passphrase length.
    pub const DEFAULT_LENGTH: usize = 30;

    /// Creates a new [`Passphrase`] from owned [`String`]
    ///
    /// # Examples
    /// ```
    /// use signstar_crypto::passphrase::Passphrase;
    ///
    /// let passphrase = Passphrase::new("passphrase".to_string());
    /// ```
    pub fn new(passphrase: String) -> Self {
        Self(SecretString::new(passphrase.into()))
    }

    /// Creates a new [`Passphrase`] from owned [`String`], adhering to a [`PassphrasePolicy`].
    ///
    /// # Errors
    ///
    /// Returns an error if `passphrase` does not adhere to `policy`.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_crypto::passphrase::{Passphrase, PassphrasePolicy};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let passphrase = Passphrase::new_with_policy(
    ///     "passphrase".to_string(),
    ///     &PassphrasePolicy { minimum_length: 10 },
    /// )?;
    ///
    /// // The passphrase "passphrase" is too short for the default policy.
    /// assert!(
    ///     Passphrase::new_with_policy("passphrase".to_string(), &PassphrasePolicy::default(),)
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_with_policy(
        passphrase: String,
        policy: &PassphrasePolicy,
    ) -> Result<Self, crate::Error> {
        if passphrase.len() < policy.minimum_length {
            return Err(Error::Length {
                length: passphrase.len(),
                required_length: policy.minimum_length,
            }
            .into());
        }

        Ok(Self::new(passphrase))
    }

    /// Generates a new [`Passphrase`].
    ///
    /// The generated passphrase will consist of alphanumeric characters.
    /// The length of the passphrase can be adjusted using `length`, but is guaranteed to be at
    /// least [`Self::DEFAULT_LENGTH`] characters long.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_crypto::passphrase::Passphrase;
    ///
    /// let passphrase = Passphrase::generate(None);
    /// println!("{}", passphrase.expose_borrowed());
    /// ```
    pub fn generate(length: Option<usize>) -> Self {
        let length = {
            let mut length = length.unwrap_or(Self::DEFAULT_LENGTH);
            if length < Self::DEFAULT_LENGTH {
                length = Self::DEFAULT_LENGTH
            }
            length
        };

        Self::new(
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(length)
                .map(char::from)
                .collect(),
        )
    }

    /// Exposes the secret passphrase as owned [`String`]
    pub fn expose_owned(&self) -> String {
        self.0.expose_secret().to_owned()
    }

    /// Exposes the secret passphrase as borrowed [`str`]
    pub fn expose_borrowed(&self) -> &str {
        self.0.expose_secret()
    }

    /// Returns the length of the passphrase.
    pub fn len(&self) -> usize {
        self.expose_borrowed().len()
    }

    /// Signals whether the passphrase is empty.
    pub fn is_empty(&self) -> bool {
        self.expose_borrowed().is_empty()
    }
}

impl Display for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl FromStr for Passphrase {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(SecretString::from(s.to_string())))
    }
}

impl Serialize for Passphrase {
    /// Serializes a [`Passphrase`].
    ///
    /// # Warning
    ///
    /// This may be used to write a passphrase to file!
    /// Take precautions so that passphrases can not leak to the environment.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.expose_secret().serialize(serializer)
    }
}

impl TryFrom<&Path> for Passphrase {
    type Error = crate::Error;

    /// Creates a new [`Passphrase`] from the contents of a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the contents of the file at `path` cannot be read to a valid UTF-8
    /// string.
    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Passphrase::from_str(
            &read_to_string(path).map_err(|source| crate::Error::IoPath {
                path: path.to_path_buf(),
                context: "reading a passphrase from the file",
                source,
            })?,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rstest::rstest;
    use tempfile::{NamedTempFile, TempDir};
    use testresult::TestResult;

    use super::*;

    #[test]
    fn passphrase_display() -> TestResult {
        let passphrase = Passphrase::new("a-secret-passphrase".to_string());
        assert_eq!(format!("{passphrase}"), "[REDACTED]");
        Ok(())
    }

    #[rstest]
    #[case::too_short_use_default(Some(20), 30)]
    #[case::none_use_default(None, 30)]
    #[case::longer_than_default(Some(31), 31)]
    fn passphrase_generate(#[case] input_length: Option<usize>, #[case] output_length: usize) {
        let passphrase = Passphrase::generate(input_length);
        assert_eq!(passphrase.expose_borrowed().len(), output_length);
    }

    /// Ensures, that a [`Passphrase`] can be read from a plaintext file.
    #[test]
    fn passphrase_try_from_path_succeeds() -> TestResult {
        let temp_file = {
            let mut temp_file = NamedTempFile::new()?;
            temp_file.write_all("passphrase".as_bytes())?;
            temp_file
        };
        let _passphrase = Passphrase::try_from(temp_file.path())?;

        Ok(())
    }

    /// Ensures, that a [`Passphrase`] cannot be read from a directory.
    #[test]
    fn passphrase_try_from_path_fails_on_path_is_dir() -> TestResult {
        let temp_file = TempDir::new()?;
        assert!(Passphrase::try_from(temp_file.path()).is_err());

        Ok(())
    }

    #[rstest]
    #[case::with_len(Passphrase::new("foo".to_string()), 3)]
    #[case::empty(Passphrase::new("".to_string()), 0)]
    fn passphrase_len(#[case] passphrase: Passphrase, #[case] len: usize) {
        assert_eq!(passphrase.len(), len);
    }

    #[rstest]
    #[case::with_len(Passphrase::new("foo".to_string()), false)]
    #[case::empty(Passphrase::new("".to_string()), true)]
    fn passphrase_is_empty(#[case] passphrase: Passphrase, #[case] is_empty: bool) {
        assert_eq!(passphrase.is_empty(), is_empty);
    }

    #[rstest]
    #[case::empty_policy_allows_empty("", PassphrasePolicy { minimum_length: 0 })]
    #[case::longer_than_minimum_requirement("foobar", PassphrasePolicy { minimum_length: 3 })]
    fn passphrase_new_with_policy_succeeds(
        #[case] passphrase: &str,
        #[case] policy: PassphrasePolicy,
    ) -> TestResult {
        match Passphrase::new_with_policy(passphrase.to_string(), &policy) {
            Ok(_) => {}
            Err(error) => panic!(
                "Expected to successfully create a passphrase from input \"{passphrase}\" and policy {policy:?}, but got error: {error}"
            ),
        }

        Ok(())
    }

    #[rstest]
    #[case::empty_policy_allows_one_char("", PassphrasePolicy { minimum_length: 1 })]
    #[case::shorter_than_minimum_requirement("foobar", PassphrasePolicy::default())]
    fn passphrase_new_with_policy_fails_on_short_passphrase(
        #[case] passphrase: &str,
        #[case] policy: PassphrasePolicy,
    ) -> TestResult {
        match Passphrase::new_with_policy(passphrase.to_string(), &policy) {
            Ok(_) => panic!("Expected to fail with an error, but succeeded instead."),
            Err(crate::Error::Passphrase(Error::Length { .. })) => {}
            Err(error) => panic!(
                "Expected to fail with Error::Length, but failed with different error: {error}"
            ),
        }

        Ok(())
    }
}
