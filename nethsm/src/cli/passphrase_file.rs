//! Handling of files containing a [`Passphrase`].

use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::Passphrase;

/// A representation of a file containing a passphrase
#[derive(Clone, Debug)]
pub struct PassphraseFile {
    /// The passphrase contained in the file.
    pub passphrase: Passphrase,
}

impl PassphraseFile {
    /// Creates a new [`PassphraseFile`] from a path.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the file to string fails.
    pub fn new(path: &Path) -> Result<Self, crate::Error> {
        Ok(Self {
            passphrase: Passphrase::new(read_to_string(path).map_err(crate::cli::Error::Io)?),
        })
    }
}

impl FromStr for PassphraseFile {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PassphraseFile::new(&PathBuf::from(s))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use log::LevelFilter;
    use rstest::rstest;
    use signstar_common::logging::setup_terminal_logging;
    use tempfile::NamedTempFile;
    use testresult::TestResult;

    use super::*;

    #[rstest]
    fn passphrase_file() -> TestResult {
        setup_terminal_logging(LevelFilter::Debug)?;

        let passphrase = "this is a passphrase";
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(passphrase.as_bytes())?;

        let passphrase_file = PassphraseFile::new(temp_file.path())?;
        assert_eq!(passphrase_file.passphrase.expose_borrowed(), passphrase);

        Ok(())
    }
}
