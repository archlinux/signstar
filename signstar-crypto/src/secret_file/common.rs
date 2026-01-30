//! Common functionality for the creation and loading of secrets from files.

use std::{os::unix::fs::PermissionsExt, path::Path};

use signstar_common::common::SECRET_FILE_MODE;

/// Checks the accessibility of a secrets file.
///
/// Checks whether file at `path`
///
/// - exists,
/// - is a file,
/// - has accessible metadata,
/// - and has the file mode [`SECRET_FILE_MODE`].
///
/// # Errors
///
/// Returns an error, if the file at `path`
///
/// - does not exist,
/// - is not a file,
/// - does not have accessible metadata,
/// - or has a file mode other than [`SECRET_FILE_MODE`].
pub(crate) fn check_secrets_file(path: impl AsRef<Path>) -> Result<(), crate::Error> {
    let path = path.as_ref();

    // check if a path exists
    if !path.exists() {
        return Err(crate::secret_file::Error::SecretsFileMissing {
            path: path.to_path_buf(),
        }
        .into());
    }

    // check if this is a file
    if !path.is_file() {
        return Err(crate::secret_file::Error::SecretsFileNotAFile {
            path: path.to_path_buf(),
        }
        .into());
    }

    // check for correct permissions
    match path.metadata() {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            if mode != SECRET_FILE_MODE {
                return Err(crate::secret_file::Error::SecretsFilePermissions {
                    path: path.to_path_buf(),
                    mode,
                }
                .into());
            }
        }
        Err(source) => {
            return Err(crate::secret_file::Error::SecretsFileMetadata {
                path: path.to_path_buf(),
                source,
            }
            .into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{Permissions, set_permissions};

    use log::{LevelFilter, debug};
    use signstar_common::logging::setup_logging;
    use tempfile::{NamedTempFile, TempDir};
    use testresult::TestResult;

    use super::*;

    /// Ensures that a file with the correct permissions is successfully checked using
    /// [`check_secrets_file`].
    #[test]
    fn check_secrets_file_succeeds() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();
        set_permissions(path, Permissions::from_mode(SECRET_FILE_MODE))?;
        debug!(
            "Created {path:?} with mode {:o}",
            path.metadata()?.permissions().mode()
        );

        check_secrets_file(path)?;

        Ok(())
    }

    /// Ensures that passing a non-existent file to [`check_secrets_file`] fails.
    #[test]
    fn check_secrets_file_fails_on_missing_file() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path().to_path_buf();
        temp_file.close()?;

        if check_secrets_file(&path).is_ok() {
            panic!("The path {path:?} is missing and should not have passed as a secrets file.");
        }

        Ok(())
    }

    /// Ensures that passing a directory to [`check_secrets_file`] fails.
    #[test]
    fn check_secrets_file_fails_on_dir() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let temp_file = TempDir::new()?;
        let path = temp_file.path();
        debug!(
            "Created {path:?} with mode {:o}",
            path.metadata()?.permissions().mode()
        );

        if check_secrets_file(path).is_ok() {
            panic!("The dir {path:?} should not have passed as a secrets file.");
        }

        Ok(())
    }

    /// Ensures that a file without the correct permissions fails [`check_secrets_file`].
    #[test]
    fn check_secrets_file_fails_on_invalid_permissions() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();
        set_permissions(path, Permissions::from_mode(0o100644))?;
        debug!(
            "Created {path:?} with mode {:o}",
            path.metadata()?.permissions().mode()
        );

        if check_secrets_file(path).is_ok() {
            panic!("The file at {path:?} should not have passed as a secrets file.");
        }

        Ok(())
    }
}
