//! Backup handling.

use std::io::Read;

use crate::Passphrase;

/// Validates a [backup].
///
/// Parses a previously created backup file. If `passphrase` is
/// [`Some`], additionally decrypts the backup and verifies the
/// encrypted backup version number.
///
/// # Errors
///
/// Returns an [`nethsm_backup::Error`] if validating a [backup] fails:
/// * the magic number is missing in the file
/// * the version number is unknown
/// * the provided passphrase is incorrect
///
/// # Examples
///
/// ```no_run
/// use nethsm::{
///     Connection,
///     ConnectionSecurity,
///     Credentials,
///     NetHsm,
///     Passphrase,
///     validate_backup,
/// };
///
/// # fn main() -> testresult::TestResult {
/// // create a connection with a user in the Backup role
/// let nethsm = NetHsm::new(
///     Connection::new(
///         "https://example.org/api/v1".try_into()?,
///         ConnectionSecurity::Unsafe,
///     ),
///     Some(Credentials::new(
///         "backup1".parse()?,
///         Some(Passphrase::new("passphrase".to_string())),
///     )),
///     None,
///     None,
/// )?;
///
/// // create a backup and write it to file
/// std::fs::write("nethsm.bkp", nethsm.backup()?)?;
///
/// // check for consistency only
/// validate_backup(&mut std::fs::File::open("nethsm.bkp")?, None)?;
///
/// // check for correct passphrase by decrypting and validating the encrypted backup version
/// validate_backup(
///     &mut std::fs::File::open("nethsm.bkp")?,
///     Passphrase::new("a sample password".into()),
/// )?;
/// # Ok(())
/// # }
/// ```
/// [backup]: https://docs.nitrokey.com/nethsm/administration#backup
pub fn validate_backup(
    reader: &mut impl Read,
    passphrase: impl Into<Option<Passphrase>>,
) -> Result<(), nethsm_backup::Error> {
    let passphrase = passphrase.into();
    let backup = nethsm_backup::Backup::parse(reader)?;
    if let Some(passphrase) = passphrase {
        let decryptor = backup.decrypt(passphrase.expose_borrowed().as_bytes())?;
        let version = decryptor.version()?;
        if version.len() != 1 || version[0] != 0 {
            return Err(nethsm_backup::Error::BadVersion {
                highest_supported_version: 0,
                backup_version: version,
            });
        }
    }
    Ok(())
}
