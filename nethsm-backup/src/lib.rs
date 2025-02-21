//! # NetHSM backup
//!
//! A library to parse, decrypt, validate and browse NetHSM backups.
//!
//! ## Format
//!
//! The backup format is an [internal detail of the NetHSM][INT].
//! This library implements the version `0` format which should be supported even on newer devices.
//!
//! The backup file consists of two formats: one outer, which contains unencrypted magic values and
//! framing for the inner format. The inner format can be accessed after decrypting values within
//! the outer one. Both of them are using similar primitives such as length-prefixed byte vectors.
//!
//! Length-prefixed byte vectors are always encoded as 3 big-endian length bytes followed by the
//! given number of bytes.
//!
//! ### Outer format
//!
//! The outer format contains, in order, the header:
//!
//! - magic value: 15 bytes consisting of: `_NETHSM_BACKUP_`,
//! - version tag: 1 byte, currently there's only one version which is stored as a `NUL` byte
//!   (`0x00`).
//!
//! and several length-prefixed values:
//!
//! - salt,
//! - encrypted inner version,
//! - encrypted domain key,
//! - variable number of encrypted items.
//!
//! ### Inner format
//!
//! The inner format is accessed by decrypting the outer format.
//! The decryption key is derived using [scrypt] based on the passphrase provided by the user and
//! the salt contained in the outer format.
//!
//! The following values exist in the inner format:
//!
//! - version: inner format version, the only known value is `0x00`, this is retrieved by decrypting
//!   encrypted inner version with the `backup-version` associated additional data,
//! - domain key: decrypted inner domain key with `domain-key` as AAD,
//! - items: decrypted key/values with the `backup` AAD, they are stored as a length-prefixed string
//!   for a key and a value which is stored as a rest of the decrypted value.
//!
//! Sample list of inner format keys:
//!
//! - `/.initialized`
//! - `/authentication/.version`
//! - `/authentication/admin`
//! - `/authentication/backup1`
//! - `/authentication/encoperator1`
//! - `/authentication/metrics1`
//! - `/authentication/namespace1~admin`
//! - `/authentication/namespace1~operator`
//! - `/authentication/namespace2~admin`
//! - `/authentication/namespace2~operator`
//! - `/authentication/operator1`
//! - `/authentication/operator2`
//! - `/config/backup-key`
//! - `/config/backup-salt`
//! - `/config/certificate`
//! - `/config/private-key`
//! - `/config/time-offset`
//! - `/config/unlock-salt`
//! - `/config/version`
//! - `/domain-key/attended`
//! - `/key/.version`
//! - `/namespace/.version`
//! - `/namespace/namespace1`
//! - `/namespace/namespace2`
//!
//! A fresh list of values in a backup can be generated by running the integration test: `cargo test
//! -- --ignored --nocapture create_backup_and_decrypt_it`
//!
//! ## Examples
//!
//! Listing all fields in a backup file:
//!
//! ```no_run
//! # fn main() -> testresult::TestResult {
//! use std::collections::HashMap;
//!
//! use nethsm_backup::Backup;
//!
//! let backup = Backup::parse(std::fs::File::open("tests/nethsm.backup-file.bkp")?)?;
//! let decryptor = backup.decrypt(b"my-very-unsafe-backup-passphrase")?;
//!
//! assert_eq!(decryptor.version()?, [0]);
//!
//! for item in decryptor.items_iter() {
//!     let (key, value) = item?;
//!     println!("Found {key} with value: {value:X?}");
//! }
//! # Ok(()) }
//! ```
//!
//! Dumping the value of one specified field (here `/config/version`):
//!
//! ```no_run
//! # fn main() -> testresult::TestResult {
//! use std::collections::HashMap;
//!
//! use nethsm_backup::Backup;
//!
//! let backup = Backup::parse(std::fs::File::open("tests/nethsm.backup-file.bkp")?)?;
//! let decryptor = backup.decrypt(b"my-very-unsafe-backup-passphrase")?;
//!
//! assert_eq!(decryptor.version()?, [0]);
//!
//! for (key, value) in decryptor
//!     .items_iter()
//!     .flat_map(|item| item.ok())
//!     .filter(|(key, _)| key == "/config/version")
//! {
//!     println!("Found {key} with value: {value:X?}");
//! }
//! # Ok(()) }
//! ```
//!
//! [INT]: https://github.com/Nitrokey/nethsm-sdk-rs/issues/36#issuecomment-2504592259
//! [scrypt]: https://docs.rs/scrypt

use std::{
    io::{ErrorKind, Read},
    slice::Iter,
};

use aes_gcm::{Aes256Gcm, KeyInit as _, aead::Aead as _};
use scrypt::{Params, scrypt};

/// Backup processing error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid parameters to the Scrypt key derivation.
    #[error("Invalid Scrypt key derivation parameters")]
    InvalidScryptParams,

    /// Scrypt key derviation failed.
    #[error("Scrypt key derivation failed")]
    ScryptKeyDerivation,

    /// AES-GCM decryption error.
    #[error("AES-GCM decryption error")]
    Decryption,

    /// Unicode decode error.
    #[error("Key is not a valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// Magic value is incorrect.
    ///
    /// This file is either corrupted or not a NetHSM backup.
    #[error("Bad magic value: {0:X?}")]
    BadMagic(Vec<u8>),

    /// Version number is not recognized.
    ///
    /// This library supports only version `0` backups.
    #[error(
        "Unsupported backup version number: {backup_version:?}. The highest supported version is {highest_supported_version}"
    )]
    BadVersion {
        highest_supported_version: u8,
        backup_version: Vec<u8>,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Magic value that is contained in all NetHSM backups.
const MAGIC: &[u8] = b"_NETHSM_BACKUP_";

/// Read 3 bytes from the provided reader and interprets it as a [usize].
fn read_usize(reader: &mut impl Read) -> std::io::Result<usize> {
    const LEN: usize = size_of::<usize>();
    let mut bytes = [0; LEN];
    // read exactly 3 bytes
    reader.read_exact(&mut bytes[LEN - 3..])?;
    Ok(usize::from_be_bytes(bytes))
}

/// Read a byte vector from the underlying reader.
///
/// A byte vector is always stored as a [usize] (see [read_usize]) and
/// then a number of bytes.
fn read_field(reader: &mut impl Read) -> Result<Vec<u8>> {
    let len = read_usize(reader)?;
    let mut field = vec![0; len];
    reader.read_exact(&mut field)?;
    Ok(field)
}

/// Check if the reader contains correct [MAGIC] value.
///
/// # Errors
///
/// Returns:
/// * [Error::BadMagic] if an unrecognized magic value is found.
/// * [Error::Io] if an I/O error occurs.
fn check_magic(reader: &mut impl Read) -> Result<()> {
    let mut magic = [0; MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if MAGIC != magic {
        return Err(Error::BadMagic(magic.into()));
    }
    Ok(())
}

/// Check if the reader contains version number that is understood.
///
/// # Errors
///
/// Returns:
/// * [Error::BadVersion] if an unrecognized version value is found.
/// * [Error::Io] if an I/O error occurs.
fn check_version(reader: &mut impl Read) -> Result<()> {
    let mut version = [0; 1];
    reader.read_exact(&mut version)?;
    let version = version[0];
    if version != 0 {
        return Err(Error::BadVersion {
            highest_supported_version: 0,
            backup_version: vec![version],
        });
    }
    Ok(())
}

/// Data of a NetHSM backup.
///
/// This object contains the data of a successfully parsed and well-formed NetHSM backup.
#[derive(Debug)]
pub struct Backup {
    salt: Vec<u8>,
    encrypted_version: Vec<u8>,
    encrypted_domain_key: Vec<u8>,
    items: Vec<Vec<u8>>,
}

impl Backup {
    /// Parse the backup from a reader.
    ///
    /// The reader must contain a well-formed, valid NetHSM backup file.
    ///
    /// # Errors
    ///
    /// Returns:
    /// * [Error::BadVersion] if an unrecognized version value is found.
    /// * [Error::BadMagic] if an unrecognized version value is found.
    /// * [Error::Io] if an I/O error occurs when reading the backup.
    pub fn parse(mut reader: impl Read) -> Result<Self> {
        check_magic(&mut reader)?;
        check_version(&mut reader)?;

        let salt = read_field(&mut reader)?;
        let encrypted_version = read_field(&mut reader)?;
        let encrypted_domain_key = read_field(&mut reader)?;

        let mut items = vec![];
        loop {
            match read_usize(&mut reader) {
                Ok(len) => {
                    let mut field = vec![0; len];
                    reader.read_exact(&mut field)?;
                    items.push(field);
                }
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(error) => {
                    return Err(error)?;
                }
            }
        }

        Ok(Self {
            salt,
            encrypted_version,
            encrypted_domain_key,
            items,
        })
    }

    /// Create a [`BackupDecryptor`] that will decrypt items with the provided passphrase.
    ///
    /// # Errors
    ///
    /// Even though this function returns a `Result` it is unlikely to fail since all parameters are
    /// static.
    pub fn decrypt(&self, passphrase: &[u8]) -> Result<BackupDecryptor> {
        BackupDecryptor::new(self, passphrase)
    }
}

/// Backup decryptor which decrypts backup items on the fly.
pub struct BackupDecryptor<'a> {
    backup: &'a Backup,
    cipher: Aes256Gcm,
}

impl<'a> BackupDecryptor<'a> {
    /// Create a new [`BackupDecryptor`] using a [`Backup`] and a passphrase.
    ///
    /// # Errors
    ///
    /// Even though this function returns a `Result` it is unlikely to fail since all parameters are
    /// static.
    fn new(backup: &'a Backup, passphrase: &[u8]) -> Result<Self> {
        let mut key = [0; 32];
        scrypt(
            passphrase,
            &backup.salt,
            &Params::new(14, 8, 16, 32).map_err(|_| Error::InvalidScryptParams)?,
            &mut key,
        )
        .map_err(|_| Error::ScryptKeyDerivation)?;
        let cipher = Aes256Gcm::new(&key.into());
        Ok(Self { backup, cipher })
    }

    /// Decrypts `ciphertext` while verifying additional data (`aad`).
    ///
    /// # Errors
    ///
    /// Returns:
    /// * [Error::Decryption] if a decryption error is encountered, for example the ciphertext is of
    ///   incorrect length, has been tampered with, the decryption passphrase is wrong or the
    ///   additional authenticated data is incorrect.
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let Some((nonce, msg)) = ciphertext.split_at_checked(12) else {
            return Err(Error::Decryption);
        };

        let payload = aes_gcm::aead::Payload { msg, aad };

        let plaintext = self
            .cipher
            .decrypt(nonce.into(), payload)
            .map_err(|_| Error::Decryption)?;
        Ok(plaintext)
    }

    /// Decrypted backup version.
    ///
    /// # Errors
    ///
    /// Returns:
    /// * [Error::Decryption] if a decryption error is encountered, for example the encrypted
    ///   version is of incorrect length, has been tampered with, the decryption passphrase is wrong
    ///   or the additional authenticated data is incorrect (e.g. a different encrypted piece of
    ///   data is impersonating the backup version).
    pub fn version(&self) -> Result<Vec<u8>> {
        self.decrypt(&self.backup.encrypted_version, b"backup-version")
    }

    /// Decrypted domain key.
    ///
    /// # Errors
    ///
    /// Returns:
    /// * [Error::Decryption] if a decryption error is encountered, for example the encrypted domain
    ///   key is of incorrect length, has been tampered with, the decryption passphrase is wrong or
    ///   the additional authenticated data is incorrect (e.g. a different encrypted piece of data
    ///   is impersonating the domain key).
    pub fn domain_key(&self) -> Result<Vec<u8>> {
        self.decrypt(&self.backup.encrypted_domain_key, b"domain-key")
    }

    /// Returns an iterator over backup entries.
    ///
    /// The entries are pairs of keys (which are strings) and values (byte vectors).
    /// Since the entries are decrypted as they are being read the pairs are wrapped in
    /// [`Result`]s.
    ///
    /// # Errors
    ///
    /// This function does not fail but reading the inner iterator may return errors:
    /// * [Error::Decryption] if a decryption error is encountered, for example the encrypted entry
    ///   is of incorrect length, has been tampered with, the decryption passphrase is wrong or the
    ///   additional authenticated data is incorrect (e.g. a different encrypted piece of data is
    ///   impersonating the backup entry).
    /// * [Error::Utf8] if the entry's key is not a well-formed UTF-8 string.
    pub fn items_iter(&'a self) -> impl Iterator<Item = Result<(String, Vec<u8>)>> + 'a {
        BackupItemDecryptor {
            decryptor: self,
            inner: self.backup.items.iter(),
        }
    }
}

/// Iterates over the entries of a backup and decrypts them on the fly.
///
/// This struct is a wrapper over an iterator of items of a [`Backup`].
/// It keeps a state of the current item being processed.
/// Each item is decrypted and then split into a UTF-8 string key and a value that is a byte vector.
struct BackupItemDecryptor<'a> {
    decryptor: &'a BackupDecryptor<'a>,
    inner: Iter<'a, Vec<u8>>,
}

impl Iterator for BackupItemDecryptor<'_> {
    type Item = Result<(String, Vec<u8>)>;

    /// Return next pair of key and value.
    ///
    /// # Errors
    ///
    /// Returns
    /// * [Error::Decryption] if a decryption error is encountered, for example the encrypted entry
    ///   is of incorrect length, has been tampered with, the decryption passphrase is wrong or the
    ///   additional authenticated data is incorrect (e.g. a different encrypted piece of data is
    ///   impersonating the backup entry).
    /// * [Error::Utf8] if the entry's key is not a well-formed UTF-8 string.
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| {
            let decrypted = self.decryptor.decrypt(item, b"backup")?;
            let mut reader = std::io::Cursor::new(decrypted);
            let key = String::from_utf8(read_field(&mut reader)?)?;
            let mut value = vec![];
            reader.read_to_end(&mut value)?;
            Ok((key, value))
        })
    }
}
