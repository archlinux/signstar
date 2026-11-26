//! Utilities for managing YubiHSM2 backups.
//!
//! # YubiHSM multi backup format
//!
//! The format's structure is as follows:
//!
//! - 4 magic bytes (0xBF, b'S', b'Y', b'B' - non printable continuation byte that makes the file
//!   invalid UTF-8)
//! - 1 version byte (always 0x00)
//! - N items encoded like so:
//!   - two zero bytes (0x0000)
//!   - two bytes for length (max object length 65535 - 0xFFFF)
//!   - array vector of given length, that vector will contain a yubihsm-wrap-compatible bytes:
//!     - 13 bytes of nonce
//!     - yubihsm-wrap-encrypted object
//! - end of backup marker:
//!   - two 0xFF bytes (0xFFFF)
//!   - two zero bytes (0x0000)
//!
//! This format allows easy destructuring into individual objects (e.g. for locally unwrapping the
//! key material) and conceptually resembles what NetHSM is using.
//!
//! Note that while the individual items may be authenticated using AEAD scheme the container is not
//! so an attacker could reorder, remove or append items.

mod wrap;
use std::io::{Error as IoError, ErrorKind, Read, Result};
use std::{fmt::Debug, io::Write};

pub use wrap::*;

const MAGIC: &[u8] = &[0xBF, b'S', b'Y', b'B'];
const V0: u8 = 0;
const ITEM_TAG: u16 = 0x0000;
const TRAILER_TAG: u16 = 0xffff;

/// YubiHSM2 backup writer.
///
/// Utility struct for creating YubiHSM2 backups containing multiple items.
/// The format is not authenticated but contains a trailer to detect accidental truncation.
///
/// If any of the public functions fail the backup should be considered corrupted.
#[derive(Debug)]
pub struct YubiHsm2BackupWriter<W: Write> {
    sink: W,
}

impl<W: Write> YubiHsm2BackupWriter<W> {
    /// Creates a new backup writer outputting the bytes into given sink.
    ///
    /// # Errors
    ///
    /// Returns an error if writing the magic or version fails.
    pub fn new(mut sink: W) -> Result<Self> {
        sink.write_all(MAGIC)?;
        sink.write_all(&[V0])?;
        Ok(Self { sink })
    }

    /// Appends a single tagged record to the source.
    ///
    /// # Errors
    ///
    /// Returns an error if writing data to the underlying sink fails or if the data length exceeds
    /// the maximum limit of [`u16::MAX`].
    fn append_record(&mut self, tag: u16, data: impl AsRef<[u8]>) -> Result<()> {
        let data = data.as_ref();
        let len = match u16::try_from(data.len()) {
            Ok(len) => len,
            Err(e) => return Err(IoError::new(ErrorKind::InvalidInput, e)),
        };
        self.sink.write_all(&tag.to_be_bytes())?;
        self.sink.write_all(&len.to_be_bytes())?;
        self.sink.write_all(data)?;
        Ok(())
    }

    /// Appends a single item to the backup.
    ///
    /// # Errors
    ///
    /// Returns an error if writing data to the underlying sink fails or if the data length exceeds
    /// the maximum limit of [`u16::MAX`].
    pub fn append(&mut self, item: impl AsRef<[u8]>) -> Result<()> {
        self.append_record(ITEM_TAG, item)
    }

    /// Finalizes the backup by appending the trailer and flushing the sink.
    ///
    /// # Errors
    ///
    /// Returns an error if writing data to the underlying sink fails.
    pub fn finalize(mut self) -> Result<W> {
        self.append_record(TRAILER_TAG, [])?;
        self.sink.flush()?;
        Ok(self.sink)
    }
}

/// YubiHSM2 backup reader.
///
/// Reads container files created by [`YubiHsm2BackupWriter`] returning them as [`Vec<u8>`]s.
///
/// The writer reads items until the trailer bits are found and then stops.
#[derive(Debug)]
pub struct YubiHsm2BackupReader<R: Read> {
    source: R,
    finalized: bool,
}

impl<R: Read> YubiHsm2BackupReader<R> {
    /// Creates a new reader from a given source.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the magic or the version fails or if they are of unexpected
    /// values.
    pub fn new(mut source: R) -> Result<Self> {
        let mut magic = [0; MAGIC.len()];
        source.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("unexpected magic {magic:?}"),
            ));
        }
        let mut version = [0; 1];
        source.read_exact(&mut version)?;
        if version != [V0] {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("unsupported version {version:?}"),
            ));
        }
        Ok(Self {
            source,
            finalized: false,
        })
    }

    /// Reads two bytes from the source and interprets them as big-endian [`u16`].
    ///
    /// # Errors
    ///
    /// Returns an error if reading the source fails.
    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0; 2];
        self.source.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    /// Reads `len` bytes from the source and returns them as a [`Vec<u8>`].
    ///
    /// # Errors
    ///
    /// Returns an error if reading the source fails.
    fn read_vec(&mut self, len: u16) -> Result<Vec<u8>> {
        let mut buf = vec![0; len as usize];
        self.source.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Reads a single item from the source.
    ///
    /// This function checks item tags. On success it returns the item bytes. If the source does not
    /// contain any more items it returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - reading the source fails,
    /// - invalid item tag has been encountered.
    pub fn read_item(&mut self) -> Result<Option<Vec<u8>>> {
        if self.finalized {
            return Ok(None);
        }
        let tag = self.read_u16()?;
        let len = self.read_u16()?;
        match (tag, len) {
            (ITEM_TAG, _) => Ok(Some(self.read_vec(len)?)),
            (TRAILER_TAG, 0) => {
                self.finalized = true;
                Ok(None)
            }
            (TRAILER_TAG, len) => Err(IoError::new(
                ErrorKind::InvalidData,
                format!("trailer tag length is not zero {len:?}"),
            )),
            (tag, _) => Err(IoError::new(
                ErrorKind::InvalidData,
                format!("unsupported tag {tag:?}"),
            )),
        }
    }

    /// Finalizes reading by checking for the trailer.
    ///
    /// This function returns the inner reader after parsing the backup is completed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - reading the source fails,
    /// - invalid item tag has been encountered,
    /// - there were more items to be read.
    pub fn finalize(mut self) -> Result<R> {
        if self.read_item()?.is_some() {
            return Err(ErrorKind::InvalidData.into());
        }
        Ok(self.source)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use testresult::TestResult;

    use super::*;

    #[test]
    fn serialize_empty() -> TestResult {
        let writer = YubiHsm2BackupWriter::new(Cursor::new(Vec::new()))?;
        let buf = writer.finalize()?.into_inner();
        assert_eq!(buf, &[0xBF, 83, 89, 66, 0x00, 0xff, 0xff, 0x00, 0x00]);

        let mut reader = YubiHsm2BackupReader::new(Cursor::new(buf))?;
        assert_eq!(reader.read_item()?, None);
        assert_eq!(reader.read_item()?, None);
        assert_eq!(reader.read_item()?, None);
        let buf = reader.finalize()?.into_inner();

        let reader = YubiHsm2BackupReader::new(Cursor::new(buf))?;
        reader.finalize()?;
        Ok(())
    }

    #[test]
    fn serialize_single() -> TestResult {
        let item = vec![1, 2, 3];
        let mut writer = YubiHsm2BackupWriter::new(Cursor::new(Vec::new()))?;
        writer.append(&item)?;
        let buf = writer.finalize()?.into_inner();
        assert_eq!(
            buf,
            &[
                0xBF, 83, 89, 66, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0xff, 0xff, 0x00,
                0x00
            ]
        );

        let mut reader = YubiHsm2BackupReader::new(Cursor::new(buf))?;
        assert_eq!(reader.read_item()?.as_ref(), Some(&item));
        assert_eq!(reader.read_item()?, None);
        assert_eq!(reader.read_item()?, None);
        let buf = reader.finalize()?.into_inner();

        let mut reader = YubiHsm2BackupReader::new(Cursor::new(buf))?;
        assert_eq!(reader.read_item()?.as_ref(), Some(&item));
        reader.finalize()?;
        Ok(())
    }

    #[test]
    fn serialize_two() -> TestResult {
        let first_item = vec![1, 2, 3];
        let second_item = vec![4, 5, 6];
        let mut writer = YubiHsm2BackupWriter::new(Cursor::new(Vec::new()))?;
        writer.append(&first_item)?;
        writer.append(&second_item)?;
        let buf = writer.finalize()?.into_inner();
        assert_eq!(
            buf,
            &[
                0xBF, 83, 89, 66, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00,
                0x03, 0x04, 0x05, 0x06, 0xff, 0xff, 0x00, 0x00
            ]
        );

        let mut reader = YubiHsm2BackupReader::new(Cursor::new(buf))?;
        assert_eq!(reader.read_item()?.as_ref(), Some(&first_item));
        assert_eq!(reader.read_item()?.as_ref(), Some(&second_item));
        assert_eq!(reader.read_item()?, None);
        let buf = reader.finalize()?.into_inner();

        let mut reader = YubiHsm2BackupReader::new(Cursor::new(buf))?;
        assert_eq!(reader.read_item()?.as_ref(), Some(&first_item));
        assert_eq!(reader.read_item()?.as_ref(), Some(&second_item));
        reader.finalize()?;
        Ok(())
    }
}
