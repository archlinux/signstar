#![doc = include_str!("../README.md")]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::path::Path;
use std::time::SystemTime;
use std::{collections::HashMap, path::PathBuf};

use rand::Rng;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
pub use sha2::Sha512;
use sha2::digest::crypto_common::hazmat::SerializableState;

pub mod cli;
pub mod ssh;

/// Signature request processing error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid content type.
    #[error("Invalid content type. Found {actual:?} but expected {expected:?}.")]
    InvalidContentType {
        /// The content type that was found.
        actual: HashType,

        /// The content type that was expected.
        expected: HashType,
    },

    /// Malformed content size.
    #[error("Malformed content size")]
    InvalidContentSize,

    /// Deserialization of hasher's state failed.
    #[error("Deserialization of the hasher's state failed: {0}")]
    HasherDeserialization(#[from] sha2::digest::crypto_common::hazmat::DeserializeStateError),

    /// Request deserialization failed.
    #[error("Could not deserialize request: {0}")]
    RequestDeserialization(#[from] serde_json::Error),

    /// I/O error occurred.
    #[error("I/O error: {source} when processing {file}")]
    Io {
        /// File being processed.
        ///
        /// This field will be empty ([`PathBuf::new`]) if the error
        /// was encountered when processing generic I/O streams.
        file: PathBuf,

        /// Source error.
        source: std::io::Error,
    },

    /// System time error that occurs when the current time is before the reference time.
    #[error("Current time is before reference time {reference_time:?}: {source}")]
    CurrentTimeBeforeReference {
        /// The reference time.
        reference_time: SystemTime,
        /// The error source.
        source: std::time::SystemTimeError,
    },

    /// Requesting signing via SSH failed.
    #[error("SSH client error: {0}")]
    SshClient(#[from] crate::ssh::client::Error),
}

/// Type of the input hash.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HashType {
    /// State of the SHA-512 hasher, as understood by the [`sha2`
    /// crate](https://crates.io/crates/sha2) in version `0.11` and
    /// compatible.
    #[serde(rename = "sha2-0.11-SHA512-state")]
    #[allow(non_camel_case_types)]
    Sha2_0_11_Sha512_State,
}

/// The requested signature type.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SignatureType {
    /// OpenPGP signature (version 4).
    #[serde(rename = "OpenPGPv4")]
    OpenPgpV4,
}

/// Input of the signing request process.
#[derive(Debug, Deserialize, Serialize)]
pub struct SignatureRequestInput {
    #[serde(rename = "type")]
    hash_type: HashType,
    content: Vec<u8>,
}

/// Outputs of the signing process.
#[derive(Debug, Deserialize, Serialize)]
pub struct SignatureRequestOutput {
    /// Type of the signature to be produced.
    #[serde(rename = "type")]
    sig_type: SignatureType,
}

impl SignatureRequestOutput {
    /// Create a new signature output which asks for OpenPGP (version
    /// 4) signature.
    pub fn new_openpgp_v4() -> Self {
        Self {
            sig_type: SignatureType::OpenPgpV4,
        }
    }

    /// Indicates if the signature output should be OpenPGP (version
    /// 4).
    pub fn is_openpgp_v4(&self) -> bool {
        self.sig_type == SignatureType::OpenPgpV4
    }
}

impl From<sha2::Sha512> for SignatureRequestInput {
    fn from(value: sha2::Sha512) -> Self {
        Self {
            hash_type: HashType::Sha2_0_11_Sha512_State,
            content: value.serialize().to_vec(),
        }
    }
}

impl TryFrom<SignatureRequestInput> for sha2::Sha512 {
    type Error = Error;
    fn try_from(value: SignatureRequestInput) -> Result<Self, Self::Error> {
        if value.hash_type != HashType::Sha2_0_11_Sha512_State {
            return Err(Error::InvalidContentType {
                actual: value.hash_type,
                expected: HashType::Sha2_0_11_Sha512_State,
            });
        }

        let hasher = sha2::Sha512::deserialize(
            value.content[..]
                .try_into()
                .map_err(|_| Error::InvalidContentSize)?,
        )?;

        Ok(hasher)
    }
}

/// Required parameters for the signing request operation.
#[derive(Debug, Deserialize, Serialize)]
pub struct Required {
    /// Inputs of the signing procedure.
    pub input: SignatureRequestInput,

    /// Outputs of the signing procedure.
    pub output: SignatureRequestOutput,
}

/// Signing request.
#[derive(Debug, Deserialize, Serialize)]
pub struct Request {
    /// Version of this signing request.
    pub version: Version,

    /// Required parameters of the signing process.
    ///
    /// All required parameters must be understood by the signing
    /// process or the entire request is to be rejected.
    pub required: Required,

    /// Optional parameters for the signing process.
    ///
    /// The server may ignore any or all parameters in this group. If
    /// any parameter is not understood by the server it must be
    /// ignored.
    pub optional: HashMap<String, Value>,
}

impl Request {
    /// Read the request from a JSON serialized bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the file fails or the file contents
    /// are not well-formed.
    pub fn from_reader(reader: impl std::io::Read) -> Result<Self, Error> {
        let req: Request = serde_json::from_reader(reader)?;
        Ok(req)
    }

    /// Write the request as a JSON serialized form.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization of the request fails or writing to
    /// the `writer` encounters an error.
    pub fn to_writer(&self, writer: impl std::io::Write) -> Result<(), Error> {
        serde_json::to_writer(writer, &self)?;
        Ok(())
    }

    /// Prepares a signing request for a file.
    ///
    /// Given a file as an `input` this function creates a well-formed request.
    /// That request is of latest known version and contains all necessary fields.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the file fails or forming the request encounters
    /// an error.
    ///
    /// # Examples
    ///
    /// The following example creates a signing request for `Cargo.toml`:
    ///
    /// ```
    /// # fn main() -> testresult::TestResult {
    /// use signstar_request_signature::Request;
    ///
    /// let signing_request = Request::for_file("Cargo.toml")?;
    /// # Ok(()) }
    /// ```
    pub fn for_file(input: impl AsRef<Path>) -> Result<Self, Error> {
        let input = input.as_ref();
        let pack_err = |source| Error::Io {
            file: input.into(),
            source,
        };
        let hasher = {
            let mut hasher = sha2::Sha512::new();
            std::io::copy(
                &mut std::fs::File::open(input).map_err(pack_err)?,
                &mut hasher,
            )
            .map_err(pack_err)?;
            hasher
        };
        let required = Required {
            input: hasher.into(),
            output: SignatureRequestOutput::new_openpgp_v4(),
        };

        // Add "grease" so that the server can handle any optional data
        // See: https://lobste.rs/s/utmsph/age_plugins#c_i76hkd
        // See: https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417
        let grease: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();

        Ok(Self {
            version: semver::Version::new(1, 0, 0),
            required,
            optional: vec![
                (
                    grease,
                    Value::String(
                        "https://gitlab.archlinux.org/archlinux/signstar/-/merge_requests/43"
                            .to_string(),
                    ),
                ),
                (
                    "request-time".into(),
                    Value::Number(
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map_err(|source| crate::Error::CurrentTimeBeforeReference {
                                reference_time: SystemTime::UNIX_EPOCH,
                                source,
                            })?
                            .as_secs()
                            .into(),
                    ),
                ),
                (
                    "file-name".into(),
                    input
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(Into::into)
                        .unwrap_or(Value::Null),
                ),
            ]
            .into_iter()
            .collect(),
        })
    }
}

/// The response to a signing request.
///
/// Tracks the `version` of the signing response and the signature as `signature`.
///
/// The details of the format are documented in the [response specification].
///
/// [response specification]: https://signstar.archlinux.page/signstar-request-signature/resources/docs/response.html
#[derive(Debug, Deserialize, Serialize)]
pub struct Response {
    /// Version of this signing response.
    pub version: Version,

    /// Raw content of the signature.
    signature: String,
}

impl Response {
    /// Creates a version 1 compatible signature from raw signature content.
    pub fn v1(signature: String) -> Self {
        Self {
            version: Version::new(1, 0, 0),
            signature,
        }
    }

    /// Creates a [`Response`] from a `reader` of JSON formatted bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization from `reader` fails.
    pub fn from_reader(reader: impl std::io::Read) -> Result<Self, Error> {
        let resp: Self = serde_json::from_reader(reader)?;
        Ok(resp)
    }

    /// Writes the [`Response`] to a `writer` in JSON serialized form.
    ///
    /// # Errors
    ///
    /// Returns an error if `self` can not be serialized or if writing to `writer` fails.
    pub fn to_writer(&self, writer: impl std::io::Write) -> Result<(), Error> {
        serde_json::to_writer(writer, &self)?;
        Ok(())
    }

    /// Writes the raw signature of the [`Response`] to a `writer`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature can not be written to the `writer`.
    pub fn signature_to_writer(&self, mut writer: impl std::io::Write) -> Result<(), Error> {
        writer
            .write_all(self.signature.as_bytes())
            .map_err(|source| Error::Io {
                file: PathBuf::new(),
                source,
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rstest::rstest;
    use sha2::Digest;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn hash_values_are_predictable() -> testresult::TestResult {
        let mut hasher = sha2::Sha512::new();
        let mut bytes = std::io::Cursor::new(b"this is sample text");
        std::io::copy(&mut bytes, &mut hasher)?;
        let result: &[u8] = &hasher.serialize();

        let expected_state = [
            8, 201, 188, 243, 103, 230, 9, 106, 59, 167, 202, 132, 133, 174, 103, 187, 43, 248,
            148, 254, 114, 243, 110, 60, 241, 54, 29, 95, 58, 245, 79, 165, 209, 130, 230, 173,
            127, 82, 14, 81, 31, 108, 62, 43, 140, 104, 5, 155, 107, 189, 65, 251, 171, 217, 131,
            31, 121, 33, 126, 19, 25, 205, 224, 91, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            64, 19, 116, 104, 105, 115, 32, 105, 115, 32, 115, 97, 109, 112, 108, 101, 32, 116,
            101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        assert_eq!(result, expected_state);

        let expected_digest = [
            20, 253, 69, 133, 146, 76, 11, 4, 191, 13, 150, 196, 9, 97, 21, 35, 186, 95, 254, 59,
            148, 60, 88, 155, 127, 203, 151, 216, 11, 16, 228, 73, 113, 23, 115, 110, 198, 42, 109,
            92, 23, 33, 70, 71, 136, 219, 73, 238, 135, 13, 223, 117, 215, 69, 243, 33, 125, 109,
            95, 121, 213, 44, 212, 166,
        ];

        let hasher = sha2::Sha512::deserialize(&expected_state.into())?;
        let hash = &hasher.finalize()[..];
        assert_eq!(hash, expected_digest);

        //let hasher = old_sha2::Sha512::deserialize(&expected_state.try_into()?)?;
        //let hash = &hasher.finalize()[..];
        //assert_eq!(hash, expected_digest);

        Ok(())
    }

    #[test]
    fn sample_request_is_ok() -> TestResult {
        let reader = std::fs::File::open("tests/sample-request.json")?;
        let reader = Request::from_reader(reader)?;
        let hasher: sha2::Sha512 = reader.required.input.try_into()?;
        assert_eq!(
            hasher.finalize(),
            [
                85, 185, 86, 249, 187, 64, 117, 47, 163, 40, 201, 53, 35, 169, 119, 90, 168, 78,
                29, 32, 20, 55, 39, 121, 253, 203, 159, 82, 85, 40, 233, 26, 208, 13, 111, 61, 93,
                100, 199, 31, 185, 140, 195, 114, 92, 118, 108, 237, 100, 152, 212, 177, 189, 56,
                146, 204, 137, 76, 235, 31, 101, 1, 19, 55
            ]
        );
        Ok(())
    }

    #[rstest]
    fn sample_request_is_bad(#[files("tests/bad-*.json")] request_file: PathBuf) -> TestResult {
        let reader = std::fs::File::open(request_file)?;
        assert!(
            Request::from_reader(reader).is_err(),
            "parsing of the request file should fail"
        );
        Ok(())
    }
}
