#![doc = include_str!("../README.md")]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

use std::collections::HashMap;

use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::digest::crypto_common::hazmat::SerializableState;
pub use sha2::Sha512;

pub mod cli;

/// Signature request processing error.
#[derive(Debug, thiserror::Error)]
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
}

/// Type of the input hash.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Serialize, PartialEq, Eq, Deserialize)]
pub enum SignatureType {
    /// OpenPGP signature (version 4).
    #[serde(rename = "OpenPGPv4")]
    OpenPgpV4,
}

/// Input of the signing request process.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureRequestInput {
    #[serde(rename = "type")]
    hash_type: HashType,
    content: Vec<u8>,
}

/// Outputs of the signing process.
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
pub struct Required {
    /// Inputs of the signing procedure.
    pub input: SignatureRequestInput,

    /// Outputs of the signing procedure.
    pub output: SignatureRequestOutput,
}

/// Signing request.
#[derive(Debug, Serialize, Deserialize)]
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
    pub fn from_reader(reader: impl std::io::Read) -> Result<Self, Error> {
        let req: Request = serde_json::from_reader(reader)?;
        Ok(req)
    }

    /// Write the request as a JSON serialized form.
    pub fn to_writer(&self, writer: impl std::io::Write) -> Result<(), Error> {
        serde_json::to_writer(writer, &self)?;
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
