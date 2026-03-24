//! Utilities for parsing and creating YubiHSM2 wrap files.
//!
//! Wrap files are used for [backup and restore] actions with a YubiHSM2 device.
//! This module provides support for the proprietary YHW data format, used by Yubico tooling.
//!
//! The module supports backup of the following types of objects:
//! - ed25519 private keys (both seeded and expanded form),
//! - AES-128 authentication keys,
//! - opaque byte vectors.
//!
//! [backup and restore]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-backup-restore.html

use std::{array::TryFromSliceError, fmt::Debug};

use aes::{Aes128, cipher::typenum::Unsigned};
use base64ct::{Base64, Encoding as _};
use ccm::{
    Ccm,
    Nonce,
    aead::{Aead, KeyInit, rand_core::RngCore},
    consts::{U13, U16},
};
use curve25519_dalek::Scalar;
use ed25519_dalek::{SigningKey, hazmat::ExpandedSecretKey};
use num_enum::{FromPrimitive, IntoPrimitive};
use yubihsm::object::{Handle, Type};

use crate::object::{Domains, ObjectId};

/// Backup error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Base64 decoding error.
    #[error("Decoding Base64 failed: {0}")]
    Base64Decode(#[from] base64ct::Error),

    /// Decryption error.
    #[error("Decryption error: {0}")]
    Decrypt(#[from] ccm::Error),

    /// Slice length error.
    #[error("Incorrect slice length: {0}")]
    SliceLength(#[from] TryFromSliceError),

    /// Unexpected Ed25519 serialized form length.
    ///
    /// The only supported values are [ExpandedEd25519KeyData::LEN] and [SeedEd25519KeyData::LEN].
    #[error("Unexpected Ed25519 serialized form length: {actual}")]
    UnexpectedEd25519SerializedLength {
        /// Length of the serialized form encountered.
        actual: usize,
    },

    /// Unsupported object type.
    #[error("Cannot parse data of unknown type: {0:?}")]
    UnknownObjectType(ObjectType),

    /// Object error.
    #[error("YubiHSM2 object error: {0:?}")]
    YubiHsmObject(#[from] yubihsm::object::Error),

    /// Parsing failed because the buffer does not contain enough data.
    #[error("Parsing buffer: not enough data.")]
    InsufficientDataInBuffer,
}

/// The representation of data about to be wrapped (encrypted) with key.
pub struct PlainWrappedDataWithKey<'a, 'b> {
    /// Data that is being wrapped.
    pub data: &'a [u8],

    /// Wrapping key.
    pub key: &'b [u8],
}

impl Debug for PlainWrappedDataWithKey<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlainWrappedDataWithKey")
            .field("data", &self.data)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl TryFrom<PlainWrappedDataWithKey<'_, '_>> for YubiHsm2Wrap {
    type Error = Error;

    /// Encrypts `value.data` using a `value.key` and returns it as a new [`YubiHsm2Wrap`].
    ///
    /// # Errors
    ///
    /// Returns an error if encryption of `wrapped_data` with `wrapping_key` fails.
    fn try_from(value: PlainWrappedDataWithKey<'_, '_>) -> Result<Self, Self::Error> {
        let cipher = Aes128Ccm::new(value.key.into());
        let mut nonce = [0; 13];
        let mut rng = aes::cipher::crypto_common::rand_core::OsRng;
        rng.fill_bytes(&mut nonce);
        let mut wrapped = cipher.encrypt(Nonce::from_slice(&nonce), value.data)?;
        wrapped.splice(0..0, nonce);

        Ok(Self { wrapped })
    }
}

type Aes128Ccm = Ccm<Aes128, U16, U13>;

/// The representation of wrapped (encrypted) data of a YubiHSM2.
#[derive(Debug)]
pub struct YubiHsm2Wrap {
    wrapped: Vec<u8>,
}

impl YubiHsm2Wrap {
    /// Creates a new [`YubiHsm2Wrap`] from raw binary bytes.
    pub fn new(wrapped: Vec<u8>) -> Self {
        Self { wrapped }
    }

    /// Creates a new [`YubiHsm2Wrap`] from bytes containing the proprietary Yubico YHW format.
    ///
    /// # Note
    ///
    /// Leading and trailing whitespace are stripped.
    ///
    /// # Errors
    ///
    /// Returns an error if `wrapped` cannot be decoded from base64.
    pub fn from_yhw(wrapped: &str) -> Result<Self, Error> {
        let wrapped = wrapped.trim_ascii();
        let wrapped = Base64::decode_vec(wrapped)?;
        Ok(Self { wrapped })
    }

    /// Creates a [`String`] containing the representation of [`Self`] in the proprietary Yubico YHW
    /// format.
    pub fn to_yhw(&self) -> String {
        Base64::encode_string(&self.wrapped)
    }

    /// Decrypts the [`YubiHsm2Wrap`] using the provided `wrapping_key`.
    ///
    /// # Errors
    ///
    /// Returns an error if decrypting the data using `wrapping_key` fails.
    pub fn decrypt(&self, wrapping_key: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Aes128Ccm::new(wrapping_key.into());
        let (nonce, ciphertext) = self.wrapped.split_at(U13::to_usize());
        let plaintext = cipher.decrypt(nonce.into(), ciphertext)?;

        Ok(plaintext)
    }
}

impl AsRef<[u8]> for YubiHsm2Wrap {
    fn as_ref(&self) -> &[u8] {
        &self.wrapped
    }
}

/// The supported algorithms available for wrapping (encryption) of data.
///
/// See <https://github.com/Yubico/yubihsm-shell/blob/5a0447b9786d0e6149b67529789bd67530b38d6b/lib/yubihsm.h#L488-L515>.
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u8)]
pub enum WrapAlgorithm {
    /// CCM using AES-128 keys.
    Aes128Ccm = 29,

    /// CCM using AES-192 keys.
    Aes192Ccm = 41,

    /// CCM using AES-256 keys.
    Aes256Ccm = 42,

    /// Unknown wrap algorithm.
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// The object type contained in the backup.
///
/// All variants that are known (that is, all with the exception of [`ObjectType::Unknown`]) are
/// supported.
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u8)]
pub enum ObjectType {
    /// Ed25519.
    ///
    /// See <https://github.com/Yubico/yubihsm-shell/blob/5a0447b9786d0e6149b67529789bd67530b38d6b/lib/yubihsm.h#L520>.
    Ed25519 = 46,

    /// AES-128 used for authentication keys.
    ///
    /// See <https://github.com/Yubico/yubihsm-shell/blob/5a0447b9786d0e6149b67529789bd67530b38d6b/lib/yubihsm.h#L507C3-L507C45>.
    Aes128Auth = 38,

    /// Raw byte data.
    ///
    /// See <https://github.com/Yubico/yubihsm-shell/blob/5a0447b9786d0e6149b67529789bd67530b38d6b/lib/yubihsm.h#L491>.
    Opaque = 30,

    /// Unknown object type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// Expanded form of an ed25519 private key without seed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedEd25519KeyData<'a> {
    /// Private scalar.
    pub private_scalar: &'a [u8; 32],

    /// Private hash prefix.
    pub private_hash_prefix: &'a [u8; 32],

    /// Public key.
    pub public: &'a [u8; 32],
}

impl ExpandedEd25519KeyData<'_> {
    /// The number of bytes tracked in an [`ExpandedEd25519KeyData`].
    pub const LEN: usize = 32 * 3;
}

impl<'a> From<ExpandedEd25519KeyData<'a>> for ExpandedSecretKey {
    fn from(value: ExpandedEd25519KeyData<'a>) -> Self {
        let mut private_scalar = *value.private_scalar;
        private_scalar.reverse();
        ExpandedSecretKey {
            scalar: Scalar::from_bytes_mod_order(private_scalar),
            hash_prefix: *value.private_hash_prefix,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ExpandedEd25519KeyData<'a> {
    type Error = TryFromSliceError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            private_scalar: value[0..32].try_into()?,
            private_hash_prefix: value[32..64].try_into()?,
            public: value[64..].try_into()?,
        })
    }
}

/// The private parts of an ed25519 key.
///
/// # Note
///
/// The data includes the private key seed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeedEd25519KeyData<'a> {
    /// Private scalar.
    pub private_scalar: &'a [u8; 32],

    /// Private hash prefix.
    pub private_hash_prefix: &'a [u8; 32],

    /// Public key.
    pub public: &'a [u8; 32],

    /// Private key seed.
    pub private_seed: &'a [u8; 32],
}

impl SeedEd25519KeyData<'_> {
    /// The number of bytes tracked in a [`SeedEd25519KeyData`].
    pub const LEN: usize = 32 * 4;
}

impl<'a> TryFrom<&'a [u8]> for SeedEd25519KeyData<'a> {
    type Error = TryFromSliceError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            private_seed: value[0..32].try_into()?,
            private_scalar: value[32..64].try_into()?,
            private_hash_prefix: value[64..96].try_into()?,
            public: value[96..].try_into()?,
        })
    }
}

impl<'a> From<SeedEd25519KeyData<'a>> for ExpandedSecretKey {
    fn from(value: SeedEd25519KeyData<'a>) -> Self {
        let mut private_scalar = *value.private_scalar;
        private_scalar.reverse();

        // NOTE: `ExpandedSecretKey::from_slice` unnecessarily clamps the scalar
        ExpandedSecretKey {
            scalar: Scalar::from_bytes_mod_order(private_scalar),
            hash_prefix: *value.private_hash_prefix,
        }
    }
}

impl<'a> From<&'a SeedEd25519KeyData<'a>> for SigningKey {
    fn from(value: &'a SeedEd25519KeyData<'a>) -> Self {
        SigningKey::from(value.private_seed)
    }
}

/// An Ed25519 key serialized in YubiHSM2 specific format.
///
/// The serialized form, as accepted by the YubiHSM2, consists of four 32-byte values:
/// - secret key seed, from with the scalar and hash-prefix are derived,
/// - scalar value, used directly for signing,
/// - hash prefix, which is a domain separator used when hashing the message to generate the
///   pseudorandom `r` value,
/// - public key, used for verifying signed data.
#[derive(Debug)]
pub struct SerializedEd25519([u8; 32 * 4]);

impl AsRef<[u8]> for SerializedEd25519 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&SigningKey> for SerializedEd25519 {
    fn from(value: &SigningKey) -> Self {
        let mut result = [0; _];
        let expanded = ExpandedSecretKey::from(&value.to_bytes());
        result[0..32].copy_from_slice(value.as_bytes());
        result[32..64].copy_from_slice(expanded.scalar.as_bytes());
        result[32..64].reverse();
        result[64..96].copy_from_slice(&expanded.hash_prefix);
        result[96..].copy_from_slice(value.verifying_key().as_bytes());
        Self(result)
    }
}

/// An AES-128 based authentication key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthAes128<'a> {
    /// Delegated capabilities of the key.
    pub delegated_capabilities: &'a [u8; 8],

    /// Pair of symmetric keys used for encryption and MAC.
    pub symmetric_keys: &'a [u8; 32],
}

impl AuthAes128<'_> {
    /// The number of bytes tracked in an [`AuthAes128`].
    const LEN: usize = 8 + 32;
}

/// The deserialized body of a wrapped object.
///
/// This usually is the private key material for a signing or authentication object.
/// However, it can also represent [raw binary data][WrappedPayload::Opaque], which may have no
/// specific purpose in the context of the cryptographic functionalities of the YubiHSM2 hardware.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WrappedPayload<'a> {
    /// Ed25519 private key parts without the private key seed.
    ExpandedEd25519(ExpandedEd25519KeyData<'a>),

    /// Ed25519 private key parts with the private key seed.
    SeedEd25519(SeedEd25519KeyData<'a>),

    /// AES-128-based authentication key.
    AuthAes128(AuthAes128<'a>),

    /// Raw binary data.
    Opaque(&'a [u8]),
}

impl<'a> WrappedPayload<'a> {
    /// Parses raw bytes of specified object type into a [`WrappedPayload`] structure.
    ///
    /// Depending on the [`ObjectType`] the expected shape of `bytes` differs:
    /// - for ed25519 keys two forms are accepted: expanded (exactly 96 bytes) and seeded (128
    ///   bytes)
    /// - for AES-128 authentication keys, `bytes` need to be exactly 40 bytes long (8 bytes for
    ///   delecated capabilities and 32 for a pair of AES-128 keys)
    /// - opaque does not make any restrictions and will accept any `bytes`
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if:
    /// - private key material length is incorrect
    fn parse(object_type: ObjectType, bytes: &'a [u8]) -> Result<WrappedPayload<'a>, Error> {
        Ok(match object_type {
            ObjectType::Ed25519 => match bytes.len() {
                ExpandedEd25519KeyData::LEN => Self::ExpandedEd25519(bytes.try_into()?),
                SeedEd25519KeyData::LEN => Self::SeedEd25519(bytes.try_into()?),
                len => return Err(Error::UnexpectedEd25519SerializedLength { actual: len }),
            },
            ObjectType::Aes128Auth => {
                let (delegated_capabilities, symmetric_keys) = bytes.split_at(8);
                Self::AuthAes128(AuthAes128 {
                    delegated_capabilities: delegated_capabilities.try_into()?,
                    symmetric_keys: symmetric_keys.try_into()?,
                })
            }
            ObjectType::Opaque => Self::Opaque(bytes),
            object_type => return Err(Error::UnknownObjectType(object_type)),
        })
    }

    /// Serializes itself into the provided buffer.
    fn serialize_into(&self, buffer: &mut Vec<u8>) {
        match self {
            WrappedPayload::ExpandedEd25519(key_data) => {
                buffer.extend_from_slice(key_data.private_scalar);
                buffer.extend_from_slice(key_data.private_hash_prefix);
                buffer.extend_from_slice(key_data.public);
            }
            WrappedPayload::SeedEd25519(key_data) => {
                buffer.extend_from_slice(key_data.private_seed);
                buffer.extend_from_slice(key_data.private_scalar);
                buffer.extend_from_slice(key_data.private_hash_prefix);
                buffer.extend_from_slice(key_data.public);
            }
            WrappedPayload::AuthAes128(key_data) => {
                buffer.extend_from_slice(key_data.delegated_capabilities);
                buffer.extend_from_slice(key_data.symmetric_keys);
            }
            WrappedPayload::Opaque(key_data) => buffer.extend_from_slice(key_data),
        }
    }

    /// Returns the expected length of the serialized form.
    fn len(&self) -> usize {
        match self {
            WrappedPayload::ExpandedEd25519(_) => ExpandedEd25519KeyData::LEN,
            WrappedPayload::SeedEd25519(_) => SeedEd25519KeyData::LEN,
            WrappedPayload::AuthAes128(_) => AuthAes128::LEN,
            WrappedPayload::Opaque(key_data) => key_data.len(),
        }
    }
}

/// Reader of big-endian encoded bytes.
struct BeReader<'a> {
    pos: usize,
    buf: &'a [u8],
}

impl<'a> BeReader<'a> {
    /// Constructs a new reader backed by the specified buffer.
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the current position of this reader.
    fn position(&self) -> usize {
        self.pos
    }

    /// Reads one byte and forwards the reader's position.
    ///
    /// # Errors
    ///
    /// Returns an [error][Error::InsufficientDataInBuffer] if there are no more bytes to read.
    fn read_u8(&mut self) -> Result<u8, Error> {
        if self.pos + 1 >= self.buf.len() {
            return Err(Error::InsufficientDataInBuffer);
        }
        let byte = self.buf[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    /// Reads a [`u16`] and forwards the reader's position.
    ///
    /// # Errors
    ///
    /// Returns an [error][Error::InsufficientDataInBuffer] if there are insufficient bytes in the
    /// buffer.
    fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes([self.read_u8()?, self.read_u8()?]))
    }

    /// Reads a constant-size array and forwards the reader's position.
    ///
    /// # Errors
    ///
    /// Returns an [error][Error::InsufficientDataInBuffer] if there are insufficient bytes in the
    /// buffer.
    fn read<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        if self.pos + N >= self.buf.len() {
            return Err(Error::InsufficientDataInBuffer);
        }
        let bytes = &self.buf[self.pos..self.pos + N];
        self.pos += N;
        bytes
            .try_into()
            .map_err(|_| Error::InsufficientDataInBuffer)
    }

    /// Reads a constant-size array and forwards the reader's position.
    ///
    /// # Errors
    ///
    /// Returns an [error][Error::InsufficientDataInBuffer] if the reader has already been fully
    /// read.
    fn read_to_end(&mut self) -> Result<&'a [u8], Error> {
        if self.pos > self.buf.len() {
            return Err(Error::InsufficientDataInBuffer);
        }
        let bytes = &self.buf[self.pos..];
        self.pos = self.buf.len() + 1;
        Ok(bytes)
    }
}

/// Parsed representation of the backup's inner format.
#[derive(Debug)]
pub struct InnerFormat<'a> {
    /// Algorithm used for creating this wrap.
    pub wrap_algorithm: WrapAlgorithm,

    /// Capabilities of the wrapped object.
    pub capabilities: &'a [u8; 8],

    /// Identifier of the wrapped object.
    pub object_id: ObjectId,

    /// Domains of the wrapped object.
    pub domains: Domains,

    /// Type of the object.
    pub object_type: ObjectType,

    /// Sequence number, which is an internal number and is always `0`.
    pub sequence: u8,

    /// Key origin.
    pub origin: u8,

    /// Key label.
    pub label: String,

    /// Payload of the key.
    pub key_data: WrappedPayload<'a>,
}

impl<'a> InnerFormat<'a> {
    /// Parses the inner format from `raw`.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the buffer does not contain enough bytes for parsing
    /// - the data in the buffer is inconsistent
    /// - parsing private key material fails
    pub fn parse(raw: &'a [u8]) -> Result<Self, crate::Error> {
        let mut reader = BeReader::new(raw);

        let wrap_algorithm = WrapAlgorithm::from(reader.read_u8()?);
        let capabilities = reader.read()?;
        let id = reader.read_u16()?;
        let datalen = reader.read_u16()?;
        let domains = reader.read_u16()?.into();
        let object_id = ObjectId::try_from(Handle::new(
            id,
            Type::from_u8(reader.read_u8()?).map_err(Error::YubiHsmObject)?,
        ))?;
        let object_type = ObjectType::from(reader.read_u8()?);
        let sequence = reader.read_u8()?;
        let origin = reader.read_u8()?;

        let label = reader.read::<40>()?;
        let len = label.iter().position(|&b| b == 0).unwrap_or(label.len());
        let label = String::from_utf8_lossy(&label[..len]).into();

        // check if the datalen is consistent with the buffer's length
        if reader.position() + datalen as usize != raw.len() {
            return Err(Error::InsufficientDataInBuffer)?;
        }

        Ok(Self {
            wrap_algorithm,
            capabilities,
            object_id,
            domains,
            object_type,
            sequence,
            origin,
            label,
            key_data: WrappedPayload::parse(object_type, reader.read_to_end()?)?,
        })
    }

    /// Serializes this format into a list of bytes.
    pub fn serialize_into(&self, buffer: &mut Vec<u8>) {
        buffer.push(self.wrap_algorithm.into());
        buffer.extend_from_slice(self.capabilities);
        buffer.extend_from_slice(&u16::from(self.object_id.id()).to_be_bytes());
        buffer.extend_from_slice(&(self.key_data.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&self.domains.to_be_bytes());
        buffer.push(self.object_id.object_type().to_u8());
        buffer.push(self.object_type.into());
        buffer.push(self.sequence);
        buffer.push(self.origin);
        let mut label: [u8; 40] = [0; 40];
        let slice_len = self.label.len().min(label.len());
        label[..slice_len].copy_from_slice(self.label.as_bytes());
        buffer.extend_from_slice(&label);
        self.key_data.serialize_into(buffer);
    }
}

#[cfg(test)]
mod tests {

    use ed25519_dalek::VerifyingKey;
    use testresult::TestResult;

    use super::*;
    use crate::object::Domain;

    const WRAP_KEY: &[u8] = &[
        0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];

    #[test]
    fn decrypt_ed25519() -> TestResult {
        let wrap = YubiHsm2Wrap::from_yhw(include_str!("../tests/backup/private-ed25519.yhw"))?;
        let decrypted = wrap.decrypt(WRAP_KEY)?;
        assert!(!decrypted.is_empty());
        let inner = InnerFormat::parse(&decrypted)?;
        let mut buffer = vec![];
        inner.serialize_into(&mut buffer);
        assert_eq!(buffer, decrypted);
        assert_eq!(inner.object_type, ObjectType::Ed25519);
        assert_eq!(inner.wrap_algorithm, WrapAlgorithm::Aes128Ccm);
        assert_eq!(u16::from(inner.object_id.id()), 0x1f_u16);
        assert_eq!(inner.domains, Domain::One.into());
        assert_eq!(inner.sequence, 0);
        assert_eq!(inner.origin, 2);
        assert_eq!(inner.label, "Ed25519_Key");
        let WrappedPayload::ExpandedEd25519(key_data) = inner.key_data else {
            panic!("Expected Ed25519 key data");
        };
        let ExpandedEd25519KeyData {
            private_scalar,
            private_hash_prefix,
            public,
        } = key_data;

        assert_eq!(
            private_scalar,
            &[
                117, 188, 78, 175, 249, 221, 207, 75, 177, 26, 92, 146, 43, 19, 156, 7, 87, 43,
                173, 199, 232, 63, 249, 230, 100, 131, 86, 147, 80, 229, 193, 192
            ]
        );
        assert_eq!(
            private_hash_prefix,
            &[
                182, 113, 137, 6, 206, 62, 108, 30, 26, 138, 65, 215, 178, 10, 9, 215, 181, 55,
                132, 37, 162, 172, 202, 169, 56, 150, 245, 195, 212, 232, 235, 183
            ]
        );
        assert_eq!(
            public,
            &[
                185, 235, 254, 46, 190, 171, 17, 45, 56, 27, 211, 240, 69, 46, 39, 226, 53, 109,
                50, 78, 181, 96, 30, 177, 162, 240, 122, 187, 82, 30, 156, 242
            ]
        );
        let signing_key: ExpandedSecretKey = key_data.into();
        let verifying_key = VerifyingKey::from(&signing_key);
        assert_eq!(public, &verifying_key.to_bytes());
        Ok(())
    }

    #[test]
    fn decrypt_ed25519_with_seed() -> TestResult {
        let wrap =
            YubiHsm2Wrap::from_yhw(include_str!("../tests/backup/private-ed25519-seed.yhw"))?;
        let decrypted = wrap.decrypt(WRAP_KEY)?;
        assert!(!decrypted.is_empty());
        let inner = InnerFormat::parse(&decrypted)?;
        let mut buffer = vec![];
        inner.serialize_into(&mut buffer);
        assert_eq!(buffer, decrypted);
        assert_eq!(inner.object_type, ObjectType::Ed25519);
        assert_eq!(inner.wrap_algorithm, WrapAlgorithm::Aes128Ccm);
        assert_eq!(u16::from(inner.object_id.id()), 13);
        assert_eq!(inner.domains, Domains::all());
        assert_eq!(inner.sequence, 0);
        assert_eq!(inner.origin, 1);
        assert_eq!(inner.label, "Signature_Key_Ed_2");
        let WrappedPayload::SeedEd25519(key_data) = inner.key_data.clone() else {
            panic!("Expected Ed25519 key data");
        };

        let SeedEd25519KeyData {
            private_scalar,
            private_hash_prefix,
            public,
            private_seed,
        } = key_data;

        assert_eq!(
            private_seed,
            &[
                73, 122, 141, 156, 79, 125, 147, 201, 97, 207, 112, 15, 133, 155, 17, 216, 4, 254,
                88, 71, 207, 139, 63, 170, 229, 246, 54, 32, 206, 12, 84, 86
            ]
        );
        assert_eq!(
            private_scalar,
            &[
                7, 81, 112, 122, 75, 85, 173, 6, 20, 181, 199, 29, 147, 191, 157, 102, 147, 157,
                133, 249, 149, 223, 14, 41, 17, 51, 179, 38, 146, 102, 210, 15
            ]
        );
        assert_eq!(
            private_hash_prefix,
            &[
                161, 55, 166, 21, 136, 215, 184, 182, 181, 62, 143, 223, 62, 159, 19, 228, 179, 87,
                101, 158, 129, 137, 207, 186, 191, 206, 220, 148, 44, 83, 203, 115
            ]
        );
        assert_eq!(
            public,
            &[
                252, 157, 136, 36, 18, 36, 60, 188, 181, 153, 78, 169, 136, 74, 14, 210, 150, 203,
                47, 42, 79, 2, 238, 0, 103, 237, 202, 100, 87, 40, 252, 44
            ]
        );
        let signing_key = SigningKey::from(&key_data);
        let serialized = SerializedEd25519::from(&signing_key);
        assert_eq!(
            inner.key_data,
            WrappedPayload::parse(ObjectType::Ed25519, serialized.as_ref())?
        );

        assert_eq!(public, &signing_key.verifying_key().to_bytes());
        let exp = ExpandedSecretKey::from(private_seed);

        let mut private_scalar = *private_scalar;
        private_scalar.reverse();

        assert_eq!(exp.scalar.as_bytes(), &private_scalar);
        assert_eq!(&exp.hash_prefix, private_hash_prefix);

        let signing_key: ExpandedSecretKey = key_data.into();
        assert_eq!(exp.scalar, signing_key.scalar);
        assert_eq!(exp.hash_prefix, signing_key.hash_prefix);

        let verifying_key = VerifyingKey::from(&signing_key);
        assert_eq!(public, &verifying_key.to_bytes());
        Ok(())
    }

    #[test]
    fn auth_key() -> TestResult {
        let wrap = YubiHsm2Wrap::from_yhw(include_str!("../tests/backup/auth.yhw"))?;
        let decrypted = wrap.decrypt(WRAP_KEY)?;
        assert!(!decrypted.is_empty());
        let inner = InnerFormat::parse(&decrypted)?;
        let mut buffer = vec![];
        inner.serialize_into(&mut buffer);
        assert_eq!(decrypted, buffer);
        assert_eq!(inner.object_type, ObjectType::Aes128Auth);
        assert_eq!(inner.capabilities, &[0, 0, 0, 0, 0, 1, 0, 0]);
        assert_eq!(inner.domains, Domain::One.into());
        assert_eq!(u16::from(inner.object_id.id()), 14);
        assert_eq!(
            inner.key_data,
            WrappedPayload::AuthAes128(AuthAes128 {
                delegated_capabilities: &[0; 8],
                symmetric_keys: &[
                    152, 123, 73, 154, 181, 120, 84, 139, 48, 32, 41, 176, 213, 53, 39, 232, 122,
                    150, 131, 153, 10, 233, 98, 202, 67, 12, 27, 245, 184, 198, 41, 93
                ]
            })
        );
        assert_eq!(inner.object_id.object_type(), Type::AuthenticationKey);
        assert_eq!(inner.label, "");
        assert_eq!(inner.origin, 2);
        assert_eq!(inner.sequence, 0);
        Ok(())
    }

    #[test]
    fn opaque_data() -> TestResult {
        let wrap = YubiHsm2Wrap::from_yhw(include_str!("../tests/backup/opaque.yhw"))?;
        let decrypted = wrap.decrypt(WRAP_KEY)?;
        assert!(!decrypted.is_empty());
        let inner = InnerFormat::parse(&decrypted)?;
        let mut buffer = vec![];
        inner.serialize_into(&mut buffer);
        assert_eq!(decrypted, buffer);
        assert_eq!(inner.object_type, ObjectType::Opaque);
        assert_eq!(inner.capabilities, &[0, 0, 0, 0, 0, 1, 0, 0]);
        assert_eq!(inner.domains, Domain::One.into());
        assert_eq!(u16::from(inner.object_id.id()), 13);
        assert_eq!(inner.key_data, WrappedPayload::Opaque(&[1, 2, 3]));
        assert_eq!(inner.object_id.object_type(), Type::Opaque);
        assert_eq!(inner.label, "random");
        assert_eq!(inner.origin, 2);
        assert_eq!(inner.sequence, 0);
        Ok(())
    }

    #[test]
    fn roundtrip_yhw() -> TestResult {
        let input = include_str!("../tests/backup/private-ed25519-seed.yhw");
        let wrap = YubiHsm2Wrap::from_yhw(input)?;
        assert_eq!(input, wrap.to_yhw());
        Ok(())
    }

    #[test]
    fn encrypt_decrypt() -> TestResult {
        let input = include_str!("../tests/backup/opaque.yhw");
        let wrap = YubiHsm2Wrap::from_yhw(input)?;
        let decrypted_original = wrap.decrypt(WRAP_KEY)?;
        let plain = PlainWrappedDataWithKey {
            data: &decrypted_original,
            key: WRAP_KEY,
        };
        let wrap: YubiHsm2Wrap = plain.try_into()?;
        let decrypted_from_plain = wrap.decrypt(WRAP_KEY)?;
        assert_eq!(decrypted_original, decrypted_from_plain);
        Ok(())
    }
}
