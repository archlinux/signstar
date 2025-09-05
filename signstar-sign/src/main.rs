//! Application for the creation of signatures from signing requests.

use std::process::ExitCode;

use clap::Parser;
use log::error;
use nethsm::{KeyId, NetHsm, OpenPgpKeyUsageFlags, OpenPgpUserId};
use pgp::{
    composed::Deserializable,
    crypto::public_key::PublicKeyAlgorithm,
    packet::{PubKeyInner, PublicKey},
    types::{KeyDetails, KeyVersion, Mpi, PublicParams, SecretKeyTrait},
};
use signstar_config::{
    CredentialsLoading,
    Error as ConfigError,
    UserMapping,
    config::base::{BackendConnection, YubiHsmConnection},
};
use signstar_request_signature::{Request, Response, Sha512};
use signstar_sign::cli::Cli;
use yubihsm::HttpConfig;

/// Signstar signing error.
#[derive(Debug, thiserror::Error)]
enum Error {
    /// Configuration does not contain key ID for the operator user.
    #[error("No key ID set for the operator user")]
    NoKeyId,

    /// Loading configuration encountered errors.
    #[error("Loading credentials encountered errors")]
    HasUserIdErrors,

    /// No credentials found for current system user.
    #[error("No credentials for the system user")]
    NoCredentials,

    /// Parameters of the signing request are unsupported.
    #[error("Unsupported signing request parameters")]
    UnsupportedParameters,

    /// Configuration error.
    #[error("Config error")]
    Config(#[from] ConfigError),

    /// NetHSM error.
    #[error("NetHsm error")]
    NetHsm(#[from] nethsm::Error),

    /// Signing request processing error.
    #[error("Signing request error: {0}")]
    SigningRequest(#[from] signstar_request_signature::Error),

    /// A signstar-common logging error.
    #[error(transparent)]
    SignstarCommonLogging(#[from] signstar_common::logging::Error),

    /// YubiHSM client error.
    #[error(transparent)]
    YubiHsmClient(#[from] yubihsm::client::Error),

    /// YubiHSM connector error.
    #[error(transparent)]
    YubiHsmConnector(#[from] yubihsm::connector::Error),

    /// YubiHSM domain error.
    #[error(transparent)]
    YubiHsmDomain(#[from] yubihsm::domain::Error),
}

trait StateSigner {
    fn sign(&self, state: Sha512) -> Result<String, Error>;
}

struct NetHsmStateSigner {
    nethsm: NetHsm,
    key_id: KeyId,
}

impl StateSigner for NetHsmStateSigner {
    fn sign(&self, state: Sha512) -> Result<String, Error> {
        Ok(self.nethsm.openpgp_sign_state(&self.key_id, state)?)
    }
}

struct YubiHsmSigner {
    public_key: PublicKey,
    yubihsm: yubihsm::client::Client,
    key_id: yubihsm::object::Id,
}

impl StateSigner for YubiHsmSigner {
    fn sign(&self, state: Sha512) -> Result<String, Error> {
        Ok(nethsm::openpgp::sign_hasher_state_with_signer(state, self)
            .map_err(nethsm::Error::OpenPgp)?)
    }
}

impl std::fmt::Debug for YubiHsmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YubiHsmSigner")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl KeyDetails for YubiHsmSigner {
    fn version(&self) -> pgp::types::KeyVersion {
        self.public_key.version()
    }

    fn fingerprint(&self) -> pgp::types::Fingerprint {
        self.public_key.fingerprint()
    }

    fn key_id(&self) -> pgp::types::KeyId {
        self.public_key.key_id()
    }

    fn algorithm(&self) -> pgp::crypto::public_key::PublicKeyAlgorithm {
        self.public_key.algorithm()
    }
}

impl SecretKeyTrait for YubiHsmSigner {
    fn create_signature(
        &self,
        _key_pw: &pgp::types::Password,
        _hash: pgp::crypto::hash::HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<pgp::types::SignatureBytes> {
        let sig = self
            .yubihsm
            .sign_ed25519(self.key_id, data)
            .expect("signing to work");
        Ok(pgp::types::SignatureBytes::Mpis(vec![
            Mpi::from_slice(sig.r_bytes()),
            Mpi::from_slice(sig.s_bytes()),
        ]))
    }

    fn hash_alg(&self) -> pgp::crypto::hash::HashAlgorithm {
        pgp::crypto::hash::HashAlgorithm::Sha512
    }
}

/// Creates a new [`StateSigner`] object with correct connection and user settings and returns it.
///
/// # Errors
///
/// Returns an error if configuration:
/// - loading encounters errors
/// - does not contain any key settings
/// - does not contain valid connections
/// - does not contain credentials with a passphrase
fn load_signer() -> Result<Box<dyn StateSigner>, Error> {
    let credentials_loading = CredentialsLoading::from_system_user()?;

    if credentials_loading.has_userid_errors() {
        return Err(Error::HasUserIdErrors);
    }

    if !credentials_loading.has_signing_user() {
        return Err(Error::NoCredentials);
    }

    let nethsm_key_id = if let UserMapping::SystemNetHsmOperatorSigning {
        nethsm_key_setup, ..
    } = credentials_loading.get_mapping().get_user_mapping()
    {
        Ok(nethsm_key_setup.get_key_id().clone())
    } else {
        Err(Error::NoKeyId)
    };

    let yubihsm_key_config = if let UserMapping::SystemYubiHsmOperatorSigning {
        yubihsm_key_id,
        yubihsm_key_domain,
        ..
    } = credentials_loading.get_mapping().get_user_mapping()
    {
        Ok((*yubihsm_key_id, *yubihsm_key_domain))
    } else {
        Err(Error::NoKeyId)
    };

    // Currently, this picks the first connection found.
    // The Signstar setup assumes, that multiple backends are used in a round-robin fashion, but
    // this is not yet implemented.
    if let Some(connection) = credentials_loading
        .get_mapping()
        .get_connections()
        .into_iter()
        .next()
    {
        let credentials = credentials_loading.credentials_for_signing_user()?;
        match connection {
            BackendConnection::NetHsm(connection) => Ok(Box::new(NetHsmStateSigner {
                nethsm: NetHsm::new(connection, Some(credentials.into()), None, None)?,
                key_id: nethsm_key_id?,
            })),
            BackendConnection::YubiHsm(connection) => {
                let connector = match &connection {
                    YubiHsmConnection::Mock => yubihsm::Connector::mockhsm(),
                    YubiHsmConnection::Usb { serial_number } => {
                        yubihsm::Connector::usb(&yubihsm::UsbConfig {
                            serial: Some(
                                serial_number.parse().expect("expected a valid serial no"),
                            ),
                            timeout_ms: yubihsm::UsbConfig::DEFAULT_TIMEOUT_MILLIS,
                        })
                    }
                    YubiHsmConnection::Http { address, port } => {
                        yubihsm::Connector::http(&HttpConfig {
                            addr: address.to_string(),
                            port: *port,
                            timeout_ms: 5000,
                        })
                    }
                };
                let client = yubihsm::client::Client::open(connector, Default::default(), true)?;

                let (key_id, yubihsm_key_domain) = yubihsm_key_config?;

                if connection == YubiHsmConnection::Mock {
                    // provision the mock HSM
                    client.generate_asymmetric_key(
                        key_id,
                        Default::default(),
                        yubihsm::domain::Domain::at(yubihsm_key_domain)?,
                        yubihsm::Capability::SIGN_EDDSA,
                        yubihsm::asymmetric::Algorithm::Ed25519,
                    )?;
                    let pubkey = &client.get_public_key(key_id)?.bytes;

                    let public_key = PublicKey::from_inner(
                        PubKeyInner::new(
                            KeyVersion::V4,
                            PublicKeyAlgorithm::EdDSALegacy,
                            chrono::DateTime::UNIX_EPOCH,
                            None,
                            PublicParams::EdDSALegacy(
                                pgp::types::EddsaLegacyPublicParams::Ed25519 {
                                    key: ed25519_dalek::VerifyingKey::from_bytes(
                                        &pubkey[..].try_into().unwrap(),
                                    )
                                    .unwrap(),
                                },
                            ),
                        )
                        .unwrap(),
                    )
                    .unwrap();

                    let signer = YubiHsmSigner {
                        public_key: public_key.clone(),
                        yubihsm: client.clone(),
                        key_id,
                    };

                    let mut flags = OpenPgpKeyUsageFlags::default();
                    flags.set_sign();

                    let cert = nethsm::openpgp::add_certificate_with_signer(
                        public_key,
                        flags,
                        OpenPgpUserId::new("Test".to_owned()).unwrap(),
                        nethsm::OpenPgpVersion::V4,
                        signer,
                    )
                    .unwrap();

                    // put the generated certificate as an opaque value with the same ID as the key
                    client.put_opaque(
                        key_id,
                        Default::default(),
                        yubihsm::domain::Domain::at(yubihsm_key_domain)?,
                        yubihsm::capability::Capability::empty(),
                        yubihsm::opaque::Algorithm::Data,
                        cert,
                    )?;
                }

                let cert = client.get_opaque(key_id)?;
                let public_key =
                    pgp::composed::SignedPublicKey::from_bytes(std::io::Cursor::new(cert))
                        .unwrap()
                        .primary_key;

                Ok(Box::new(YubiHsmSigner {
                    public_key,
                    yubihsm: client,
                    key_id,
                }))
            }
        }
    } else {
        Err(Error::NoCredentials)
    }
}

/// Signs the signing request in `reader` and write the response to the `writer`.
///
/// # Errors
///
/// Returns an error if:
///
/// - logging cannot be set up,
/// - a [`Request`] cannot be created from `reader`,
/// - the [`Request`] does not use OpenPGP v4,
/// - the [`Request`] is not version 1,
/// - a [`Sha512`] hasher state can not be created from the [`Request`],
/// - no [`NetHsm`] and [`KeyId`] can be retrieved for the calling user,
/// - a signature can not be created over the hasher state,
/// - or the [`Response`] can not be written to the `writer`.
fn sign_request(reader: impl std::io::Read, writer: impl std::io::Write) -> Result<(), Error> {
    let req = Request::from_reader(reader)?;

    if !req.required.output.is_openpgp_v4() {
        Err(Error::UnsupportedParameters)?;
    }

    if req.version.major != 1 {
        Err(Error::UnsupportedParameters)?;
    }

    let hasher: Sha512 = req.required.input.try_into()?;

    let signer = load_signer()?;

    let signature = signer.sign(hasher)?;

    Response::v1(signature).to_writer(writer)?;

    Ok(())
}

/// Signs the signing request on standard input and returns a signing response on standard output.
fn main() -> ExitCode {
    let args = Cli::parse();

    if let Err(error) = signstar_common::logging::setup_logging(args.verbosity) {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    let result = sign_request(std::io::stdin(), std::io::stdout());

    if let Err(error) = result {
        log::error!(error:err; "Processing signing request failed: {error:#?}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
