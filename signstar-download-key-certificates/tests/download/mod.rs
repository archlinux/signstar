//! Integration tests for Signstar Download Key Certificates.

use std::{
    collections::HashMap,
    env::var,
    fs::{File, copy},
    io::Write,
    os::unix::fs::chown,
    path::{Path, PathBuf},
};

use actix_web::{App, HttpRequest, HttpServer, Responder, get};
use base64ct::{Base64, Encoding as _};
use change_user_run::{CommandOutput, run_command_as_user};
use log::{LevelFilter, debug, error, info};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rstest::rstest;
use signstar_common::logging::setup_terminal_logging;
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use signstar_config::config::MappingSystemUserId;
#[cfg(feature = "nethsm")]
use signstar_config::nethsm::NetHsmUserMapping;
#[cfg(feature = "yubihsm2")]
use signstar_config::yubihsm2::YubiHsm2UserMapping;
use signstar_config::{
    config::{Config, UserBackendConnection, UserBackendConnectionFilter},
    test::{
        ConfigFileConfig,
        ConfigFileLocation,
        ConfigFileVariant,
        SystemPrepareConfig,
        SystemUserConfig,
        list_files_in_dir,
    },
};
use signstar_download_key_certificates::{CertificateType, Certificates};
use tempfile::tempdir;
use testresult::TestResult;
use tokio::{spawn, task::yield_now};

/// The payload executable to run in tests.
const SIGNSTAR_DOWNLOAD_KEY_CERTIFICATES_PAYLOAD: &str = "signstar-download-key-certificates";
/// Environment variables that are passed in to a command call as a different user.
const ENV_LIST: &[&str] = &[
    "LLVM_PROFILE_FILE",
    "CARGO_LLVM_COV",
    "CARGO_LLVM_COV_SHOW_ENV",
    "CARGO_LLVM_COV_TARGET_DIR",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
];
/// The location of cargo-llvm-cov `.profraw` files when running a command as a different user.
const LLVM_PROFILE_FILE: &str = "/tmp/signstar-%p-%16m.profraw";

/// Collects all `.profraw` files from `path` and copies them to `CARGO_LLVM_COV_TARGET_DIR`.
///
/// Only copies files from `path` if the `CARGO_LLVM_COV_TARGET_DIR` environment variable is set.
/// Changes the ownership of files copied to `CARGO_LLVM_COV_TARGET_DIR` to root.
///
/// # Errors
///
/// Returns an error if
///
/// - `path` cannot be read,
/// - an entry in `path` cannot be read,
/// - copying a file from `path` to `CARGO_LLVM_COV_TARGET_DIR` fails,
/// - or changing the ownership permissions of a copied file in `CARGO_LLVM_COV_TARGET_DIR` to root
///   fails.
fn collect_coverage_files(path: impl AsRef<Path>) -> TestResult {
    let path = path.as_ref();
    list_files_in_dir(path)?;

    let Ok(cov_target_dir) = var("CARGO_LLVM_COV_TARGET_DIR") else {
        return Ok(());
    };
    debug!("Found CARGO_LLVM_COV_TARGET_DIR={cov_target_dir}");
    let cov_target_dir = PathBuf::from(cov_target_dir);

    for dir_entry in path.read_dir()? {
        let dir_entry = dir_entry?;
        let from = dir_entry.path();
        let Some(file_name) = &from.file_name() else {
            continue;
        };
        if let Some(extension) = from.extension()
            && extension == "profraw"
        {
            let target_file = cov_target_dir.join(file_name);
            debug!("Copying {from:?} to {target_file:?}");
            copy(&from, &target_file)?;
            chown(&target_file, Some(0), Some(0))?;
        }
    }

    Ok(())
}

#[get("//keys/signing1")]
async fn get_key(_req: HttpRequest) -> impl Responder {
    r#"{"type":"Curve25519","mechanisms":[],"restrictions":{},"operations":1}"#
}

#[get("//keys/signing1/cert")]
async fn get_cert(_req: HttpRequest) -> impl Responder {
    Base64::decode_vec(include_str!("cert.asc")).expect("static base64 data to be valid")
}

/// Runs the `signstar-sign` executable as a Unix user configured for signing.
///
/// Presents a mocked API surface when used with a NetHSM as backend.
#[rstest]
#[cfg_attr(
    feature = "nethsm",
    case::nethsm_plain_admin(
        SystemPrepareConfig{
            machine_id: true,
            credentials_socket: true,
            signstar_config: ConfigFileConfig {
                location: Some(ConfigFileLocation::default()),
                variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminSystemdCredsSingleConnection,
                system_user_config: Some(SystemUserConfig{ create_secrets: true, create_ssh_authorized_keys: true })
            },
        }
    )
)]
#[cfg_attr(
    feature = "_yubihsm2-mockhsm",
    case::yubihsm2_mockhsm_plain_admin(
        SystemPrepareConfig{
            machine_id: true,
            credentials_socket: true,
            signstar_config: ConfigFileConfig {
                location: Some(ConfigFileLocation::default()),
                variant: ConfigFileVariant::OnlyYubiHsm2MockHsmBackendAdminPlaintextNonAdminSystemdCreds,
                system_user_config: Some(SystemUserConfig{ create_secrets: true, create_ssh_authorized_keys: true  })
            },
        }
    )
)]
#[tokio::test]
async fn run_signstar_download_key_certificates(
    #[case] prepare_config: SystemPrepareConfig,
) -> TestResult {
    setup_terminal_logging(LevelFilter::Info)?;
    let _credentials_socket = prepare_config.apply()?;
    let config = Config::from_system_path()?;

    // Start a dummy web server to mock the interface used by the `signstar-sign` executable, if the
    // NetHSM backend is used.
    if matches!(
        prepare_config.signstar_config,
        ConfigFileConfig {
            variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminSystemdCredsSingleConnection,
            ..
        }
    ) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()])?;

        let dir = tempdir()?.keep();
        let key_file = dir.join("key.pem");
        let cert_file = dir.join("cert.pem");

        File::create_new(&key_file)?.write_all(signing_key.serialize_pem().as_bytes())?;
        File::create_new(&cert_file)?.write_all(cert.pem().as_bytes())?;

        spawn(async move {
            let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            builder
                .set_private_key_file(&key_file, SslFiletype::PEM)
                .unwrap();
            builder.set_certificate_chain_file(&cert_file).unwrap();

            HttpServer::new(|| {
                App::new()
                    .wrap(actix_web::middleware::Logger::default())
                    .service(get_cert)
                    .service(get_key)
            })
            .bind_openssl("127.0.0.1:8080", builder)
            .unwrap()
            .run()
            .await
        });

        // run the spawned task before we return from this function
        // see: https://docs.rs/tokio/latest/tokio/task/index.html#yield_now
        yield_now().await;
    }

    let mut tests_ran = 0;

    // Run `signstar-sign`, only using users configured for signing.
    for system_user_id in config
        .user_backend_connections(&[UserBackendConnectionFilter::NonAdmin])
        .iter()
        .filter_map(|user_backend_connection| match user_backend_connection {
            #[cfg(feature = "nethsm")]
            mapping @ UserBackendConnection::NetHsm {
                mapping: NetHsmUserMapping::CertificateRetrieval { .. },
                ..
            } => mapping.system_user_id(),

            #[cfg(feature = "yubihsm2")]
            mapping @ UserBackendConnection::YubiHsm2 {
                mapping: YubiHsm2UserMapping::CertificateRetrieval { .. },
                ..
            } => mapping.system_user_id(),
            _ => None,
        })
    {
        let CommandOutput {
            status,
            stdout,
            stderr,
            ..
        } = run_command_as_user(
            SIGNSTAR_DOWNLOAD_KEY_CERTIFICATES_PAYLOAD,
            &[],
            Some(include_bytes!(
                "../../../signstar-request-signature/tests/sample-request.json",
            )),
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            system_user_id.as_ref(),
        )?;
        if !status.success() {
            error!("Standard error: {stderr}");
        }
        assert!(
            status.success(),
            "requires the command to exit successfully but got {status}"
        );
        info!("Raw signing response: {stdout}");

        let certificates: Certificates = serde_json::from_str(&stdout)?;
        assert_ne!(certificates.certs.len(), 0);
        assert_eq!(
            certificates.certs[0].r#type,
            CertificateType::OpenPgp,
            "expected OpenPGP certificate"
        );

        tests_ran += 1;
    }

    assert_ne!(tests_ran, 0, "expected to run at least one test");

    collect_coverage_files("/tmp")?;

    Ok(())
}
