//! Integration tests for Signstar Sign.

use std::collections::HashMap;
use std::env::var;
use std::fs::copy;
use std::os::unix::fs::chown;
use std::path::{Path, PathBuf};
use std::{fs::File, io::Write};

use change_user_run::{CommandOutput, create_users, run_command_as_user};
use log::{LevelFilter, debug};
use pgp::composed::{Deserializable as _, DetachedSignature};
use rstest::rstest;
use signstar_common::logging::setup_logging;
use signstar_common::system_user::get_home_base_dir_path;
use signstar_config::test::{list_files_in_dir, prepare_system_with_config};
use tempfile::tempdir;
use testresult::TestResult;

use crate::utils::{SIGNSTAR_CONFIG_FULL, SIGNSTAR_CONFIG_PLAINTEXT};

const SIGNSTAR_SIGN_PAYLOAD: &str = "signstar-sign";
use actix_web::{App, HttpRequest, HttpServer, Responder, get, post};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use rcgen::{CertifiedKey, generate_simple_self_signed};

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

#[get("//keys/key1")]
async fn get_key(_req: HttpRequest) -> impl Responder {
    r#"{"type":"Curve25519","mechanisms":[],"restrictions":{},"operations":1}"#
}

#[get("//keys/key1/cert")]
async fn get_cert(_req: HttpRequest) -> impl Responder {
    BASE64_STANDARD
        .decode(
            r#"xjMEZ+VhSxYJKwYBBAHaRw8BAQdA2KONgN7kvXUBlnh5isobtDbLxBXQbsdohf87Df096mXNAS7CjwQQFggANwIZAQUCZ+VhSwIbAwgLCQgHCg0MCwUVCgkICwIWAgEnFiEEJ+rNVN734ABCNPFLpYLJVKxmFLEACgkQpYLJVKxmFLGh6QD/XdFJ7y52ag8H0DyBpCIRSFdl13BTT0bZf1d0TXIWIm8BAOO33aEXdEaxJBh7k60L6JxjATxWDKT+yMdXB76cD3QEzjgEZ+VhSxIKKwYBBAGXVQEFAQEHQPCHxYr7O6G09KDQ+gDVJCmHLaf5eH+LJ1BC6i1DBSRYAwEIB8J4BBgWCAAgBQJn5WFLAhsMFiEEJ+rNVN734ABCNPFLpYLJVKxmFLEACgkQpYLJVKxmFLFZ1QD/WDIyxKOxoOd/uI3GkWBlHl0BfI1ao9NvK5YcaOpQUycA/RC3vW9IwJIPPyegfDu96o9/GjB36O5QvttUHwLqY6oJ"#,
        )
        .unwrap()
}

#[post("//keys/key1/sign")]
async fn sign_data(_req: HttpRequest) -> impl Responder {
    r#"{"signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}"#
}

/// Loading credentials for unprivileged system users succeeds.
///
/// Tests integration with `systemd-creds` encrypted secrets and plaintext secrets.
#[rstest]
#[case::plain(SIGNSTAR_CONFIG_PLAINTEXT)]
#[case::full(SIGNSTAR_CONFIG_FULL)]
#[tokio::test]
async fn load_credentials_for_user(#[case] config_data: &[u8]) -> TestResult {
    use signstar_common::common::get_data_home;

    setup_logging(LevelFilter::Info)?;
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec!["localhost".into()])?;

    let dir = tempdir()?.keep();
    let key_file = dir.join("key.pem");
    let cert_file = dir.join("cert.pem");

    File::create_new(&key_file)?.write_all(signing_key.serialize_pem().as_bytes())?;
    File::create_new(&cert_file)?.write_all(cert.pem().as_bytes())?;

    tokio::spawn(async move {
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
                .service(sign_data)
        })
        .bind_openssl("127.0.0.1:8080", builder)
        .unwrap()
        .run()
        .await
    });

    // run the spawned task before we return from this function
    // see: https://docs.rs/tokio/latest/tokio/task/index.html#yield_now
    tokio::task::yield_now().await;

    let (creds_mapping, _credentials_socket) = prepare_system_with_config(config_data)?;
    assert!(
        !creds_mapping.is_empty(),
        "must contain at least one mapping"
    );
    // Get all system users
    let system_users = creds_mapping
        .iter()
        .filter_map(|mapping| {
            mapping
                .get_user_mapping()
                .get_system_user()
                .map(|user| user.to_string())
        })
        .collect::<Vec<String>>();
    // Create all system users and their homes
    create_users(
        &system_users
            .iter()
            .map(|user| user.as_str())
            .collect::<Vec<_>>(),
        Some(&get_home_base_dir_path()),
        None,
    )?;
    // Create secrets for each system user and their backend users
    for mapping in &creds_mapping {
        mapping.create_secrets_dir()?;
        mapping.create_non_administrative_secrets()?;
    }
    // List all files and directories in the data home.
    list_files_in_dir(get_data_home())?;

    let mut tests_ran = 0;

    // Retrieve backend credentials for each system user
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            use pgp::packet::SignatureType;

            let CommandOutput {
                status,
                stdout,
                stderr,
                ..
            } = run_command_as_user(
                SIGNSTAR_SIGN_PAYLOAD,
                &[],
                Some(
                    br#"{
  "version": "1.0.0",
  "required": {
    "input": {
      "type": "sha2-0.11-SHA512-state",
      "content": [
        8, 201, 188, 243, 103, 230, 9, 106, 59, 167, 202, 132, 133, 174, 103,
        187, 43, 248, 148, 254, 114, 243, 110, 60, 241, 54, 29, 95, 58, 245, 79,
        165, 209, 130, 230, 173, 127, 82, 14, 81, 31, 108, 62, 43, 140, 104, 5,
        155, 107, 189, 65, 251, 171, 217, 131, 31, 121, 33, 126, 19, 25, 205,
        224, 91, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 20, 73, 32,
        108, 105, 107, 101, 32, 115, 116, 114, 97, 119, 98, 101, 114, 114, 105,
        101, 115, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      ]
    },
    "output": {
      "type": "OpenPGPv4"
    }
  },
  "optional": {
    "request-time": 1728913277,
    "XHy1dHj": "https://gitlab.archlinux.org/archlinux/signstar/-/merge_requests/43"
  }
}
"#,
                ),
                ENV_LIST,
                Some(HashMap::from([(
                    "LLVM_PROFILE_FILE".to_string(),
                    LLVM_PROFILE_FILE.to_string(),
                )])),
                system_user_id.as_ref(),
            )?;
            if !status.success() {
                log::error!("Standard error: {stderr}");
            }
            assert!(
                status.success(),
                "requires the command to exit successfully but got {status}"
            );
            log::info!("Raw signing response: {stdout}");
            let response = signstar_request_signature::Response::from_reader(
                std::io::Cursor::new(stdout.as_bytes()),
            )?;
            log::info!("Parsed signing response: {response:#?}");
            assert_eq!(response.version.major, 1);
            let mut sig = Vec::new();
            response.signature_to_writer(&mut sig)?;
            let sig = std::io::Cursor::new(sig);
            let sig = DetachedSignature::from_armor_single(sig)?.0;
            assert_eq!(Some(SignatureType::Binary), sig.signature.typ());
            tests_ran += 1;
        } else {
            panic!("expected system user to be configured");
        }
    }

    assert_ne!(tests_ran, 0, "expected to run at least one test");

    collect_coverage_files("/tmp")?;

    Ok(())
}
