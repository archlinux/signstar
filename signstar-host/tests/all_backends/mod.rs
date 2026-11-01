//! Containerized integration tests for `signstar-host` with all possible backends enabled.

#![cfg(all(
    feature = "nethsm",
    feature = "_containerized-integration-test",
    feature = "yubihsm2"
))]

use log::LevelFilter;
use signstar_common::logging::setup_terminal_logging;
use signstar_config::test::{
    ConfigFileConfig,
    ConfigFileLocation,
    ConfigFileVariant,
    SystemPrepareConfig,
    SystemUserConfig,
    SystemUserConfigSettings,
};
use signstar_host::{
    config::load_config,
    configure::{ConfigurationResult, HostConfiguration},
};
use testresult::TestResult;

/// The certificate for a signing key
const SIGNING_KEY_CERTIFICATE: &str = include_str!("../fixtures/cert.asc");

/// Tests against all available backend types.
mod all {
    use super::*;

    /// Tests for `signstar-configure`.
    mod configure {
        use super::*;

        /// Ensures, that [`HostConfiguration::sync`] aborts if a Signstar configuration file is
        /// present in one of the default system locations but no physical NetHSM and
        /// YubiHSM2 backend is available.
        #[test]
        fn host_configuration_sync_aborts_on_unavailable_backend_connections() -> TestResult {
            setup_terminal_logging(LevelFilter::Debug)?;

            let mut system_prepare_config = SystemPrepareConfig {
                machine_id: false,
                credentials_socket: false,
                signstar_config: ConfigFileConfig {
                    location: Some(ConfigFileLocation::UsrShare),
                    variant: ConfigFileVariant::AllBackendsAdminPlaintextNonAdminPlaintext,
                    system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: false,
                        create_ssh_authorized_keys: true,
                    })),
                },
            };
            system_prepare_config.apply()?;

            let config = load_config()?;
            let host_configuration = HostConfiguration::new(&config);
            let configuration_result = host_configuration.sync()?;

            assert_eq!(
                configuration_result,
                ConfigurationResult::NoAvailableBackendConnection
            );

            Ok(())
        }

        #[cfg(feature = "cli")]
        mod cli {
            use std::process::{ExitCode, Termination};

            use assert_cmd::cargo::cargo_bin_cmd;

            use super::*;

            /// Ensures, that calling the `signstar-configure` CLI aborts on unavailable backend
            /// connections.
            #[test]
            fn abort_on_unavailable_backend_connections() -> TestResult {
                setup_terminal_logging(LevelFilter::Debug)?;

                let mut system_prepare_config = SystemPrepareConfig {
                    machine_id: false,
                    credentials_socket: false,
                    signstar_config: ConfigFileConfig {
                        location: Some(ConfigFileLocation::UsrShare),
                        variant: ConfigFileVariant::AllBackendsAdminPlaintextNonAdminPlaintext,
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                            create_secrets: false,
                            create_ssh_authorized_keys: true,
                        })),
                    },
                };
                system_prepare_config.apply()?;

                let exit_code = {
                    let mut command = cargo_bin_cmd!("signstar-configure");
                    let output = command
                        .arg("--verbose")
                        .arg("--verbose")
                        .arg("--verbose")
                        .output()?;

                    ExitCode::from(u8::try_from(
                        output.status.code().expect("there to be an exit code"),
                    )?)
                };

                assert_eq!(
                    exit_code,
                    ConfigurationResult::NoAvailableBackendConnection.report()
                );

                Ok(())
            }

            /// Ensures, that calling the `signstar-configure` CLI aborts on no configuration items
            /// for any backends.
            #[test]
            fn abort_on_no_config_item_form_backends() -> TestResult {
                setup_terminal_logging(LevelFilter::Debug)?;

                let mut system_prepare_config = SystemPrepareConfig {
                    machine_id: false,
                    credentials_socket: false,
                    signstar_config: ConfigFileConfig {
                        location: Some(ConfigFileLocation::UsrShare),
                        variant: ConfigFileVariant::NoBackendAdminPlaintextNonAdminPlaintext,
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                            create_secrets: false,
                            create_ssh_authorized_keys: true,
                        })),
                    },
                };
                system_prepare_config.apply()?;

                let exit_code = {
                    let mut command = cargo_bin_cmd!("signstar-configure");
                    let output = command
                        .arg("--verbose")
                        .arg("--verbose")
                        .arg("--verbose")
                        .output()?;

                    ExitCode::from(u8::try_from(
                        output.status.code().expect("there to be an exit code"),
                    )?)
                };

                assert_eq!(
                    exit_code,
                    ConfigurationResult::MissingConfigurationForBackend.report()
                );

                Ok(())
            }

            /// Ensures, that calling the `signstar-configure` CLI fails on no configuration file.
            #[test]
            fn fail_on_no_configuration_file() -> TestResult {
                setup_terminal_logging(LevelFilter::Debug)?;

                let mut system_prepare_config = SystemPrepareConfig {
                    machine_id: false,
                    credentials_socket: false,
                    signstar_config: ConfigFileConfig {
                        location: None,
                        variant: ConfigFileVariant::NoBackendAdminPlaintextNonAdminPlaintext,
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                            create_secrets: false,
                            create_ssh_authorized_keys: true,
                        })),
                    },
                };
                system_prepare_config.apply()?;

                let exit_code = {
                    let mut command = cargo_bin_cmd!("signstar-configure");
                    let output = command
                        .arg("--verbose")
                        .arg("--verbose")
                        .arg("--verbose")
                        .output()?;

                    ExitCode::from(u8::try_from(
                        output.status.code().expect("there to be an exit code"),
                    )?)
                };

                assert_eq!(exit_code, ExitCode::FAILURE);

                Ok(())
            }
        }
    }

    /// Tests for `signstar-download-key-certificates`.
    mod download_key_certificates {
        use std::{collections::HashMap, fs::File, io::Write};

        use actix_web::{App, HttpRequest, HttpServer, Responder, get, middleware::Logger};
        use base64ct::{Base64, Encoding as _};
        use change_user_run::{
            COVERAGE_ENV_LIST,
            CommandOutput,
            collect_coverage_data,
            run_command_as_user,
        };
        use log::{error, info};
        use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use rstest::rstest;
        use signstar_common::{
            backend::BackendType,
            request_api::{CertificateType, Certificates},
        };
        #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
        use signstar_config::config::MappingSystemUserId;
        #[cfg(feature = "nethsm")]
        use signstar_config::nethsm::NetHsmUserMapping;
        #[cfg(feature = "yubihsm2")]
        use signstar_config::yubihsm2::YubiHsm2UserMapping;
        use signstar_config::{
            config::{UserBackendConnection, UserBackendConnectionFilter},
            test::{
                ConfigFileConfig,
                ConfigFileLocation,
                ConfigFileVariant,
                SystemPrepareConfig,
                SystemUserConfig,
            },
        };
        use tempfile::tempdir;
        use tokio::{spawn, task::yield_now};

        use super::*;

        /// The payload executable to run in tests.
        const SIGNSTAR_DOWNLOAD_KEY_CERTIFICATES_PAYLOAD: &str =
            "signstar-download-key-certificates";

        /// The location of cargo-llvm-cov `.profraw` files when running a command as a different
        /// user.
        const LLVM_PROFILE_FILE: &str = "/tmp/signstar-%p-%16m.profraw";

        /// Responder for the NetHSM key `signing1`.
        #[get("//keys/signing1")]
        async fn get_key(_req: HttpRequest) -> impl Responder {
            r#"{"type":"Curve25519","mechanisms":[],"restrictions":{},"operations":1}"#
        }

        /// Responder for the NetHSM key certificate for key `signing1`.
        #[get("//keys/signing1/cert")]
        async fn get_cert(_req: HttpRequest) -> impl Responder {
            Base64::decode_vec(SIGNING_KEY_CERTIFICATE)
                .expect("signing key certificate fixture to be valid")
        }

        /// Runs the `signstar-sign` executable as a Unix user configured for signing.
        ///
        /// Presents a mocked API surface when used with a NetHSM as backend.
        #[rstest]
        #[cfg_attr(
            feature = "nethsm",
            case::nethsm_plain_admin(
                SystemPrepareConfig {
                    machine_id: true,
                    credentials_socket: true,
                    signstar_config: ConfigFileConfig {
                        location: Some(ConfigFileLocation::default()),
                        variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminSystemdCredsSingleConnection,
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: true,
                        create_ssh_authorized_keys: true,
                    }))
                    },
                }
            )
        )]
        #[cfg_attr(
            feature = "_yubihsm2-mockhsm",
            case::yubihsm2_mockhsm_plain_admin(
                SystemPrepareConfig {
                    machine_id: true,
                    credentials_socket: true,
                    signstar_config: ConfigFileConfig {
                        location: Some(ConfigFileLocation::default()),
                        variant: ConfigFileVariant::OnlyYubiHsm2MockHsmBackendAdminPlaintextNonAdminSystemdCreds,
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: true,
                        create_ssh_authorized_keys: true,
                    }))
                    },
                }
            )
        )]
        #[tokio::test]
        async fn run_signstar_download_key_certificates(
            #[case] mut prepare_config: SystemPrepareConfig,
        ) -> TestResult {
            setup_terminal_logging(LevelFilter::Info)?;
            let _credentials_socket = prepare_config.apply()?;
            let config = load_config()?;

            // Start a dummy web server to mock the interface used by the
            // `signstar-download-key-certificates` executable, if the NetHSM backend is
            // used.

            if prepare_config
                .signstar_config
                .variant
                .contains_backend(BackendType::NetHsm)
            {
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
                            .wrap(Logger::default())
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

            // Collect the list of system users setup for certificate retrieval and use the first
            // one found.
            let Some(system_user_id) = config
                .user_backend_connections(&[UserBackendConnectionFilter::NonAdmin])
                .iter()
                .filter_map(|user_backend_connection| match user_backend_connection {
                    #[cfg(feature = "nethsm")]
                    mapping @ UserBackendConnection::NetHsm {
                        mapping: NetHsmUserMapping::CertificateRetrieval { .. },
                        ..
                    } => mapping.system_user_id().cloned(),

                    #[cfg(feature = "yubihsm2")]
                    mapping @ UserBackendConnection::YubiHsm2 {
                        mapping: YubiHsm2UserMapping::CertificateRetrieval { .. },
                        ..
                    } => mapping.system_user_id().cloned(),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .first()
                .cloned()
            else {
                panic!("expected there to be at least one user setup for certificate retrieval");
            };

            // Run as user configured for certificate retrieval.
            let CommandOutput {
                status,
                stdout,
                stderr,
                ..
            } = run_command_as_user(
                SIGNSTAR_DOWNLOAD_KEY_CERTIFICATES_PAYLOAD,
                &[],
                Some(include_bytes!(
                    "../../../fixtures/request/sample-request.json",
                )),
                COVERAGE_ENV_LIST,
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

            collect_coverage_data("/tmp")?;

            Ok(())
        }
    }

    /// Tests for `signstar-sign`.
    mod sign {
        #[cfg(feature = "_yubihsm2-mockhsm")]
        use std::str::FromStr;
        use std::{
            collections::HashMap,
            fs::File,
            io::{Cursor, Write},
            sync::Arc,
        };

        use actix_web::{
            App,
            HttpRequest,
            HttpServer,
            Responder,
            get,
            post,
            web::{self, Data},
        };
        use base64ct::{Base64, Encoding as _};
        use change_user_run::{
            COVERAGE_ENV_LIST,
            CommandOutput,
            collect_coverage_data,
            run_command_as_user,
        };
        use log::{error, info};
        use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
        use pgp::{
            composed::{Deserializable as _, DetachedSignature},
            packet::SignatureType,
        };
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use rstest::rstest;
        use signstar_common::{
            backend::BackendType,
            logging::setup_terminal_logging,
            request_api::Response,
        };
        #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
        use signstar_config::config::MappingSystemUserId;
        #[cfg(feature = "nethsm")]
        use signstar_config::nethsm::NetHsmUserMapping;
        #[cfg(feature = "yubihsm2")]
        use signstar_config::yubihsm2::YubiHsm2UserMapping;
        use signstar_config::{
            config::{UserBackendConnection, UserBackendConnectionFilter},
            test::{
                ConfigFileConfig,
                ConfigFileLocation,
                ConfigFileVariant,
                SystemPrepareConfig,
                SystemUserConfig,
            },
        };
        #[cfg(feature = "_yubihsm2-mockhsm")]
        use signstar_yubihsm2::Credentials;
        #[cfg(feature = "_yubihsm2-mockhsm")]
        use signstar_yubihsm2::mock::setup_single_key_in_mockhsm;
        use tempfile::tempdir;
        use tokio::{spawn, task::yield_now};
        use yubihsm::{Connector, Uuid, connector::RawMessage};

        use super::*;

        /// The payload executable to run in tests.
        const SIGNSTAR_SIGN_PAYLOAD: &str = "signstar-sign";

        /// The location of cargo-llvm-cov `.profraw` files when running a command as a different
        /// user.
        const LLVM_PROFILE_FILE: &str = "/tmp/signstar-%p-%16m.profraw";

        /// Responder for the NetHSM key `signing1`.
        #[get("//keys/signing1")]
        async fn get_key(_req: HttpRequest) -> impl Responder {
            r#"{"type":"Curve25519","mechanisms":[],"restrictions":{},"operations":1}"#
        }

        /// Responder for the NetHSM key certificate for key `signing1`.
        #[get("//keys/signing1/cert")]
        async fn get_cert(_req: HttpRequest) -> impl Responder {
            Base64::decode_vec(include_str!("../fixtures/cert.asc"))
                .expect("static base64 data to be valid")
        }

        /// Responder for signing with the NetHSM key `signing1`.
        #[post("//keys/signing1/sign")]
        async fn sign_data(_req: HttpRequest) -> impl Responder {
            r#"{"signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}"#
        }

        /// API calls for YubiHSM
        #[post("/connector/api")]
        async fn connector_api(request: web::Bytes, connector: Data<Arc<Connector>>) -> Vec<u8> {
            connector
                .send_message(Uuid::new_v4(), RawMessage::from(request.to_vec()))
                .expect("message to succeed")
                .as_ref()
                .to_vec()
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
                        variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminSystemdCreds,
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: true,
                        create_ssh_authorized_keys: true,
                    }))
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
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: true,
                        create_ssh_authorized_keys: true,
                    }))
                    },
                }
            )
        )]
        #[cfg_attr(
            feature = "_yubihsm2-mockhsm",
            case::yubihsm2_http_plain_admin(
                SystemPrepareConfig{
                    machine_id: true,
                    credentials_socket: true,
                    signstar_config: ConfigFileConfig {
                        location: Some(ConfigFileLocation::default()),
                        variant: ConfigFileVariant::OnlyYubiHsm2HttpBackendAdminPlaintextNonAdminPlaintext,
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: true,
                        create_ssh_authorized_keys: true,
                    }))
                    },
                }
            )
        )]
        #[tokio::test]
        async fn run_signstar_sign(#[case] mut prepare_config: SystemPrepareConfig) -> TestResult {
            setup_terminal_logging(LevelFilter::Info)?;
            let _credentials_socket = prepare_config.apply()?;
            let config = load_config()?;
            let Some(system_user_config) = prepare_config.signstar_config.system_user_config else {
                panic!("Expected to have a SystemUserConfig");
            };
            let Some(creds) = system_user_config.backend_credentials() else {
                panic!("Expected to have backend credentials");
            };
            info!(
                "Setup the following backend users with credentials: {}",
                creds
                    .keys()
                    .fold(String::new(), |acc, s| format!("{acc}, {s}"))
            );

            // Start a dummy web server to mock the interface used by the `signstar-sign`
            // executable, if the NetHSM backend is used.
            if prepare_config
                .signstar_config
                .variant
                .contains_backend(BackendType::NetHsm)
            {
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
                            .service(sign_data)
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

            // Collect the list of system users and respective backend users setup for signing.
            let signing_users = config
                .user_backend_connections(&[UserBackendConnectionFilter::NonAdmin])
                .iter()
                .filter_map(|user_backend_connection| match user_backend_connection {
                    #[cfg(feature = "nethsm")]
                    mapping @ UserBackendConnection::NetHsm {
                        mapping: NetHsmUserMapping::Signing { backend_user, .. },
                        ..
                    } => mapping
                        .system_user_id()
                        .map(|system_user_id| (system_user_id.clone(), backend_user.to_string())),

                    #[cfg(feature = "yubihsm2")]
                    mapping @ UserBackendConnection::YubiHsm2 {
                        mapping:
                            YubiHsm2UserMapping::Signing {
                                authentication_key_id,
                                ..
                            },
                        ..
                    } => mapping.system_user_id().map(|system_user_id| {
                        (system_user_id.clone(), authentication_key_id.to_string())
                    }),

                    _ => None,
                })
                .collect::<Vec<_>>();

            if signing_users.is_empty() {
                panic!(
                    "Expected at least one system user and accompanying backend user for signing in the configuration"
                );
            }

            // Run `signstar-sign`, only using users configured for signing.
            for (system_user_id, signing_user) in signing_users {
                info!(
                    "Using signstar-sign with system user {system_user_id} and backend user {signing_user}"
                );

                // Start a dummy web server to mock the interface used by the `signstar-sign`
                // executable, if the YubiHSM HTTP backend is used.
                #[cfg(feature = "_yubihsm2-mockhsm")]
                if matches!(
                    prepare_config.signstar_config,
                    ConfigFileConfig {
                        variant:
                            ConfigFileVariant::OnlyYubiHsm2HttpBackendAdminPlaintextNonAdminPlaintext,
                        ..
                    }
                ) {
                    let connector = setup_single_key_in_mockhsm(
                        1,
                        &Credentials::new(
                            u16::from_str(&signing_user)?,
                            creds
                                .get(&signing_user)
                                .expect("there to be a passphrase for signing user")
                                .clone(),
                        ),
                    )?;

                    spawn(async move {
                        let connector = Arc::new(connector);

                        HttpServer::new(move || {
                            App::new()
                                .app_data(Data::new(connector.clone()))
                                .wrap(actix_web::middleware::Logger::default())
                                .service(connector_api)
                        })
                        .bind("127.0.0.1:8081")
                        .expect("binding to port 8081 to succeed")
                        .run()
                        .await
                    });

                    // run the spawned task before we return from this function
                    // see: https://docs.rs/tokio/latest/tokio/task/index.html#yield_now
                    yield_now().await;
                }

                let CommandOutput {
                    status,
                    stdout,
                    stderr,
                    ..
                } = run_command_as_user(
                    SIGNSTAR_SIGN_PAYLOAD,
                    &[],
                    Some(include_bytes!(
                        "../../../fixtures/request/sample-request.json",
                    )),
                    COVERAGE_ENV_LIST,
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
                let response = Response::from_reader(Cursor::new(stdout.as_bytes()))?;
                info!("Parsed signing response: {response:#?}");
                assert_eq!(response.version.major, 1);
                let mut sig = Vec::new();
                response.signature_to_writer(&mut sig)?;
                let sig = Cursor::new(sig);
                let sig = DetachedSignature::from_armor_single(sig)?.0;
                assert_eq!(Some(SignatureType::Binary), sig.signature.typ());
                assert_ne!(None, sig.signature.signers_userid());
                assert_eq!(2, sig.signature.notations().len());
            }

            collect_coverage_data("/tmp")?;

            Ok(())
        }
    }
}

/// Tests against the NetHSM backend type.
mod nethsm_backend {
    use super::*;

    /// Tests for `signstar-configure`.
    mod configure {
        use super::*;

        /// Ensures, that [`HostConfiguration::sync`] aborts if a Signstar configuration file is
        /// present in one of the default system locations but no physical NetHSM backend is
        /// available.
        #[test]
        fn host_configuration_sync_aborts_on_unavailable_connections() -> TestResult {
            setup_terminal_logging(LevelFilter::Debug)?;

            let mut system_prepare_config = SystemPrepareConfig {
                machine_id: false,
                credentials_socket: false,
                signstar_config: ConfigFileConfig {
                    location: Some(ConfigFileLocation::UsrShare),
                    variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminPlaintext,
                    system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: false,
                        create_ssh_authorized_keys: true,
                    })),
                },
            };
            system_prepare_config.apply()?;

            let config = load_config()?;
            let host_configuration = HostConfiguration::new(&config);
            let configuration_result = host_configuration.sync()?;

            assert_eq!(
                configuration_result,
                ConfigurationResult::NoAvailableBackendConnection
            );

            Ok(())
        }

        #[cfg(feature = "cli")]
        mod cli {
            use std::process::{ExitCode, Termination};

            use assert_cmd::cargo::cargo_bin_cmd;

            use super::*;

            /// Ensures, that calling the `signstar-configure` CLI aborts on unavailable backend
            /// connections.
            #[test]
            fn abort_on_unavailable_backend_connections() -> TestResult {
                setup_terminal_logging(LevelFilter::Debug)?;

                let mut system_prepare_config = SystemPrepareConfig {
                    machine_id: false,
                    credentials_socket: false,
                    signstar_config: ConfigFileConfig {
                        location: Some(ConfigFileLocation::UsrShare),
                        variant:
                            ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminPlaintext,
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                            create_secrets: false,
                            create_ssh_authorized_keys: true,
                        })),
                    },
                };
                system_prepare_config.apply()?;

                let exit_code = {
                    let mut command = cargo_bin_cmd!("signstar-configure");
                    let output = command
                        .arg("--verbose")
                        .arg("--verbose")
                        .arg("--verbose")
                        .output()?;

                    ExitCode::from(u8::try_from(
                        output.status.code().expect("there to be an exit code"),
                    )?)
                };

                assert_eq!(
                    exit_code,
                    ConfigurationResult::NoAvailableBackendConnection.report()
                );

                Ok(())
            }
        }
    }
}

/// Tests against the YubiHSM2 backend type.
mod yubihsm_backend {
    use super::*;

    /// Tests for `signstar-configure`.
    mod configure {
        use super::*;

        /// Ensures, that [`HostConfiguration::sync`] succeeds if a Signstar configuration file is
        /// present in one of the default system locations and a YubiHSM2 mockhsm backend is used.
        #[test]
        #[cfg(feature = "_yubihsm2-mockhsm")]
        fn host_configuration_sync_succeeds_on_host_without_admin_creds_and_mockhsm() -> TestResult
        {
            setup_terminal_logging(LevelFilter::Debug)?;

            let mut system_prepare_config = SystemPrepareConfig {
                machine_id: false,
                credentials_socket: false,
                signstar_config: ConfigFileConfig {
                    location: Some(ConfigFileLocation::UsrShare),
                    variant:
                        ConfigFileVariant::OnlyYubiHsm2MockHsmBackendAdminPlaintextNonAdminPlaintext,
                    system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: false,
                        create_ssh_authorized_keys: true,
                    })),
                },
            };
            system_prepare_config.apply()?;

            let config = load_config()?;
            let host_configuration = HostConfiguration::new(&config);
            let configuration_result = host_configuration.sync()?;

            assert_eq!(configuration_result, ConfigurationResult::SyncSucceeded);

            Ok(())
        }

        /// Ensures, that [`HostConfiguration::sync`] aborts if a Signstar configuration file is
        /// present in one of the default system locations but no physical YubiHSM2 backend
        /// is available.
        #[test]
        fn host_configuration_sync_aborts_on_unavailable_yubihsm2_connections() -> TestResult {
            setup_terminal_logging(LevelFilter::Debug)?;

            let mut system_prepare_config = SystemPrepareConfig {
                machine_id: false,
                credentials_socket: false,
                signstar_config: ConfigFileConfig {
                    location: Some(ConfigFileLocation::UsrShare),
                    variant: ConfigFileVariant::OnlyYubiHsm2BackendAdminPlaintextNonAdminPlaintext,
                    system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: false,
                        create_ssh_authorized_keys: true,
                    })),
                },
            };
            system_prepare_config.apply()?;

            let config = load_config()?;
            let host_configuration = HostConfiguration::new(&config);
            let configuration_result = host_configuration.sync()?;

            assert_eq!(
                configuration_result,
                ConfigurationResult::NoAvailableBackendConnection
            );

            Ok(())
        }

        #[cfg(feature = "cli")]
        mod cli {
            use std::process::{ExitCode, Termination};

            use assert_cmd::cargo::cargo_bin_cmd;

            use super::*;

            /// Ensures, that calling the `signstar-configure` CLI succeeds if a Signstar
            /// configuration file is present in one of the default system locations and
            /// a YubiHSM2 mockhsm backend is used.
            #[test]
            #[cfg(feature = "_yubihsm2-mockhsm")]
            fn succeeds_on_host_without_admin_creds_and_mockhsm() -> TestResult {
                setup_terminal_logging(LevelFilter::Debug)?;

                let mut system_prepare_config = SystemPrepareConfig {
                machine_id: false,
                credentials_socket: false,
                signstar_config: ConfigFileConfig {
                    location: Some(ConfigFileLocation::UsrShare),
                    variant:
                        ConfigFileVariant::OnlyYubiHsm2MockHsmBackendAdminPlaintextNonAdminPlaintext,
                    system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: false,
                        create_ssh_authorized_keys: true,
                    })),
                },
            };
                system_prepare_config.apply()?;

                let exit_code = {
                    let mut command = cargo_bin_cmd!("signstar-configure");
                    let output = command
                        .arg("--verbose")
                        .arg("--verbose")
                        .arg("--verbose")
                        .output()?;

                    ExitCode::from(u8::try_from(
                        output.status.code().expect("there to be an exit code"),
                    )?)
                };

                assert_eq!(exit_code, ConfigurationResult::SyncSucceeded.report());

                Ok(())
            }

            /// Ensures, that calling the `signstar-configure` CLI aborts on unavailable backend
            /// connections.
            #[test]
            fn abort_on_unavailable_backend_connections() -> TestResult {
                setup_terminal_logging(LevelFilter::Debug)?;

                let mut system_prepare_config = SystemPrepareConfig {
                    machine_id: false,
                    credentials_socket: false,
                    signstar_config: ConfigFileConfig {
                        location: Some(ConfigFileLocation::UsrShare),
                        variant:
                            ConfigFileVariant::OnlyYubiHsm2BackendAdminPlaintextNonAdminPlaintext,
                        system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                            create_secrets: false,
                            create_ssh_authorized_keys: true,
                        })),
                    },
                };
                system_prepare_config.apply()?;

                let exit_code = {
                    let mut command = cargo_bin_cmd!("signstar-configure");
                    let output = command
                        .arg("--verbose")
                        .arg("--verbose")
                        .arg("--verbose")
                        .output()?;

                    ExitCode::from(u8::try_from(
                        output.status.code().expect("there to be an exit code"),
                    )?)
                };

                assert_eq!(
                    exit_code,
                    ConfigurationResult::NoAvailableBackendConnection.report()
                );

                Ok(())
            }
        }
    }
}
