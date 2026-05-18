//! Containerized integration tests for [`signstar-request-signature`].

#![cfg(feature = "_containerized-integration-test")]

/// Tests for privileged users (uid < 1000).
mod containerized {
    use std::{assert_matches, fs::write, path::PathBuf};

    use rstest::rstest;
    use signstar_request_signature::ssh::client::{
        ConnectConfig,
        DEFAULT_CONFIG,
        ETC_OVERRIDE_CONFIG,
        RUN_OVERRIDE_CONFIG,
    };
    use testresult::TestResult;
    /// Creates directory hierarchy for `usr`, `etc` and `run` subdirectories within a `root`
    /// directory.
    fn create_test_hierarchy() -> TestResult {
        let etc = PathBuf::from(ETC_OVERRIDE_CONFIG);
        let etc_dir = etc
            .parent()
            .expect("etc config override to have a parent dir");
        std::fs::create_dir_all(etc_dir)?;

        let usr = PathBuf::from(DEFAULT_CONFIG);
        let usr_dir = usr
            .parent()
            .expect("usr config override to have a parent dir");
        std::fs::create_dir_all(usr_dir)?;

        let run = PathBuf::from(RUN_OVERRIDE_CONFIG);
        let run_dir = run
            .parent()
            .expect("run config override to have a parent dir");
        std::fs::create_dir_all(run_dir)?;
        Ok(())
    }

    #[rstest]
    #[case::etc(ETC_OVERRIDE_CONFIG)]
    #[case::usr(DEFAULT_CONFIG)]
    #[case::run(RUN_OVERRIDE_CONFIG)]
    fn reading_single_location_config(#[case] subdir: &str) -> TestResult {
        use signstar_request_signature::ssh::client::ConnectConfig;

        create_test_hierarchy()?;
        let config_file = PathBuf::from(subdir);

        let config = r#"[hosts.local]
host = "127.0.0.1"
port = 2222
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]

[users.signstar-sign]
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
hosts = ["local"]
"#;
        write(config_file, config)?;
        let config = ConnectConfig::from_first_system_config()?;
        assert_eq!(1, config.hosts.len());
        assert_eq!("local", config.users["signstar-sign"].hosts[0]);
        Ok(())
    }

    const ETC_CONFIG: &str = r#"[hosts.etc]
host = "127.0.0.1"
port = 2222
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]

[users.signstar-sign]
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
hosts = ["etc"]
"#;

    const USR_CONFIG: &str = r#"[hosts.usr]
host = "127.0.0.1"
port = 2222
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]

[users.signstar-sign]
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
hosts = ["usr"]
"#;

    const RUN_CONFIG: &str = r#"[hosts.run]
host = "127.0.0.1"
port = 2222
known_hosts = ["127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh8eDowbkS5cA/50DhIsOUI5bDf5Kx0sSJZDQgfoRAd"]

[users.signstar-sign]
agent_socket = "/agent/path"
user_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMPF9G0NQMEIBWR0NBc7sVBc2uxkKwY3SWvzRWQAtLPp"
hosts = ["run"]
"#;

    #[test]
    fn reading_all_locations() -> TestResult {
        create_test_hierarchy()?;

        write(ETC_OVERRIDE_CONFIG, ETC_CONFIG)?;
        write(RUN_OVERRIDE_CONFIG, RUN_CONFIG)?;
        write(DEFAULT_CONFIG, USR_CONFIG)?;

        let config = ConnectConfig::from_first_system_config()?;
        assert_eq!(1, config.hosts.len());
        assert_eq!("etc", config.users["signstar-sign"].hosts[0]);
        Ok(())
    }

    #[test]
    fn override_usr_with_run() -> TestResult {
        create_test_hierarchy()?;

        write(RUN_OVERRIDE_CONFIG, RUN_CONFIG)?;
        write(DEFAULT_CONFIG, USR_CONFIG)?;

        let config = ConnectConfig::from_first_system_config()?;
        assert_eq!(1, config.hosts.len());
        assert_eq!("run", config.users["signstar-sign"].hosts[0]);
        Ok(())
    }

    #[test]
    fn override_usr_with_etc() -> TestResult {
        create_test_hierarchy()?;

        write(ETC_OVERRIDE_CONFIG, ETC_CONFIG)?;
        write(DEFAULT_CONFIG, USR_CONFIG)?;

        let config = ConnectConfig::from_first_system_config()?;
        assert_eq!(1, config.hosts.len());
        assert_eq!("etc", config.users["signstar-sign"].hosts[0]);
        Ok(())
    }

    #[test]
    fn override_run_with_etc() -> TestResult {
        create_test_hierarchy()?;

        write(ETC_OVERRIDE_CONFIG, ETC_CONFIG)?;
        write(RUN_OVERRIDE_CONFIG, RUN_CONFIG)?;

        let config = ConnectConfig::from_first_system_config()?;
        assert_eq!(1, config.hosts.len());
        assert_eq!("etc", config.users["signstar-sign"].hosts[0]);
        Ok(())
    }

    #[test]
    fn mask_etc() -> TestResult {
        create_test_hierarchy()?;

        // empty /etc/ masks other configurations
        write(ETC_OVERRIDE_CONFIG, "")?;
        write(RUN_OVERRIDE_CONFIG, RUN_CONFIG)?;
        write(DEFAULT_CONFIG, USR_CONFIG)?;

        // but the targets field is required so it returns an error
        assert_matches!(
            ConnectConfig::from_first_system_config(),
            Err(signstar_request_signature::Error::Toml(_))
        );
        Ok(())
    }

    #[test]
    fn mask_run() -> TestResult {
        create_test_hierarchy()?;

        write(ETC_OVERRIDE_CONFIG, ETC_CONFIG)?;
        // masking /run
        write(RUN_OVERRIDE_CONFIG, "")?;
        write(DEFAULT_CONFIG, USR_CONFIG)?;

        // etc still takes precedence
        let config = ConnectConfig::from_first_system_config()?;
        assert_eq!(1, config.hosts.len());
        assert_eq!("etc", config.users["signstar-sign"].hosts[0]);
        Ok(())
    }

    #[test]
    fn mask_run_no_etc() -> TestResult {
        create_test_hierarchy()?;

        // empty /run/ masks /usr
        write(RUN_OVERRIDE_CONFIG, "")?;
        write(DEFAULT_CONFIG, USR_CONFIG)?;

        // but the targets field is required so it returns an error
        assert_matches!(
            ConnectConfig::from_first_system_config(),
            Err(signstar_request_signature::Error::Toml(_))
        );
        Ok(())
    }
}
