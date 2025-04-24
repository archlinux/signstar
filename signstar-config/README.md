# Signstar config

Configuration file handling for Signstar hosts.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_config/> for development version of the crate
- <https://docs.rs/signstar_config/latest/signstar_config/> for released versions of the crate

## Examples

### Administrative credentials

Administrative credentials on a Signstar host describe all required secrets to unlock, backup, restore and fully provision a NetHSM backend.
They can be used from plaintext and [`systemd-creds`] encrypted files.
Functions for interacting with configurations in default locations must be called by root.

```rust no_run
use nethsm_config::AdministrativeSecretHandling;
use signstar_config::AdminCredentials;

# fn main() -> testresult::TestResult {
// Load from plaintext file in default location
let creds = AdminCredentials::load(AdministrativeSecretHandling::Plaintext)?;

// Load from systemd-creds encrypted file in default location
let creds = AdminCredentials::load(AdministrativeSecretHandling::SystemdCreds)?;

// Store in plaintext file in default location
creds.store(AdministrativeSecretHandling::Plaintext)?;

// Store in systemd-creds encrypted file in default location
creds.store(AdministrativeSecretHandling::SystemdCreds)?;
# Ok(())
# }
```

### Creating secrets for non-administrative credentials

Non-administrative credentials on a Signstar host provide access to non-administrative users on a NetHSM backend.
They can be used in plaintext and [`systemd-creds`] encrypted files.

Assuming, that a Signstar configuration is present on the host, it is possible to create secrets for each backend user assigned to any of the configured system users.
Functions for the creation of secrets must be called by root.

```rust no_run
use nethsm_config::{
    AdministrativeSecretHandling,
    ConfigInteractivity,
    ConfigSettings,
    ExtendedUserMapping,
    HermeticParallelConfig,
};
use signstar_common::config::get_default_config_file_path;
use signstar_config::{AdminCredentials, SecretsWriter};

# fn main() -> testresult::TestResult {
// Load Signstar config from default location
let config = HermeticParallelConfig::new_from_file(
    ConfigSettings::new(
        "my_app".to_string(),
        ConfigInteractivity::NonInteractive,
        None,
    ),
    Some(&get_default_config_file_path()),
)?;

// Get extended user mappings for all users
let creds_mapping: Vec<ExtendedUserMapping> = config.into();

// Create secrets for each system user and their backend users
for mapping in &creds_mapping {
    mapping.create_secrets_dir()?;
    mapping.create_non_administrative_secrets()?;
}
# Ok(())
# }
```

---

NOTE: For the creation of system users based on a Signstar config refer to [signstar-configure-build].

---

### Loading secrets for non-administrative users

Depending on user mapping in the Signstar config, a system user may have one or more NetHSM backend users assigned to it.
The credentials for each NetHSM backend user can be loaded by each configured system user.
Functions for the loading of secrets must be called by the system user that is assigned that particular secret.

```rust no_run
use signstar_config::CredentialsLoading;

# fn main() -> testresult::TestResult {
// Load all credentials for the current system user
let credentials_loading = CredentialsLoading::from_system_user()?;

// Assuming the current system user is a signing user, get the credentials for its assigned user in the NetHSM backend
let credentials = credentials_loading.credentials_for_signing_user()?;
# Ok(())
# }
```

## Features

- `test-helpers` enables the `signstar_config::test` module which provides utilities for test setups that are also useful for other crates.
- `_containerized-integration-test` enables tests that require to be run in a separate, ephemeral container each.

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[contributing guidelines]: ../CONTRIBUTING.md
[signstar-configure-build]: https://signstar.archlinux.page/signstar-configure-build/index.html
[`systemd-creds`]: https://man.archlinux.org/man/systemd-creds.1
