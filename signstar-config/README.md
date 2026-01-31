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

#### NetHSM

```rust no_run
# #[cfg(feature = "nethsm")]
# mod impl_nethsm {
use signstar_config::{AdminCredentials, NetHsmAdminCredentials};
use signstar_crypto::AdministrativeSecretHandling;

#     pub fn main() -> testresult::TestResult {
// Load from plaintext file in default location
let creds = NetHsmAdminCredentials::load(AdministrativeSecretHandling::Plaintext)?;

// Load from systemd-creds encrypted file in default location
let creds = NetHsmAdminCredentials::load(AdministrativeSecretHandling::SystemdCreds)?;

// Store in plaintext file in default location
creds.store(AdministrativeSecretHandling::Plaintext)?;

// Store in systemd-creds encrypted file in default location
creds.store(AdministrativeSecretHandling::SystemdCreds)?;
#         Ok(())
#     }
# }
# #[cfg(not(feature = "nethsm"))]
# mod impl_none {
#     pub fn main() -> testresult::TestResult {
#         Ok(())
#     }
# }
# #[cfg(feature = "nethsm")]
# use impl_nethsm::main;
# #[cfg(not(feature = "nethsm"))]
# use impl_none::main;
```

#### YubiHSM2

```rust no_run
# #[cfg(feature = "yubihsm2")]
# mod impl_yubihsm2 {
use signstar_config::{AdminCredentials, yubihsm2::admin_credentials::YubiHsm2AdminCredentials};
use signstar_crypto::AdministrativeSecretHandling;

#     pub fn main() -> testresult::TestResult {
// Load from plaintext file in default location
let creds = YubiHsm2AdminCredentials::load(AdministrativeSecretHandling::Plaintext)?;

// Load from systemd-creds encrypted file in default location
let creds = YubiHsm2AdminCredentials::load(AdministrativeSecretHandling::SystemdCreds)?;

// Store in plaintext file in default location
creds.store(AdministrativeSecretHandling::Plaintext)?;

// Store in systemd-creds encrypted file in default location
creds.store(AdministrativeSecretHandling::SystemdCreds)?;
#         Ok(())
#     }
# }
# #[cfg(not(feature = "yubihsm2"))]
# mod impl_none {
#     pub fn main() -> testresult::TestResult {
#         Ok(())
#     }
# }
# #[cfg(feature = "yubihsm2")]
# use impl_yubihsm2::main;
# #[cfg(not(feature = "yubihsm2"))]
# use impl_none::main;
```

### Creating secrets for non-administrative credentials

Non-administrative credentials on a Signstar host provide access to non-administrative users on a backend.
They can be used in plaintext and [`systemd-creds`] encrypted files.

Assuming, that a Signstar configuration is present on the host, it is possible to create secrets for each backend user assigned to any of the configured system users.
Functions for the creation of secrets must be called by root.

---

NOTE: For the creation of system users based on a Signstar config refer to [signstar-configure-build].

---

```rust no_run
# #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
# mod impl_any {
use signstar_config::{
    config::{Config, UserBackendConnection, UserBackendConnectionFilter},
};
use signstar_crypto::AdministrativeSecretHandling;

#     pub fn main() -> testresult::TestResult {
// Load Signstar config from one of the default system locations.
let config = Config::from_system_path()?;

// Get the user backend connections for all non-administrative users.
let user_backend_connections = config.user_backend_connections(UserBackendConnectionFilter::NonAdmin);

// Create secrets for each system user and their backend users.
for user_backend_connection in user_backend_connections.iter() {
    user_backend_connection.create_non_admin_backend_user_secrets()?;
}
#         Ok(())
#     }
# }
# #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
# mod impl_none {
#     pub fn main() -> testresult::TestResult {
#         Ok(())
#     }
# }
# #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
# use impl_any::main;
# #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
# use impl_none::main;
```

### Loading secrets for non-administrative users

Depending on user mapping in the Signstar config, a system user may have one or more NetHSM backend users assigned to it.
The credentials for each NetHSM backend user can be loaded by each configured system user.
Functions for the loading of secrets must be called by the system user that is assigned that particular secret.

```rust no_run
# #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
# mod impl_any {
use signstar_config::config::{Config, NonAdminBackendUserIdFilter, NonAdminBackendUserIdKind};

#     pub fn main() -> testresult::TestResult {
// Load Signstar config from one of the default system locations.
let config = Config::from_system_path()?;
// Get the user backend connection for the Unix user named "test".
let Some(user_backend_connection) = config.user_backend_connection(&"test".parse()?) else {
  panic!("No Unix user of that name is configured for any of the available backends.")
};

// Assuming the selected Unix user is supposed to be used for signing, get the credentials for its assigned user in the backend.
let credentials = user_backend_connection.load_non_admin_backend_user_secrets(NonAdminBackendUserIdFilter{ backend_user_id_kind: NonAdminBackendUserIdKind::Signing })?;
#         Ok(())
#     }
# }
# #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
# mod impl_none {
#     pub fn main() -> testresult::TestResult {
#         Ok(())
#     }
# }
# #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
# use impl_any::main;
# #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
# use impl_none::main;
```

## Features

- `_containerized-integration-test`: Integration tests that require a containerized test environment.
  **NOTE**: Unless you are developing this crate, you will very likely not want to use this feature.
- `_nethsm-integration-test`: Integration tests that require a containerized NetHSM environment.
  **NOTE**: Unless you are developing this crate, you will very likely not want to use this feature.
- `_test-helpers`: Enables the `signstar_config::test` module which provides utilities for test setups that may also be useful for other crates.
  **NOTE**: Unless you are developing this crate, you will very likely not want to use this feature.
- `_yubihsm2-mockhsm`: Test environment and integration using a virtual [YubiHSM2].
  **NOTE**: Unless you are developing this crate, you will very likely not want to use this feature.
  **WARNING**: This feature requires building in `debug` mode (see [signstar#288])!
- `nethsm`: Enables support for the NetHSM backend.
- `yubihsm2`: Enables support for the [YubiHSM2] backend.

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[YubiHSM2]: https://www.yubico.com/de/product/yubihsm-2/
[`systemd-creds`]: https://man.archlinux.org/man/systemd-creds.1
[contributing guidelines]: ../CONTRIBUTING.md
[signstar#288]: https://gitlab.archlinux.org/archlinux/signstar/-/work_items/288
[signstar-configure-build]: https://signstar.archlinux.page/signstar-configure-build/index.html
