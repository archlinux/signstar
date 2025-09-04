# NetHSM

A high-level library to interact with the API of a [Nitrokey] [NetHSM].

The [NetHSM] is a hardware appliance, that serves as secure store for cryptographic keys.
With the help of a REST API it is possible to communicate with the device (as well as the official [nethsm container]) for setup and various cryptographic actions.

The [nethsm-sdk-rs] library is auto-generated using [openapi-generator].
This leads to a broad API surface with sparse documentation, that this crate attempts to rectify with the help of a central struct used for authentication setup and communication.

As this crate is a wrapper around [`nethsm_sdk_rs`] it covers all available actions from provisioning, over key and user management to backup and restore.

The NetHSM provides dedicated [user management] based on a [role] system (see [`UserRole`]) which can be used to separate concerns.
Each user has exactly one [role].

With the help of a [namespace] concept, it is possible to segregate users and their keys into secluded groups.
Notably, this introduces *R-Administrators* (system-wide users in the [`Administrator`][`UserRole::Administrator`] [role]), which have access to all system-wide actions, but can *not* modify users and keys in a [namespace] and *N-Administrators* ([namespace] users in the [`Administrator`][`UserRole::Administrator`] [role]), which have access only to actions towards users and keys in their own [namespace].
[Namespace] users in the [`Operator`][`UserRole::Operator`] [role] only have access to keys in their own [namespace], while system-wide users only have access to system-wide keys.

The cryptographic key material on the NetHSM can be assigned to one or several [tags].
Users in the [`Operator`][`UserRole::Operator`] [role] can be assigned to the same [tags] to gain access to the respective keys.

Using the central [`NetHsm`] struct it is possible to establish a TLS connection for multiple users and all available operations.
TLS validation can be configured based on a variant of the [`ConnectionSecurity`] enum:

- [`ConnectionSecurity::Unsafe`]: The host certificate is not validated.
- [`ConnectionSecurity::Fingerprints`]: The host certificate is validated based on configurable
  fingerprints.
- [`ConnectionSecurity::Native`]: The host certificate is validated using the native Operating
  System trust store.

## Documentation

- <https://signstar.archlinux.page/rustdoc/nethsm/> for development version of the crate
- <https://docs.rs/nethsm/latest/nethsm/> for released versions of the crate

Apart from the crate specific documentation it is very recommended to read the canonical upstream documentation as well: <https://docs.nitrokey.com/nethsm/>

## Testing

This library is integration tested against [Nitrokey]'s official [nethsm container].
To run these long running tests a [podman] installation is required.
The tests handle the creation and teardown of containers as needed.

```shell
cargo test --all -- --ignored
```

## Re-exports

This crate relies on a set of external crates in its own public API.

Re-exports ensure that the respective dependencies do not have to be relied upon directly by consumers:

- [`chrono::DateTime`]
- [`chrono::Utc`]
- [`nethsm_sdk_rs::models::DistinguishedName`]
- [`nethsm_sdk_rs::models::InfoData`]
- [`nethsm_sdk_rs::models::LoggingConfig`]
- [`nethsm_sdk_rs::models::NetworkConfig`]
- [`nethsm_sdk_rs::models::PublicKey`]
- [`nethsm_sdk_rs::models::SystemInfo`]
- [`nethsm_sdk_rs::models::SystemState`]
- [`nethsm_sdk_rs::models::SystemUpdateData`]
- [`nethsm_sdk_rs::models::UserData`]

## Examples

Establish a connection with a [Nitrokey] [NetHSM] and manage credentials:

```rust
use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase};

# fn main() -> testresult::TestResult {
// Create a new connection to a NetHSM at "https://example.org" using admin credentials
let nethsm = NetHsm::new(
    Connection::new(
        "https://example.org/api/v1".try_into()?,
        ConnectionSecurity::Unsafe,
    ),
    Some(Credentials::new("admin".parse()?, Some(Passphrase::new("passphrase".to_string())))),
    None,
    None,
)?;

// Connections can be initialized without any credentials and more than one can be provided later on
let nethsm = NetHsm::new(
    Connection::new(
        "https://example.org/api/v1".try_into()?,
        ConnectionSecurity::Unsafe,
    ),
    None,
    None,
    None,
)?;

nethsm.add_credentials(Credentials::new("admin".parse()?, Some(Passphrase::new("passphrase".to_string()))));
nethsm.add_credentials(Credentials::new("user1".parse()?, Some(Passphrase::new("other_passphrase".to_string()))));

// A set of credentials must be used before establishing a connection with the configured NetHSM
nethsm.use_credentials(&"user1".parse()?)?;
# Ok(())
# }
```

## Features

- `test-helpers` enables the `signstar_config::test` module which provides utilities for test setups that are also useful for other crates.
- `_nethsm-integration-test` enables tests that require `podman` for starting test dependencies in containers.

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[NetHSM]: https://www.nitrokey.com/products/nethsm
[Nitrokey]: https://nitrokey.com
[contributing guidelines]: ../CONTRIBUTING.md
[namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
[nethsm container]: https://hub.docker.com/r/nitrokey/nethsm
[nethsm-sdk-rs]: https://crates.io/crates/nethsm-sdk-rs
[openapi-generator]: https://openapi-generator.tech/
[podman]: https://podman.io/
[role]: https://docs.nitrokey.com/nethsm/administration#roles
[systemd]: https://systemd.io/
[tags]: https://docs.nitrokey.com/nethsm/operation#tags-for-keys
[user management]: https://docs.nitrokey.com/nethsm/administration#user-management
