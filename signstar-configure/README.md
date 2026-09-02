# Signstar configure

Runtime configuration for Signstar hosts.

A _Signstar host_ is a Linux host, that has several regular users configured, which allow access to specific credentials on an HSM backend.

This package provides a library that relies on the system's Signstar configuration file to handle and optionally configure the administrative credentials which are then used to configure

- the available HSM backends (e.g. [NetHSM] and/or [YubiHSM2])
- the specific backend credentials for real users on the host

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_configure/> for development version of the crate
- <https://docs.rs/signstar_configure/latest/signstar_configure/> for released versions of the crate

## Examples

### Library

Synchronization of backends depends on the system's Signstar configuration file, the available HSM backends and administrative credentials.

```rust
# #[cfg(not(feature = "_yubihsm2-mockhsm"))]
# mod default {
#     pub fn main() {}
# }
#
# #[cfg(feature = "_yubihsm2-mockhsm")]
# mod yubihsm2_mockhsm {
use signstar_configure::BackendSync;
use signstar_config::config::Config;

#     pub fn main() -> testresult::TestResult {
// NOTE: You can rely on the `signstar_configure::load_config` helper function to load the system's Signstar config.
let config = Config::from_file_path("../fixtures/config/yubihsm2_mockhsm_backend/admin-plaintext-non-admin-plaintext.yaml")?;
let backend = BackendSync::new(&config);
backend.sync()?;;
#         Ok(())
#     }
# }
# #[cfg(feature = "_yubihsm2-mockhsm")]
# use yubihsm2_mockhsm::main;
# #[cfg(not(feature = "_yubihsm2-mockhsm"))]
# use default::main;
```

## Features

- `_containerized-integration-test`: Integration tests that require a containerized test environment.
  **NOTE**: Unless you are developing this crate, you will very likely not want to use this feature.
- `_yubihsm2-mockhsm`: Test environment and integration using a virtual [YubiHSM2]
  **NOTE**: Unless you are developing this crate, you will very likely not want to use this feature.
- `nethsm`: Enables support for the [NetHSM] backend (default).
- `yubihsm2`: Enables support for the [YubiHSM2] backend (default)

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[NetHSM]: https://www.nitrokey.com/products/nethsm
[YubiHSM2]: https://www.yubico.com/products/hardware-security-module/
[contributing guidelines]: ../CONTRIBUTING.md
