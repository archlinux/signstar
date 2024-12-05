# NetHSM-config

A library for working with application configuration files for [Nitrokey NetHSM] devices.

The [Nitrokey NetHSM] is a hardware appliance, that serves as secure store for cryptographic keys.
With the help of a REST API it is possible to communicate with the device (as well as the official [nethsm container]) for setup and various cryptographic actions.

This library is meant to be used by end-user applications written against the [nethsm] crate.

## Documentation

- <https://signstar.archlinux.page/rustdoc/nethsm_config/> for development version of the crate
- <https://docs.rs/nethsm_config/latest/nethsm_config/> for released versions of the crate

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[Nitrokey NetHSM]: https://www.nitrokey.com/products/nethsm
[contributing guidelines]: ../CONTRIBUTING.md
[nethsm container]: https://hub.docker.com/r/nitrokey/nethsm
[nethsm]: https://crates.io/crates/nethsm
