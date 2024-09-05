# NetHSM-config

A library for working with application configuration files for [Nitrokey NetHSM] devices.

The [Nitrokey NetHSM] is a hardware appliance, that serves as secure store for cryptographic keys.
With the help of a REST API it is possible to communicate with the device (as well as the official [nethsm container]) for setup and various cryptographic actions.

This library is meant to be used by end-user applications written against the [nethsm] crate.

## License

This project is licensed under the terms of the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) and [MIT](https://opensource.org/licenses/MIT).

[Nitrokey NetHSM]: https://www.nitrokey.com/products/nethsm
[nethsm container]: https://hub.docker.com/r/nitrokey/nethsm
[nethsm]: https://crates.io/crates/nethsm
