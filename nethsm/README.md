# NetHSM

A high-level library abstracting the use of the [nethsm-sdk-rs] library.

The [NetHSM] is a hardware appliance, that serves as secure store for cryptographic keys.
With the help of a REST API it is possible to communicate with the device (as well as the official [nethsm container]) for setup and various cryptographic actions.

The [nethsm-sdk-rs] library is auto-generated using [openapi-generator].
This leads to a broad API surface with sparse documentation, that this crate attempts to rectify with the help of a central struct used for authentication setup and communication.

## Testing

This library is integration tested against [Nitrokey]'s official [nethsm container].
To run these long running tests a [podman] installation is required.
The tests handle the creation and teardown of containers as needed.

```shell
cargo test --all -- --ignored
```

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[contributing guidelines]: ../CONTRIBUTING.md
[nethsm-sdk-rs]: https://crates.io/crates/nethsm-sdk-rs
[NetHSM]: https://www.nitrokey.com/products/nethsm
[Nitrokey]: https://nitrokey.com
[nethsm container]: https://hub.docker.com/r/nitrokey/nethsm
[podman]: https://podman.io/
[systemd]: https://systemd.io/
[openapi-generator]: https://openapi-generator.tech/
