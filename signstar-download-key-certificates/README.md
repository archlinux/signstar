# Signstar Download Key Certificates

Offers a library and executable for returning key certificates stored in backends of a Signstar host.

Currently, only [OpenPGP certificates] are returned.
However, the response format is designed with extensibility in mind and other technologies can be integrated in the future.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_download_key_certificates/> for development version of the crate
- <https://docs.rs/signstar_download_key_certificates/latest/signstar_download_key_certificates/> for released versions of the crate

## `signstar-download-key-certificates`

The command does not take any flags (with the exception of the verbosity level) nor any input:

```bash no_run
signstar-download-key-certificates | jq --raw-output '.certs[0]'
```

## Features

- `_containerized-integration-test`: Integration tests that require a containerized test environment.
  **NOTE**: Unless you are developing this crate, you will very likely not want to use this feature.
- `_yubihsm2-mockhsm`: Test environment and integration using a virtual [YubiHSM2] (implies the `yubihsm2` feature).
  **NOTE**: Unless you are developing this crate, you will very likely not want to use this feature.
- `cli`: Enables the command line interface (enabled by default)
- `nethsm`: For [NetHSM] support.
- `yubihsm2`: For [YubiHSM2] support.

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[NetHSM]: https://docs.nitrokey.com/nethsm/
[OpenPGP certificates]: https://openpgp.dev/book/certificates.html
[Signstar signing requests]: https://signstar.archlinux.page/signstar-request-signature/request.html
[Signstar signing response]: https://signstar.archlinux.page/signstar-request-signature/response.html
[YubiHSM2]: https://www.yubico.com/de/product/yubihsm-2/
[`signstar-request-signature`]: https://signstar.archlinux.page/signstar-request-signature/index.html
[contributing guidelines]: ../CONTRIBUTING.md
