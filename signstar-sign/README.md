# Signstar Sign

This crate offers an executable for processing signing requests.
Signing requests are created using the [`signstar-request-signature`] and specify everything that is needed for creating an artifact signature.
The signing response returned by this executable contains a raw, protocol-specific framing.
Currently, `signstar-sign` can created only OpenPGP signatures but the format is extensible and more could be implemented in the future.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_sign/> for development version of the crate
- <https://docs.rs/signstar_configure_build/latest/signstar_sign/> for released versions of the crate

## `signstar-sign`

The following command takes a signing request, encoded in JSON, and produces a JSON response.
The JSON response contains a `signature` field, which is an armored OpenPGP signature.

```bash no_run
signstar-sign < ../signstar-request-signature/tests/sample-request.json | jq --raw-output .signature | rsop dearmor | rpacket dump
```

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[contributing guidelines]: ../CONTRIBUTING.md
