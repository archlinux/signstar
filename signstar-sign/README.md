# Signstar Sign

Offers an executable for processing [Signstar signing requests].
Requests are created using [`signstar-request-signature`] and specify everything that is needed for creating an artifact signature.

The `signstar-sign` executable provided by this crate returns a [Signstar signing response] which contains a signature in protocol-specific framing.

Currently, only [OpenPGP signatures] are supported.
However, both request and response format are designed with extensibility in mind and other technologies can be integrated in the future.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_sign/> for development version of the crate
- <https://docs.rs/signstar_sign/latest/signstar_sign/> for released versions of the crate

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
[OpenPGP signatures]: https://openpgp.dev/book/signing_data.html
[Signstar signing requests]: https://signstar.archlinux.page/signstar-request-signature/request.html
[Signstar signing response]: https://signstar.archlinux.page/signstar-request-signature/response.html
[contributing guidelines]: ../CONTRIBUTING.md
[`signstar-request-signature`]: https://signstar.archlinux.page/signstar-request-signature/index.html
