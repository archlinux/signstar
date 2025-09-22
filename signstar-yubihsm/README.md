# Signstar YubiHSM

Signstar-specific bindings to YubiHSM.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_yubihsm/> for development version of the crate
- <https://docs.rs/signstar_crypto/latest/signstar_yubihsm/> for released versions of the crate

## Example usage

Reset the device to factory settings (erasing all key material) and get the HSM info:

```bash
echo $PWD
signstar-yubihsm "tests/scenarios/reset.json" | jq --compact-output
```

Adding new authentication key:

```bash
signstar-yubihsm "tests/scenarios/add-auth.json" | jq --compact-output
```

Generating key:

```bash
signstar-yubihsm "tests/scenarios/gen-key.json" | jq --compact-output
```

Signing using ed25519 keys:

```bash
signstar-yubihsm "tests/scenarios/raw-sign.json" | jq --compact-output
```

Exporting key under wrap:

```bash
signstar-yubihsm "tests/scenarios/export-wrapped.json" | jq --compact-output
```

Import previously wrapped key and using it for signing:

```bash
signstar-yubihsm "tests/scenarios/import-wrapped.json" | jq --compact-output
```

Enable forced auditing of signing and retrieving log:

```bash
signstar-yubihsm "tests/scenarios/audit.json" | jq --compact-output
```

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[NetHSM]: https://www.nitrokey.com/products/nethsm
[contributing guidelines]: ../CONTRIBUTING.md
