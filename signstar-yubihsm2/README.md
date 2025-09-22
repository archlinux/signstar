# Signstar YubiHSM2

Integration for YubiHSM2 devices as Signstar backend.

This library contains a small, safe subset of primitives used by Signstar.
For example: YubiHSM2 allows exporting raw secret keys while in Signstar we would always export them under wrap (encrypted).
Additionally, this library provides strong types for expressing object capabilities and identity.

To ease deployment and provisioning of a YubiHSM2 backend a command-line interface to execute deployment scenarios is included.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_yubihsm2/> for development version of the crate
- <https://docs.rs/signstar_yubihsm2/latest/signstar_yubihsm2/> for released versions of the crate

## Examples

### CLI

Reset the device to factory settings (erasing all key material) and get the HSM info:

```bash
echo $PWD
signstar-yubihsm scenario run "tests/scenarios/reset.json" | jq --compact-output
```

Adding new authentication key:

```bash
signstar-yubihsm scenario run "tests/scenarios/add-auth.json" | jq --compact-output
```

Generating key:

```bash
signstar-yubihsm scenario run "tests/scenarios/gen-key.json" | jq --compact-output
```

Signing using ed25519 keys:

```bash
signstar-yubihsm scenario run "tests/scenarios/raw-sign.json" | jq --compact-output
```

Exporting key under wrap:

```bash
signstar-yubihsm scenario run "tests/scenarios/wrapping/export-wrapped.json" | jq --compact-output
```

Import previously wrapped key and using it for signing:

```bash
signstar-yubihsm scenario run "tests/scenarios/wrapping/import-wrapped.json" | jq --compact-output
```

Enable forced auditing of signing and retrieving log:

```bash
signstar-yubihsm scenario run "tests/scenarios/audit.json" | jq --compact-output
```

## Features

- `cli` - enables command line interface for executing scenario files
- `mockhsm` - allows running scenario files against an emulated YubiHSM2, due to [`yubihsm` crate limitation] this works only in debug builds
- `serde` - serialization and deserialization of objects using `serde`

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[contributing guidelines]: ../CONTRIBUTING.md
[`yubihsm` crate limitation]: https://gitlab.archlinux.org/archlinux/signstar/-/issues/288
