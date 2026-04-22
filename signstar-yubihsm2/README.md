# Signstar YubiHSM2

Integration for [YubiHSM2] devices as Signstar backend.

This library contains a small, safe subset of primitives used by Signstar.
For example: [YubiHSM2] allows exporting raw secret keys while in Signstar we would always export them under wrap (encrypted).
Additionally, this library provides strong types for expressing object capabilities and identity.

To ease deployment and provisioning of a YubiHSM2 backend a command-line interface to execute deployment scenarios is included.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_yubihsm2/> for development version of the crate
- <https://docs.rs/signstar_yubihsm2/latest/signstar_yubihsm2/> for released versions of the crate

## Examples

### Running scenarios

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

### Backup

Decrypt and print details about several types of objects:

```bash
wrap_key="$(mktemp --suffix '-wrap.key' --dry-run)"
echo -en '\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff' > "$wrap_key"

signstar-yubihsm backup dump "tests/backup/auth.yhw" "$wrap_key"
signstar-yubihsm backup dump "tests/backup/opaque.yhw" "$wrap_key"
signstar-yubihsm backup dump "tests/backup/private-ed25519.yhw" "$wrap_key"
signstar-yubihsm backup dump "tests/backup/private-ed25519-seed.yhw" "$wrap_key"
```

### Wrapping ed25519 keys

```bash
wrap_key="$(mktemp --suffix '-wrap.key' --dry-run)"
echo -en '\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff' > "$wrap_key"

private_key="$(mktemp --suffix '-private.key' --dry-run)"
head -c 32 /dev/random > "$private_key"

wrapped_key="$(mktemp --suffix '-private.key' --dry-run)"

signstar-yubihsm backup wrap-ed25519 --capabilities Sign,Export --domains 1,2 --label test --id 3 "$private_key" "$wrap_key" > "$wrapped_key"
signstar-yubihsm backup dump "$wrapped_key" "$wrap_key"
```

## Features

- `_yubihsm2-mockhsm`: Test environment and integration using a virtual [YubiHSM2].
  **NOTE**: Unless you are developing this crate, you will very likely not want to use this feature.
  **WARNING**: This feature requires building in `debug` mode (see [signstar#288])!
- `cli`: Enables command line interface for executing scenario files
- `serde`: Serialization and deserialization of objects using `serde`.

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[YubiHSM2]: https://www.yubico.com/de/product/yubihsm-2/
[contributing guidelines]: ../CONTRIBUTING.md
[signstar#288]: https://gitlab.archlinux.org/archlinux/signstar/-/work_items/288
