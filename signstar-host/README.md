# Signstar Host

Libraries and executables for _Signstar hosts_.

A _Signstar host_ is a Linux host, that has several regular users configured, which allow access to specific credentials on an HSM backend.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_host/> for development version of the crate
- <https://docs.rs/signstar-host/latest/signstar_host/> for released versions of the crate

## Executables

Several executables are available with the `cli` feature.

Unless noted otherwise, none of them take any arguments or input and only allow for their verbosity level to be adjusted.

### `signstar-configure`

The executable `signstar-configure` configures a _Signstar host_ during runtime.

![Graph: Configuring Signstar host with signstar-configure](../img/signstar-configure-workflow.svg)

It relies on the system's Signstar configuration file to handle and optionally configure the administrative credentials which are then used to configure

- the available HSM backends (e.g. [NetHSM] and/or [YubiHSM2])
- the specific backend credentials for real users on the host

![Graph: Configuring Signstar users and HSM backends during runtime](../img/signstar-configuring-signstar-users-and-hsm-backends-during-runtime.svg)

The executable is meant to be run as root on a Signstar host in regular intervals:

```bash no_run
signstar-configure
```

For this purpose, a systemd service and timer unit (see [systemd.service] and [systemd.timer], respectively) are made available in the `resources/systemd/` directory.

### `signstar-configure-build`

The executable `signstar-configure-build` configures a Signstar system during build of an image for a Signstar host.

It relies on the system's Signstar configuration file to create system users and their integration.

![Graph: Configuring Signstar host during image build](../img/signstar-configuring-signstar-host-during-image-build.svg)

Based on configured user mappings in the configuration file, `signstar-configure-build`:

- creates unlocked system users
    - with a random passphrase
    - with a home directory below `/var/lib/signstar/home/` (but without creating it)
- adds [tmpfiles.d] integration for each user, so that their home directory is created automatically
- adds a dedicated [authorized_keys] file and [sshd_config] drop-in configuration, which defines a [ForceCommand] option to enforce specific commands for each configured user with SSH access

The executable is meant to be run as root during build of an image for a Signstar host:

```bash
signstar-configure-build
```

<!--
```bash
remote_user_list=(
  nethsm-backup
  nethsm-metrics
  nethsm-signing
  yubihsm2-audit-log
  yubihsm2-backup
  yubihsm2-signing
  signstar-share-holder1
  signstar-share-holder2
  signstar-share-holder3
  signstar-wireguard-download
)
local_user_list=(
  nethsm-hermetic-metrics
  yubihsm2-hermetic-audit-log
)

cat /etc/passwd
cat /usr/lib/tmpfiles.d/signstar-user-*.conf
cat /etc/ssh/signstar-user*.authorized_keys
cat /etc/ssh/sshd_config.d/10-signstar-user*.conf

for user in "${remote_user_list[@]}" "${local_user_list[@]}"; do
  grep -R "$user" /etc/passwd
  test -f "/usr/lib/tmpfiles.d/signstar-user-$user.conf"
done

for user in "${remote_user_list[@]}"; do
  test -f "/etc/ssh/signstar-user-$user.authorized_keys"
  test -f "/etc/ssh/sshd_config.d/10-signstar-user-$user.conf"
done
```
-->

### `signstar-download-key-certificates`

The executable `signstar-download-key-certificates` returns key certificates stored in HSM backends of a Signstar host.

Currently, only [OpenPGP certificates] are returned.
However, the response format is designed with extensibility in mind and other technologies can be integrated in the future.

The executable is meant to be run as a non-root user, which is setup for access to all key certificates in an HSM backend:

```bash no_run
signstar-download-key-certificates | jq --raw-output '.certs[0]'
```

### `signstar-sign`

The executable `signstar-sign` accepts a [signing request] and returns a [signing response] for it using HSM backends of a Signstar host.

A [signing response] contains digital signatures in protocol-specific framing.

Currently, only [OpenPGP signatures][OpenPGP signature] are supported.
However, both the [signing request] and [signing response] format are designed with extensibility in mind and other technologies can be integrated in the future.

The executable is meant to be run as a non-root user, which is setup for access to a single signing key in an HSM backend:

```bash no_run
signstar-sign < ../fixtures/request/sample-request.json | jq --raw-output .signature | rsop dearmor | rpacket dump
```

The above example takes a JSON [signing request], and produces a JSON [signing response].
Here, the response's `signature` field contains an armored [OpenPGP signature], which is de-armored and then inspected.

## Examples

### Library

The crate can be used as a library as well.

#### `signstar_host::configure`

Synchronization of backends depends on the system's Signstar configuration file, the available HSM backends and administrative credentials.

```rust
# #[cfg(not(feature = "_yubihsm2-mockhsm"))]
# mod default {
#     pub fn main() {}
# }
#
# #[cfg(feature = "_yubihsm2-mockhsm")]
# mod yubihsm2_mockhsm {
use signstar_host::configure::HostConfiguration;
use signstar_config::config::Config;

#     pub fn main() -> testresult::TestResult {
// NOTE: You can rely on the `signstar_configure::load_config` helper function to load the system's Signstar config.
let config = Config::from_file_path("../fixtures/config/yubihsm2_mockhsm_backend/admin-plaintext-non-admin-plaintext.yaml")?;
let backend = HostConfiguration::new(&config);
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
[ForceCommand]: https://man.archlinux.org/man/sshd_config.5#ForceCommand
[MIT]: https://opensource.org/licenses/MIT
[NetHSM]: https://www.nitrokey.com/products/nethsm
[OpenPGP certificates]: https://openpgp.dev/book/certificates.html
[OpenPGP signature]: https://openpgp.dev/book/signing_data.html
[YubiHSM2]: https://www.yubico.com/products/hardware-security-module/
[authorized_keys]: https://man.archlinux.org/man/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
[contributing guidelines]: ../CONTRIBUTING.md
[signing request]: https://signstar.archlinux.page/signing-api/request.html
[signing response]: https://signstar.archlinux.page/signing-api/response.html
[sshd_config]: https://man.archlinux.org/man/sshd_config.5
[systemd.service]: https://man.archlinux.org/man/systemd.service.5
[systemd.timer]: https://man.archlinux.org/man/systemd.timer.5
[tmpfiles.d]: https://man.archlinux.org/man/tmpfiles.d.5
