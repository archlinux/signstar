# Signstar OS

This is a [`mkosi`] based setup for a dedicated, image-based OS for the [signstar] project.

**NOTE**: This setup is not yet production ready and for testing purposes only!

The OS offers a read-only root filesystem (with verity), a [LUKS] encrypted (with [TPM-2.0] backed keys), writable `/var` and `/boot`, based on the [Discoverable Partitions Specification].

Updates to the host are possible using the mechanisms provided by [systemd-sysupdate].

## Requirements

This setup requires [`mkosi`] >= 25.

**NOTE**: [`mkosi`] >=25 is currently not compatible with the linux-hardened kernel (see [mkosi#3054])!

### Using a custom mkosi version

To use e.g. the current latest version of [`mkosi`], add it to `PATH`:

```shell
git clone https://github.com/systemd/mkosi
export PATH="$(pwd)/mkosi/bin/mkosi:$PATH"
```

## Building images

Images for installation and update can be built in one go.
The resulting checksum file is OpenPGP signed using a provided key.

```shell
just build-image <my-OpenPGP-fingerprint>
```

The above creates an ephemeral x509 keypair in the build output directory, which is used for Secure Boot and verity signatures.

To provide your own signing keypair, also provide the second and third parameter to the recipe:

```shell
just build-image <my-OpenPGP-fingerprint> /path/to/signing.key /path/to/signing.cert
```

## Versioning

The version of the operation system is defined by the contents of the `mkosi.version` file.

## Running images

The lateset built image can be run using [QEMU]:

```shell
just run-image
```

## Installation

An initial image for installation is created in the output directory after [building images].

The file `SignstarOS_<mkosi.version>.raw` can be written to a block device on a machine supporting [UEFI], in ["setup mode"] for [Secure Boot].
After booting, the OS should automatically enroll the provided keys.

## Updating

Each build provides artifacts, that are used by the automatic update system:

- `SignstarOS_<mkosi.version>.efi`
- `SignstarOS_<mkosi.version>.root-x86-64.<root-UUID>.raw`
- `SignstarOS_<mkosi.version>.root-x86-64-verity.<root-verity-UUID>.raw`
- `SignstarOS_<mkosi.version>.root-x86-64-verity-sig.<root-verity-sig-UUID>.raw`
- `SignstarOS_<mkosi.version>.SHA256SUMS`
- `SignstarOS_<mkosi.version>.SHA256SUMS.gpg`

All files need to be uploaded to the remote server location, which is setup in the image, using [sysupdate.d].
The following files are expected to be renamed:

- `SignstarOS_<mkosi.version>.SHA256SUMS` -> `SHA256SUMS`
- `SignstarOS_<mkosi.version>.SHA256SUMS.gpg` -> `SHA256SUMS.gpg`

The running operating system will automatically poll for updates in the configured location, download checksums and signature for artifacts of newer version than its own and update to them.
After updating, the system automatically reboots into the new version of the OS.

[`mkosi`]: https://man.archlinux.org/man/mkosi.1
[signstar]: https://gitlab.archlinux.org/archlinux/signstar
[TPM-2.0]: https://en.wikipedia.org/wiki/Trusted_Platform_Module
[LUKS]: https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup
[Discoverable Partitions Specification]: https://uapi-group.org/specifications/specs/discoverable_partitions_specification/
[systemd-sysupdate]: https://man.archlinux.org/man/systemd-sysupdate.8
[building images]: #building-images
[QEMU]: https://man.archlinux.org/man/qemu.1
[UEFI]: https://en.wikipedia.org/wiki/UEFI
["setup mode"]: https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot#Putting_firmware_in_%22Setup_Mode%22
[Secure Boot]: https://en.wikipedia.org/wiki/UEFI#Secure_Boot
[sysupdate.d]: https://man.archlinux.org/man/sysupdate.d.5
[mkosi#3054]: https://github.com/systemd/mkosi/issues/3054
