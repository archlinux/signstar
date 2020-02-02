# Signstar

Provide a secure way to sign packages, arch iso's and pacman databases in an enclave.

## Requirements

- simple auditable and memory safe non-interpreted language aka rust
- runs as login shell accepting stdin and outputting a signature to stdout
- sandbox the whole process including seccomp filters
- simple logging facility: user, hash of input, date
- avoid any shellout and writing to harddisc if possible
- must not be possible to do anything else than signing an artifact###

## Threat model

### Obtaining GPG key

- Prevent extraction of the key by using a GPG smartcard or TPM.

### Unauthorized signing

- Restrict network access to a specific server to reduce exposure
- Restrict ssh access to very specific keys
- Restrict ssh key access to a dedicated user

### Considerations

- Think about ways to isolate inputs and not allow users/packagers to sign arbitrary date. However this will require sophisticated changes as repo database and package files can easily be changed before sending to the signing server. We would need to restrict it should tooling and workflow similar

## Architecture

For signing a dedicated user is set up on a secure enclave which only allows ssh logins from a specific server. A dedicated user on the source server can ssh into the signing server and retrieve a signed artefact back.

```bash
ssh signer@signstar.archlinux.org < core.db.tar.xz > core.db.tar.xz.sig
```

The sshd_config is configured as:

```
Match user signer
    ForceCommand /usr/bin/signstar
```
