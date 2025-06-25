# NetHSM Command Line Interface

A command line interface (CLI) for the Nitrokey [NetHSM] based on the [nethsm crate].

## Documentation

- <https://signstar.archlinux.page/rustdoc/nethsm_cli/> for development version of the crate
- <https://docs.rs/nethsm_cli/latest/nethsm_cli/> for released versions of the crate

## Installation

This crate can be installed using `cargo`:

```bash no_run
cargo install nethsm-cli
```

Afterwards the `nethsm` executable is available.

It is recommended to refer to the extensive `--help` output of the executable and its subcommands.

## Usage

The following assumes a recent version of `openssl` and `podman`.

### Start a test container

```bash no_run
podman run --rm -ti --network=pasta:-t,auto,-u,auto,-T,auto,-U,auto docker.io/nitrokey/nethsm:testing
```

### Configuration file

The configuration file uses the [TOML] format.

By default an Operating System specific, well-defined configuration file location is chosen.
Using `-c` / `--config` / the `NETHSM_CONFIG` environment variable it is possible to provide a custom configuration file location.

```bash
# use a custom, temporary directory for all generated files
nethsm_tmpdir="$(mktemp --directory --suffix '.nethsm-test')"
# set a custom, temporary configuration file location
export NETHSM_CONFIG="$(mktemp --tmpdir="$nethsm_tmpdir" --suffix '-nethsm.toml' --dry-run)"
```

To be able to interact with a NetHSM (or the testing container), each device must be added to the configuration file.

```bash
# add the container using unsafe TLS connection handling for testing
nethsm env add device --label test https://localhost:8443/api/v1 Unsafe
```

If only one device environment is configured, it is used by default when issuing `nethsm` commands.
If more than one environment is configured, the target device must be selected using the global `-l`/ `--label` option.

The handling of credentials is flexible: Credentials can be stored in the configuration file with or without passphrases or not at all.
If credentials are not configured, they are prompted for interactively.

```bash
# prepare a temporary passphrase file for the initial admin user passphrase
nethsm_admin_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.admin-passphrase.txt')"
export NETHSM_PASSPHRASE_FILE="$nethsm_admin_passphrase_file"
printf 'my-very-unsafe-admin-passphrase' > "$NETHSM_PASSPHRASE_FILE"
# add the default admin user credentials
nethsm env add credentials admin Administrator
```

<!--
```bash
set +x
counter=0

while ! nethsm health state; do
  printf "NetHSM is not ready, waiting (try %d)...\n" "$counter"
  sleep 1
  counter=$(( counter + 1 ))
  if (( counter > 30 )); then
    printf "NetHSM is not up even after 30 tries. Aborting."
    set -x
    exit 2
  fi
done

printf "NetHSM is ready for provisioning after %d seconds.\n" "$counter"
set -x
```
-->

### Provisioning

Before using a device for the first time, it must be provisioned.
This includes setting the passphrase for the initial "admin" user, the unlock passphrase and the system time of the device.

```bash
# prepare a temporary passphrase file for the initial unlock passphrase
export NETHSM_UNLOCK_PASSPHRASE_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.unlock-passphrase.txt')"
printf 'my-very-unsafe-unlock-passphrase' > "$NETHSM_UNLOCK_PASSPHRASE_FILE"
# reuse the initial admin passphrase
export NETHSM_ADMIN_PASSPHRASE_FILE="$nethsm_admin_passphrase_file"
nethsm provision
```

### Users

Each user may be in exactly one role ("Administrator", "Operator", "Metrics" or "Backup").
Users either exist system-wide or in a "Namespace".
Users in a Namespace only have access to users and keys in their own Namespace and are not able to interact with system-wide facilities.
System-wide users on the other hand are not able to access keys or manipulate users in a Namespace, but can interact with other system-wide facilities, as well as system-wide users and keys.

- "Administrator": for adjusting system configuration, managing users and keys (may exist in a Namespace or system-wide)
  - *R-Administrator*: a system-wide Administrator which is able to interact with all system-wide facilities, as well as managing system-wide users and keys
  - *N-Administrator*: a namespace Administrator, which is only able to operate on users and keys in their own namespace
- "Operator": for using cryptographic keys and getting random bytes (may exist in a Namespace or system-wide)
- "Metrics": for retrieving metrics of a device (may only exist system-wide)
- "Backup": for creating and downloading backups of a device (may only exist system-wide)

System-wide and namespace users are easily distinguishable: While system-wide user names consist only of characters in the set `[a-z0-9]` (e.g. `admin1`), namespace user names consist of characters in the set `[a-z0-9~]` and start with the namespace name (e.g. `namespace1~admin1`).

```bash
nethsm_admin1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.admin1-passphrase.txt')"
printf 'my-very-unsafe-admin1-passphrase' > "$nethsm_admin1_passphrase_file"
nethsm_operator1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.operator1-passphrase.txt')"
printf 'my-very-unsafe-operator1-passphrase' > "$nethsm_operator1_passphrase_file"
nethsm_backup1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.backup1-passphrase.txt')"
printf 'my-very-unsafe-backup1-passphrase' > "$nethsm_backup1_passphrase_file"
nethsm_metrics1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.metrics1-passphrase.txt')"
printf 'my-very-unsafe-metrics1-passphrase' > "$nethsm_metrics1_passphrase_file"
nethsm_namespace1_admin1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.namespace1-admin1-passphrase.txt')"
printf 'my-very-unsafe-namespace1-admin1-passphrase' > "$nethsm_namespace1_admin1_passphrase_file"
nethsm_namespace1_operator1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.namespace1-operator1-passphrase.txt')"
printf 'my-very-unsafe-namespace1-operator1-passphrase' > "$nethsm_namespace1_operator1_passphrase_file"

# we create a user in each role and add the credentials including passphrases to the configuration
# NOTE: this is for testing purposes! passphrases stored in configuration files can easily be retrieved!
export NETHSM_PASSPHRASE_FILE="$nethsm_admin1_passphrase_file"
nethsm user add "Some Admin1" Administrator admin1
nethsm env add credentials admin1 Administrator
export NETHSM_PASSPHRASE_FILE="$nethsm_operator1_passphrase_file"
nethsm user add "Some Operator1" Operator operator1
nethsm env add credentials operator1 Operator
export NETHSM_PASSPHRASE_FILE="$nethsm_backup1_passphrase_file"
nethsm user add "Some Backup1" Backup backup1
nethsm env add credentials backup1 Backup
export NETHSM_PASSPHRASE_FILE="$nethsm_metrics1_passphrase_file"
nethsm user add "Some Metrics1" Metrics metrics1
nethsm env add credentials metrics1 Metrics

# we also create an admin for a namespace "namespace1" and create that namespace
export NETHSM_PASSPHRASE_FILE="$nethsm_namespace1_admin1_passphrase_file"
nethsm user add "Namespace1 Admin1" Administrator namespace1~admin1
nethsm env add credentials namespace1~admin1 Administrator
nethsm --user admin namespace add namespace1

# now the N-Administrator can create further users in that namespace
export NETHSM_PASSPHRASE_FILE="$nethsm_operator1_passphrase_file"
nethsm --user namespace1~admin1 user add "Namespace1 Operator1" Operator namespace1~operator1
nethsm env add credentials namespace1~operator1 Operator

# NOTE: from now on we have to be *specific* about which Administrator and which Operator user to use for each action as we have multiple and `nethsm` opportunistically selects the first it finds!

# show the configured environments in the configuration file
nethsm env list
```

The user names and accompanying information can be queried:

```bash
# the R-Administrator can see all users
while read -r user; do
   nethsm --user admin1 user get "$user"
done < <(nethsm --user admin1 user list)

# the N-Administrator can only see the users in its own namespace
while read -r user; do
   nethsm --user namespace1~admin1 user get "$user"
done < <(nethsm --user namespace1~admin1 user list)
```

Tags for users can only be created once keys with those tags exists.

### Keys

Keys on the device are managed using users in the "Administrator" role.
Depending on restrictions (tags), the keys may then be used by users in the "Operator" role.

**NOTE**: Keys created by an *N-Administrator* are only visible within their namespace and only available to *Operator* users in that namespace.

#### Generating keys

Below, we are generating keys of all available types (Curve25519, EcP224, EcP256, EcP384, EcP521, Generic and Rsa).
When generating a key, the unique ID for it may be set manually (else it is auto-generated).
Tags, which later on allow users access to the keys may also be set during key generation.

Note that some keys require to set the key bit length (i.e. Generic and Rsa).

```bash
# keys created by the R-Administrator are only available to system-wide Operator users!
nethsm --user admin1 key generate --key-id signing1 --tags tag1 Curve25519 EdDsaSignature
nethsm --user admin1 key generate --key-id signing2 --tags tag2 EcP224 EcdsaSignature
nethsm --user admin1 key generate --key-id signing3 --tags tag2 EcP256 EcdsaSignature
nethsm --user admin1 key generate --key-id signing4 --tags tag2 EcP384 EcdsaSignature
nethsm --user admin1 key generate --key-id signing5 --tags tag2 EcP521 EcdsaSignature
nethsm --user admin1 key generate --key-id encdec1 --tags tag3 --length 128 Generic AesDecryptionCbc AesEncryptionCbc
nethsm --user admin1 key generate --key-id dec1 --tags tag4 --length 2048 Rsa RsaDecryptionPkcs1
nethsm --user admin1 key generate --key-id signing6 --tags tag5 --length 2048 Rsa RsaSignaturePssSha512
nethsm --user admin1 key generate --key-id signing8 --tags tag6 --length 2048 Rsa RsaSignaturePkcs1

# keys created by the N-Administrator are only available to Operator users in the same namespace!
nethsm --user namespace1~admin1 key generate --key-id signing1 --tags tag1 Curve25519 EdDsaSignature
nethsm --user namespace1~admin1 key generate --key-id signing2 --tags tag2 EcP224 EcdsaSignature
nethsm --user namespace1~admin1 key generate --key-id signing3 --tags tag2 EcP256 EcdsaSignature
nethsm --user namespace1~admin1 key generate --key-id signing4 --tags tag2 EcP384 EcdsaSignature
nethsm --user namespace1~admin1 key generate --key-id signing5 --tags tag2 EcP521 EcdsaSignature
nethsm --user namespace1~admin1 key generate --key-id encdec1 --length 128 --tags tag3 Generic AesDecryptionCbc AesEncryptionCbc
nethsm --user namespace1~admin1 key generate --key-id dec1 --length 2048 --tags tag4 Rsa RsaDecryptionPkcs1
nethsm --user namespace1~admin1 key generate --key-id signing6 --length 2048 --tags tag5 Rsa RsaSignaturePssSha512
nethsm --user namespace1~admin1 key generate --key-id signing8 --length 2048 --tags tag6 Rsa RsaSignaturePkcs1
```

All key IDs on the device and info about them can be listed:

```bash
# R-Administrators can only see system-wide keys
while read -r key; do
  nethsm key get "$key"
done < <(nethsm --user admin1 key list)

# N-Administrators can only see keys in their own namespace
while read -r key; do
  nethsm key get "$key"
done < <(nethsm --user namespace1~admin1 key list)
```

#### Importing keys

Keys can also be imported:

```bash
ed25519_cert_pem="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.ed25519_cert.pem')"
ed25519_cert_der="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.ed25519_cert.pkcs8.der')"
openssl genpkey -algorithm ed25519 -out "$ed25519_cert_pem"
openssl pkcs8 -topk8 -inform pem -in "$ed25519_cert_pem" -outform der -nocrypt -out "$ed25519_cert_der"

# import supports PKCS#8 private key in ASN.1 DER-encoded format, by default
nethsm --user admin1 key import --key-id signing7 Curve25519 "$ed25519_cert_der" EdDsaSignature

# however, importing a PKCS#8 private key in ASN.1 PEM-encoded format is supported, too
nethsm --user admin1 key import --format PEM --key-id signing9 Curve25519 "$ed25519_cert_pem" EdDsaSignature

# forgot to set a tag for key signing7 so that operator1 has access!
nethsm --user admin1 key tag signing7 tag1

# show information about the new key
nethsm --user operator1 key get signing7

# the same for namespace1
# import supports PKCS#8 private key in ASN.1 DER-encoded format, by default
nethsm --user namespace1~admin1 key import --key-id signing7 Curve25519 "$ed25519_cert_der" EdDsaSignature

# however, importing a PKCS#8 private key in ASN.1 PEM-encoded format is supported, too
nethsm --user namespace1~admin1 key import --format PEM --key-id signing9 Curve25519 "$ed25519_cert_pem" EdDsaSignature

# forgot to set a tag for key signing7 so that namespace1~operator1 has access!
nethsm --user namespace1~admin1 key tag signing7 tag1

# show information about the new key
nethsm --user namespace1~operator1 key get signing7
```

#### Access to keys

To provide access to keys for users, the users have to be tagged with the same tags as the keys.

```bash
# an R-Administrator can only modify system-wide users
nethsm --user admin1 user tag operator1 tag1
# an N-Administrator can only modify namespace users
nethsm --user namespace1~admin1 user tag namespace1~operator1 tag1
```

#### Signing messages

```bash
export NETHSM_KEY_SIGNATURE_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.readme.signature.sig')"
export NETHSM_KEY_PUBKEY_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.pubkey.pem')"
message_digest="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.message.dgst')"

# if we add the tag2 tag for operator1 it is able to use signing{2-5}
nethsm --user admin1 user tag operator1 tag2
# if we add the tag5 tag for operator1 it is able to use signing6
nethsm --user admin1 user tag operator1 tag5
nethsm --user admin1 user tag operator1 tag6

# we made the same tags available in namespace1, so the examples work similarly
# if we add the tag2 tag for namespace1~operator1 it is able to use signing{2-5}
nethsm --user namespace1~admin1 user tag namespace1~operator1 tag2
# if we add the tag5 tag for namespace1~operator1 it is able to use signing6
nethsm --user namespace1~admin1 user tag namespace1~operator1 tag5
nethsm --user namespace1~admin1 user tag namespace1~operator1 tag6

# create a signature with each key type
nethsm --user operator1 key sign --force signing1 EdDsa README.md
nethsm --user operator1 key public-key --force signing1
openssl pkeyutl -verify -in README.md -rawin -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user operator1 key sign --force signing2 EcdsaP224 README.md
nethsm --user operator1 key public-key --force signing2
openssl dgst -sha224 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user operator1 key sign --force signing3 EcdsaP256 README.md
nethsm --user operator1 key public-key --force signing3
openssl dgst -sha256 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user operator1 key sign --force signing4 EcdsaP384 README.md
nethsm --user operator1 key public-key --force signing4
openssl dgst -sha384 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user operator1 key sign --force signing5 EcdsaP521 README.md
nethsm --user operator1 key public-key --force signing5
openssl dgst -sha512 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user operator1 key sign --force signing6 PssSha512 README.md
nethsm --user operator1 key public-key --force signing6
openssl dgst -sha512 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha512 -pkeyopt rsa_pss_saltlen:-1

nethsm --user operator1 key sign --force signing7 EdDsa README.md
nethsm --user operator1 key public-key --force signing7
openssl pkeyutl -verify -in README.md -rawin -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

# the same of course also works in a namespace!
nethsm --user namespace1~operator1 key sign --force signing1 EdDsa README.md
nethsm --user namespace1~operator1 key public-key --force signing1
openssl pkeyutl -verify -in README.md -rawin -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user namespace1~operator1 key sign --force signing2 EcdsaP224 README.md
nethsm --user namespace1~operator1 key public-key --force signing2
openssl dgst -sha224 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user namespace1~operator1 key sign --force signing3 EcdsaP256 README.md
nethsm --user namespace1~operator1 key public-key --force signing3
openssl dgst -sha256 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user namespace1~operator1 key sign --force signing4 EcdsaP384 README.md
nethsm --user namespace1~operator1 key public-key --force signing4
openssl dgst -sha384 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user namespace1~operator1 key sign --force signing5 EcdsaP521 README.md
nethsm --user namespace1~operator1 key public-key --force signing5
openssl dgst -sha512 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm --user namespace1~operator1 key sign --force signing6 PssSha512 README.md
nethsm --user namespace1~operator1 key public-key --force signing6
openssl dgst -sha512 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha512 -pkeyopt rsa_pss_saltlen:-1

nethsm --user namespace1~operator1 key sign --force signing7 EdDsa README.md
nethsm --user namespace1~operator1 key public-key --force signing7
openssl pkeyutl -verify -in README.md -rawin -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

# if we remove the tag5 tag for operator1 it is no longer able to use signing6
nethsm --user admin1 user untag operator1 tag5
# analogous: if we remove the tag5 tag for namespace1~operator1 it is no longer able to use signing6
nethsm --user namespace1~admin1 user untag namespace1~operator1 tag5
```

#### OpenPGP

The CLI can also create OpenPGP certificates for keys stored in the HSM:

```bash
export GNUPGHOME="$(mktemp --directory --tmpdir="$nethsm_tmpdir" --suffix 'gnupghome')"
export NETHSM_KEY_CERT_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.openpgp-cert.pgp')"

nethsm --user admin1 --user operator1 openpgp add --can-sign signing1 "Test signing1 key <test@example.org>"
nethsm --user operator1 key cert get --force signing1
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing1 key"

nethsm --user admin1 --user operator1 openpgp add signing3 "Test signing3 key <test@example.org>"
nethsm --user operator1 key cert get --force signing3
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing3 key"

nethsm --user admin1 --user operator1 openpgp add signing4 "Test signing4 key <test@example.org>"
nethsm --user operator1 key cert get --force signing4
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing4 key"

nethsm --user admin1 --user operator1 openpgp add signing5 "Test signing5 key <test@example.org>"
nethsm --user operator1 key cert get --force signing5
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing5 key"

nethsm --user admin1 --user operator1 openpgp add signing8 "Test signing8 key <test@example.org>"
nethsm --user operator1 key cert get --force signing8
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing8 key"

# all of this works with our namespaced keys as well of course!
nethsm --user namespace1~admin1 --user namespace1~operator1 openpgp add --can-sign signing1 "Test signing1 key <test@example.org>"
nethsm --user namespace1~operator1 key cert get --force signing1
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing1 key"

nethsm --user namespace1~admin1 --user namespace1~operator1 openpgp add signing3 "Test signing3 key <test@example.org>"
nethsm --user namespace1~operator1 key cert get --force signing3
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing3 key"

nethsm --user namespace1~admin1 --user namespace1~operator1 openpgp add signing4 "Test signing4 key <test@example.org>"
nethsm --user namespace1~operator1 key cert get --force signing4
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing4 key"

nethsm --user namespace1~admin1 --user namespace1~operator1 openpgp add signing5 "Test signing5 key <test@example.org>"
nethsm --user namespace1~operator1 key cert get --force signing5
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing5 key"

nethsm --user namespace1~admin1 --user namespace1~operator1 openpgp add signing8 "Test signing8 key <test@example.org>"
nethsm --user namespace1~operator1 key cert get --force signing8
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing8 key"
```

Importing new keys:

```bash
export NETHSM_OPENPGP_TSK_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.openpgp-private-key.tsk')"
rsop generate-key --no-armor --signing-only "Test signing10 key <test@example.org>" > "$NETHSM_OPENPGP_TSK_FILE"
nethsm --user admin1 openpgp import --key-id signing10 --tags tag1
# openpgp import automatically stores the certificate so it can be fetched
nethsm --user operator1 key cert get --force signing10
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing10 key"

nethsm --user namespace1~admin1 openpgp import --key-id signing10 --tags tag1
# openpgp import automatically stores the certificate so it can be fetched
nethsm --user namespace1~operator1 key cert get --force signing10
gpg --import "$NETHSM_KEY_CERT_OUTPUT_FILE"
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing10 key"
```

Signing messages:

```bash
export NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.openpgp-message.txt.sig')"
export NETHSM_OPENPGP_SIGNATURE_MESSAGE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.openpgp-message.txt')"
printf "I like strawberries\n" > "$NETHSM_OPENPGP_SIGNATURE_MESSAGE"

for key in signing1 signing3 signing4 signing5 signing8 signing10; do
  nethsm --user operator1 openpgp sign --force "$key"
  gpg --verify "$NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE" "$NETHSM_OPENPGP_SIGNATURE_MESSAGE"
  nethsm --user operator1 key cert get --force "$key"
  rsop verify "$NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE" "$NETHSM_KEY_CERT_OUTPUT_FILE" < "$NETHSM_OPENPGP_SIGNATURE_MESSAGE"
  sqop verify "$NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE" "$NETHSM_KEY_CERT_OUTPUT_FILE" < "$NETHSM_OPENPGP_SIGNATURE_MESSAGE"

  nethsm --user namespace1~operator1 openpgp sign --force "$key"
  gpg --verify "$NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE" "$NETHSM_OPENPGP_SIGNATURE_MESSAGE"
  nethsm --user namespace1~operator1 key cert get --force "$key"
  rsop verify "$NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE" "$NETHSM_KEY_CERT_OUTPUT_FILE" < "$NETHSM_OPENPGP_SIGNATURE_MESSAGE"
done

signstar-request-signature prepare "$NETHSM_OPENPGP_SIGNATURE_MESSAGE" | tee "${NETHSM_OPENPGP_SIGNATURE_MESSAGE}.json"
nethsm openpgp sign-state --force "signing1" "${NETHSM_OPENPGP_SIGNATURE_MESSAGE}.json"
# the signature is always armored
grep -- "-----BEGIN PGP SIGNATURE-----" "$NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE"
gpg --verify "$NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE" "$NETHSM_OPENPGP_SIGNATURE_MESSAGE"
rpacket dump "$NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE"
sha512sum "$NETHSM_OPENPGP_SIGNATURE_MESSAGE"
jq < "${NETHSM_OPENPGP_SIGNATURE_MESSAGE}.json"
```


#### Encrypting messages

Messages can be encrypted using keys that offer the key mechanisms for this operation.

```bash
message="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.message.txt')"
printf "Hello World! This is a message!!" > "$message"
export NETHSM_KEY_ENCRYPT_IV="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.iv.txt')"
printf "This is unsafe!!" > "$NETHSM_KEY_ENCRYPT_IV"
export NETHSM_KEY_ENCRYPT_OUTPUT="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.symmetric-encrypted-message.txt.enc')"
# the initialization vector for decryption must be the same
export NETHSM_KEY_DECRYPT_IV="$NETHSM_KEY_ENCRYPT_IV"
export NETHSM_KEY_DECRYPT_OUTPUT="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.decrypted-message.txt')"

# we need to provide access to the key by tagging the user
nethsm --user admin1 user tag operator1 tag3

# let's use our symmetric encryption key to encrypt a message
nethsm --user operator1 key encrypt --force encdec1 "$message"

# now let's decrypt the encrypted message again
nethsm --user operator1 key decrypt --force encdec1 "$NETHSM_KEY_ENCRYPT_OUTPUT" AesCbc
cat "$NETHSM_KEY_DECRYPT_OUTPUT"

[[ "$(b2sum "$NETHSM_KEY_DECRYPT_OUTPUT" | cut -d ' ' -f1)" == "$(b2sum "$message" | cut -d ' ' -f1)" ]]

# this works analogously in a namespace
# we need to provide access to the key by tagging the user
nethsm --user namespace1~admin1 user tag namespace1~operator1 tag3
# let's use our symmetric encryption key to encrypt a message
nethsm --user namespace1~operator1 key encrypt --force encdec1 "$message"
# now let's decrypt the encrypted message again
nethsm --user namespace1~operator1 key decrypt --force encdec1 "$NETHSM_KEY_ENCRYPT_OUTPUT" AesCbc
cat "$NETHSM_KEY_DECRYPT_OUTPUT"
[[ "$(b2sum "$NETHSM_KEY_DECRYPT_OUTPUT" | cut -d ' ' -f1)" == "$(b2sum "$message" | cut -d ' ' -f1)" ]]
```

The same works for asymmetric keys as well:

```bash
# unset the initialization vectors as we do not need them for this
unset NETHSM_KEY_DECRYPT_IV NETHSM_KEY_ENCRYPT_IV
asymmetric_enc_message="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.asymmetric-encrypted-message.txt.enc')"

# we need to provide access to the key by tagging the user
nethsm --user admin1 user tag operator1 tag4
# retrieve the public key of the key to use (and overwrite any previously existing)
nethsm --user operator1 key public-key --force dec1
# encrypt the previous message
openssl pkeyutl -encrypt -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin -in "$message" -out "$asymmetric_enc_message"
# decrypt the asymmetrically encrypted message and replace any existing output
nethsm --user operator1 key decrypt --force dec1 "$asymmetric_enc_message" Pkcs1
cat "$NETHSM_KEY_DECRYPT_OUTPUT"
[[ "$(b2sum "$NETHSM_KEY_DECRYPT_OUTPUT" | cut -d ' ' -f1)" == "$(b2sum "$message" | cut -d ' ' -f1)" ]]

# this works analogously in a namespace
# we need to provide access to the key by tagging the user
nethsm --user namespace1~admin1 user tag namespace1~operator1 tag4
# retrieve the public key of the key to use (and overwrite any previously existing)
nethsm --user namespace1~operator1 key public-key --force dec1
# encrypt the previous message
openssl pkeyutl -encrypt -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin -in "$message" -out "$asymmetric_enc_message"
# decrypt the asymmetrically encrypted message and replace any existing output
nethsm --user namespace1~operator1 key decrypt --force dec1 "$asymmetric_enc_message" Pkcs1
cat "$NETHSM_KEY_DECRYPT_OUTPUT"
[[ "$(b2sum "$NETHSM_KEY_DECRYPT_OUTPUT" | cut -d ' ' -f1)" == "$(b2sum "$message" | cut -d ' ' -f1)" ]]
```

#### Public key

Administrators and operators can retrieve the public key of any key:

```bash
# when NETHSM_KEY_PUBKEY_OUTPUT_FILE is set, the public key is written to that file
# to print to stdout, we unset the environment variable
unset NETHSM_KEY_PUBKEY_OUTPUT_FILE

# keys of type "Generic" don't have a public key, so we do not request them
for key in signing{1..8} dec1; do
  nethsm --user operator1 key public-key --force "$key"
  # in our namespace1 we have keys of the same name, that we can get public keys for
  nethsm --user namespace1~operator1 key public-key --force "$key"
done
```

#### Certificate Signing Requests for keys

Certificate Signing Requests for a particular target can be issued using the keys.

```bash
# get a CSR for example.com
nethsm --user operator1 key csr signing7 example.com
# also for the key of the same name in our namespace
nethsm --user namespace1~operator1 key csr signing7 example.com
```

### Random bytes

The device can generate an arbitrary number of random bytes on demand.
All users in the "Operator" role have access to this functionality!

```bash
export NETHSM_RANDOM_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.random.txt')"
nethsm random 200

[[ -f "$NETHSM_RANDOM_OUTPUT_FILE" ]]
```

### Metrics

The metrics for a device can only be retrieved by a system-wide user in the "Metrics" role.

```bash
nethsm metrics
```

### Device configuration

Several aspects of the device configuration can be retrieved and modified.
The device configuration is only available to "R-Administrators" (system-wide users in the "Administrator" role).

#### Boot mode

The boot mode defines whether the system starts into "Locked" or "Operational" state (the former requiring to supply the unlock passphrase to get to "Operational" state).

```bash
nethsm --user admin1 config get boot-mode

# let's set it to unattended
nethsm --user admin1 config set boot-mode Unattended

nethsm --user admin1 config get boot-mode
```

#### Logging

Each device may send syslog to a remote host.

```bash
nethsm --user admin1 config get logging
```

#### Network

The devices have a unique and static network configuration.

```bash
nethsm --user admin1 config get network
```

#### System Time

The device's system time can be queried and set.

```bash
nethsm --user admin1 config get time
nethsm --user admin1 config set time
nethsm --user admin1 config get time
```

#### TLS certificate

We can get and set the TLS certificate used for the device.

```bash
nethsm --user admin1 config get tls-certificate
# this generates a new RSA 4096bit certificate on the device
nethsm --user admin1 config set tls-generate Rsa 4096
nethsm --user admin1 config get tls-certificate
```

We can also receive only the public key for the TLS certificate:

```bash
nethsm --user admin1 config get tls-public-key
```

Or generate a Certificate Signing Request for the TLS certificate:

```bash
nethsm --user admin1 config get tls-csr example.com
```

#### Setting passphrases

The backup passphrase is used to decrypt a backup created for the device, when importing. By default it is the empty string (`""`).

```bash
nethsm_backup_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.backup-passphrase.txt')"
printf 'my-very-unsafe-backup-passphrase' > "$nethsm_backup_passphrase_file"
export NETHSM_NEW_PASSPHRASE_FILE="$nethsm_backup_passphrase_file"
nethsm_initial_backup_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.initial-backup-passphrase.txt')"
touch "$nethsm_initial_backup_passphrase_file"
export NETHSM_OLD_PASSPHRASE_FILE="$nethsm_initial_backup_passphrase_file"
nethsm --user admin1 config set backup-passphrase
```

The unlock passphrase is set during initial provisioning and is used to unlock the device when it is locked.

```bash
export NETHSM_OLD_PASSPHRASE_FILE="$NETHSM_UNLOCK_PASSPHRASE_FILE"
export NETHSM_NEW_PASSPHRASE_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.unlock-passphrase.txt')"
printf 'my-new-unsafe-unlock-passphrase' > "$NETHSM_NEW_PASSPHRASE_FILE"
nethsm --user admin1 config set unlock-passphrase
```

### Locking

The device can be locked and unlocked, which puts it into state `"Locked"` and `"Operational"`, respectively.

```bash
nethsm --user admin1 lock
nethsm --user admin1 health state
nethsm --user admin1 health alive
# as we have changed the unlock passphrase, we need to provide the new one
export NETHSM_UNLOCK_PASSPHRASE_FILE="$NETHSM_NEW_PASSPHRASE_FILE"
nethsm unlock
nethsm --user admin1 health state
nethsm --user admin1 health ready
```

### System modifications

The devices offer various system level actions, e.g.:

```bash no_run
# reset device to factory settings
nethsm --user admin1 system factory-reset
```

```bash no_run
# reboot device
nethsm --user admin1 system reboot
```

```bash no_run
# shut down device
nethsm --user admin1 system shutdown
```

```bash
# get system info about the device
nethsm --user admin1 system info
```

#### Backups

The device offers backing up of keys and user data.
Backup retrieval is only available to system-wide users in the "Backup" role!

```bash
export NETHSM_BACKUP_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.backup-file.bkp')"
nethsm system backup
```

A backup can later on be used to restore a device, using an "R-Administrator":

```bash no_run
export NETHSM_BACKUP_PASSPHRASE_FILE="$nethsm_backup_passphrase_file"
nethsm --user admin1 system restore "$NETHSM_BACKUP_OUTPUT_FILE"
```

Backups can be validated offline:

```bash
export NETHSM_VALIDATE_BACKUP_PASSPHRASE_FILE="$nethsm_backup_passphrase_file"
nethsm system validate-backup "$NETHSM_BACKUP_OUTPUT_FILE"
```

#### Updates

Updates for the operating system/ firmware of the device are uploaded to the device and then applied or aborted.

```bash no_run
nethsm --user admin1 system upload-update my-update-file.bin
# apply the update
nethsm --user admin1 system commit-update
# abort the update
nethsm --user admin1 system cancel-update
```

<!--
```bash
rm -r -- "$nethsm_tmpdir"
```
-->

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[NetHSM]: https://www.nitrokey.com/products/nethsm
[contributing guidelines]: ../CONTRIBUTING.md
[nethsm crate]: https://crates.io/crates/nethsm
[TOML]: https://toml.io/en/
