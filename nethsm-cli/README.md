# NetHSM Command Line Interface

A command line interface (CLI) for the Nitrokey [NetHSM] based on the [nethsm crate].

## Installation

This crate can be installed using `cargo`:

```sh
cargo install nethsm-cli
```

Afterwards the `nethsm` executable is available.

It is recommended to refer to the extensive `--help` output of the executable and its subcommands.

## Usage

The following assumes a recent version of `openssl` and `podman`.

### Start a test container

```sh
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

* "Administrator": for adjusting system configuration, managing users and keys
* "Operator": for using cryptographic keys and getting random bytes
* "Metrics": for retrieving metrics of a device
* "Backup": for creating and downloading backups of a device

```bash
nethsm_admin1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.admin1-passphrase.txt')"
printf 'my-very-unsafe-admin1-passphrase' > "$nethsm_admin1_passphrase_file"
nethsm_operator1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.operator1-passphrase.txt')"
printf 'my-very-unsafe-operator1-passphrase' > "$nethsm_operator1_passphrase_file"
nethsm_backup1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.backup1-passphrase.txt')"
printf 'my-very-unsafe-backup1-passphrase' > "$nethsm_backup1_passphrase_file"
nethsm_metrics1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.metrics1-passphrase.txt')"
printf 'my-very-unsafe-metrics1-passphrase' > "$nethsm_metrics1_passphrase_file"

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
```

The user names and accompanying information can be queried:

```bash
for user in $(nethsm user list); do
  nethsm user get "$user"
done
```

Tags for users can only be created once keys with those tags exists.

### Keys

Keys on the device are managed using a user in the "Administrator" role.
Depending on restrictions (tags), the keys may then be used by users in the "Operator" role.

#### Generating keys

Below, we are generating keys of all available types (Curve25519, EcP224, EcP256, EcP384, EcP521, Generic and Rsa).
When generating a key, the unique ID for it may be set manually (else it is auto-generated).
Tags, which later on allow users access to the keys may also be set during key generation.

Note that some keys require to set the key bit length (i.e. Generic and Rsa).

```bash
nethsm key generate --key-id signing1 --tags tag1 Curve25519 EdDsaSignature
nethsm key generate --key-id signing2 --tags tag2 EcP224 EcdsaSignature
nethsm key generate --key-id signing3 --tags tag2 EcP256 EcdsaSignature
nethsm key generate --key-id signing4 --tags tag2 EcP384 EcdsaSignature
nethsm key generate --key-id signing5 --tags tag2 EcP521 EcdsaSignature
nethsm key generate --key-id encdec1 --tags tag3 --length 128 Generic AesDecryptionCbc AesEncryptionCbc
nethsm key generate --key-id dec1 --tags tag4 --length 2048 Rsa RsaDecryptionPkcs1
nethsm key generate --key-id signing6 --tags tag5 --length 2048 Rsa RsaSignaturePssSha512
nethsm key generate --key-id signing8 --tags tag6 --length 2048 Rsa RsaSignaturePkcs1
```

All key IDs on the device and info about them can be listed:

```bash
for key in $(nethsm key list); do
  nethsm key get "$key"
done
```

#### Importing keys

Keys can also be imported:

```bash
ed25519_cert_pem="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.ed25519_cert.pem')"
ed25519_cert_der="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.ed25519_cert.pkcs8.der')"
openssl genpkey -algorithm ed25519 -out "$ed25519_cert_pem"
openssl pkcs8 -topk8 -inform pem -in "$ed25519_cert_pem" -outform der -nocrypt -out "$ed25519_cert_der"

# import supports PKCS#8 private key in ASN.1 DER-encoded format, by default
nethsm key import Curve25519 "$ed25519_cert_der" EdDsaSignature --key-id signing7

# however, importing a PKCS#8 private key in ASN.1 PEM-encoded format is supported, too
nethsm key import Curve25519 --format PEM "$ed25519_cert_pem" EdDsaSignature --key-id signing9

# forgot to set a tag!
nethsm key tag signing7 tag1

nethsm key get signing7
```

#### Access to keys

To provide access to keys for users, the users have to be tagged with the same tags as the keys.

```bash
nethsm user tag operator1 tag1
```

#### Signing messages

```bash
export NETHSM_KEY_SIGNATURE_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.readme.signature.sig')"
export NETHSM_KEY_PUBKEY_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.pubkey.pem')"
message_digest="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.message.dgst')"

# if we add the tag2 tag for operator1 it is able to use signing{2-5}
nethsm user tag operator1 tag2
# if we add the tag5 tag for operator1 it is able to use signing6
nethsm user tag operator1 tag5
nethsm user tag operator1 tag6

# create a signature with each key type
nethsm key sign --force signing1 EdDsa README.md
nethsm key public-key --force signing1
openssl pkeyutl -verify -in README.md -rawin -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm key sign --force signing2 EcdsaP224 README.md
nethsm key public-key --force signing2
openssl dgst -sha224 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm key sign --force signing3 EcdsaP256 README.md
nethsm key public-key --force signing3
openssl dgst -sha256 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm key sign --force signing4 EcdsaP384 README.md
nethsm key public-key --force signing4
openssl dgst -sha384 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm key sign --force signing5 EcdsaP521 README.md
nethsm key public-key --force signing5
openssl dgst -sha512 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

nethsm key sign --force signing6 PssSha512 README.md
nethsm key public-key --force signing6
openssl dgst -sha512 -binary README.md > "$message_digest"
openssl pkeyutl -verify -in "$message_digest" -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha512 -pkeyopt rsa_pss_saltlen:-1

nethsm key sign --force signing7 EdDsa README.md
nethsm key public-key --force signing7
openssl pkeyutl -verify -in README.md -rawin -sigfile "$NETHSM_KEY_SIGNATURE_OUTPUT_FILE" -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin

# if we remove the tag5 tag for operator1 it is no longer able to use signing6
nethsm user untag operator1 tag5
```

#### OpenPGP

The CLI can also create OpenPGP certificates for keys stored in the HSM:

```bash
export GNUPGHOME="$(mktemp --directory --tmpdir="$nethsm_tmpdir" --suffix 'gnupghome')"

nethsm openpgp add --can-sign signing1 "Test signing1 key"
nethsm key cert get signing1 > "$nethsm_tmpdir/ed25519.pgp"
gpg --import "$nethsm_tmpdir/ed25519.pgp"
sq inspect "$nethsm_tmpdir/ed25519.pgp" | grep "Test signing1 key"

nethsm openpgp add signing3 "Test signing3 key"
nethsm key cert get signing3 > "$nethsm_tmpdir/p256.pgp"
gpg --import "$nethsm_tmpdir/p256.pgp"
sq inspect "$nethsm_tmpdir/p256.pgp" | grep "Test signing3 key"

nethsm openpgp add signing4 "Test signing4 key"
nethsm key cert get signing4 > "$nethsm_tmpdir/p384.pgp"
gpg --import "$nethsm_tmpdir/p384.pgp"
sq inspect "$nethsm_tmpdir/p384.pgp" | grep "Test signing4 key"

nethsm openpgp add signing5 "Test signing5 key"
nethsm key cert get signing5 > "$nethsm_tmpdir/p521.pgp"
gpg --import "$nethsm_tmpdir/p521.pgp"
sq inspect "$nethsm_tmpdir/p521.pgp" | grep "Test signing5 key"

nethsm openpgp add signing8 "Test signing8 key"
nethsm key cert get signing8 > "$nethsm_tmpdir/rsa.pgp"
gpg --import "$nethsm_tmpdir/rsa.pgp"
sq inspect "$nethsm_tmpdir/rsa.pgp" | grep "Test signing8 key"
```

Importing new keys:

```bash
rsop generate-key --no-armor --signing-only "Test signing10 key <test@example.com>" > "$nethsm_tmpdir/private.pgp"
nethsm openpgp import --tags tag1 --key-id signing10 "$nethsm_tmpdir/private.pgp" > /dev/null
# openpgp import automatically stores the certificate so it can be fetched
nethsm key cert get signing10 > "$nethsm_tmpdir/imported.pgp"
gpg --import "$nethsm_tmpdir/imported.pgp"
sq inspect "$nethsm_tmpdir/imported.pgp" | grep "Test signing10 key"
```

Signing messages:

```bash
echo "I like strawberries" > "$nethsm_tmpdir/message.txt"

for key in signing1 signing3 signing4 signing5 signing8 signing10; do
  printf "Signing with key %s ...\n" "$key"

  nethsm openpgp sign "$key" "$nethsm_tmpdir/message.txt" > "$nethsm_tmpdir/message.txt.pgp"
  gpg --verify "$nethsm_tmpdir/message.txt.pgp" "$nethsm_tmpdir/message.txt"
  nethsm key cert get "$key" > "$nethsm_tmpdir/cert.pgp"
  rsop verify "$nethsm_tmpdir/message.txt.pgp" "$nethsm_tmpdir/cert.pgp" < "$nethsm_tmpdir/message.txt"
done
```


#### Encrypting messages

Messages can be encrypted using keys that offer the key mechanisms for this operation.

```bash
message="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.message.txt')"
printf "Hello World! This is a message!!" > "$message"
export NETHSM_KEY_ENCRYPT_IV="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.iv.txt')"
printf "This is unsafe!!" > "$NETHSM_KEY_ENCRYPT_IV"
export NETHSM_KEY_ENCRYPT_OUTPUT="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.symmetric-encrypted-message.txt.enc')"

# we need to provide access to the key by tagging the user
nethsm user tag operator1 tag3

# let's use our symmetric encryption key to encrypt a message
nethsm key encrypt encdec1 "$message"

# the initialization vector must be the same
export NETHSM_KEY_DECRYPT_IV="$NETHSM_KEY_ENCRYPT_IV"
export NETHSM_KEY_DECRYPT_OUTPUT="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.decrypted-message.txt')"
# now let's decrypt the encrypted message again
nethsm key decrypt encdec1 "$NETHSM_KEY_ENCRYPT_OUTPUT" AesCbc
cat "$NETHSM_KEY_DECRYPT_OUTPUT"

[[ "$(b2sum "$NETHSM_KEY_DECRYPT_OUTPUT" | cut -d ' ' -f1)" == "$(b2sum "$message" | cut -d ' ' -f1)" ]]
```

The same works for asymmetric keys as well:

```bash
# we need to provide access to the key by tagging the user
nethsm user tag operator1 tag4

# unset the initialization vectors as we do not need them for this
unset NETHSM_KEY_DECRYPT_IV NETHSM_KEY_ENCRYPT_IV
# retrieve the public key of the key to use (and overwrite any previously existing)
nethsm key public-key --force dec1

asymmetric_enc_message="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.asymmetric-encrypted-message.txt.enc')"
# encrypt the previous message
openssl pkeyutl -encrypt -inkey "$NETHSM_KEY_PUBKEY_OUTPUT_FILE" -pubin -in "$message" -out "$asymmetric_enc_message"

# decrypt the asymmetrically encrypted message and replace any existing output
nethsm key decrypt dec1 "$asymmetric_enc_message" Pkcs1 --force
cat "$NETHSM_KEY_DECRYPT_OUTPUT"

[[ "$(b2sum "$NETHSM_KEY_DECRYPT_OUTPUT" | cut -d ' ' -f1)" == "$(b2sum "$message" | cut -d ' ' -f1)" ]]
```

#### Public key

Administrators and operators can retrieve the public key of any key:

```bash
# keys of type "Generic" don't have a public key, so we do not request them
for key in signing{1..8} dec1; do
  nethsm key public-key "$key" --force
done
```

#### Certificate Signing Requests for keys

Certificate Signing Requests for a particular target can be issued using the keys.

```bash
# get a CSR for example.com
nethsm key csr signing7 example.com
```

### Random bytes

The device can generate an arbitrary number of random bytes on demand.

```bash
export NETHSM_RANDOM_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.random.txt')"
nethsm random 200

[[ -f "$NETHSM_RANDOM_OUTPUT_FILE" ]]
```

### Metrics

The metrics for a device can only be retrieved by a user in the "Metrics" role.

```bash
nethsm metrics
```

### Device configuration

Several aspects of the device configuration can be retrieved and modified.

#### Boot mode

The boot mode defines whether the system starts into "Locked" or "Operational" state (the former requiring to supply the unlock passphrase to get to "Operational" state).

```bash
nethsm config get boot-mode

# let's set it to unattended
nethsm config set boot-mode Unattended

nethsm config get boot-mode
```

#### Logging

Each device may send syslog to a remote host.

```bash
nethsm config get logging
```

#### Network

The devices have a unique and static network configuration.

```bash
nethsm config get network
```

#### System Time

The device's system time can be queried and set.

```bash
nethsm config get time
nethsm config set time
nethsm config get time
```

#### TLS certificate

We can get and set the TLS certificate used for the device.

```bash
nethsm config get tls-certificate
# this generates a new RSA 4096bit certificate on the device
nethsm config set tls-generate Rsa 4096
nethsm config get tls-certificate
```

We can also receive only the public key for the TLS certificate:

```bash
nethsm config get tls-public-key
```

Or generate a Certificate Signing Request for the TLS certificate:

```bash
nethsm config get tls-csr example.com
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
nethsm config set backup-passphrase
```

The unlock passphrase is set during initial provisioning and is used to unlock the device when it is locked.

```bash
export NETHSM_OLD_PASSPHRASE_FILE="$NETHSM_UNLOCK_PASSPHRASE_FILE"
export NETHSM_NEW_PASSPHRASE_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.unlock-passphrase.txt')"
printf 'my-new-unsafe-unlock-passphrase' > "$NETHSM_NEW_PASSPHRASE_FILE"
nethsm config set unlock-passphrase
```

### Locking

The device can be locked and unlocked, which puts it into state `"Locked"` and `"Operational"`, respectively.

```bash
nethsm lock
nethsm health state
nethsm health alive
# as we have changed the unlock passphrase, we need to provide the new one
export NETHSM_UNLOCK_PASSPHRASE_FILE="$NETHSM_NEW_PASSPHRASE_FILE"
nethsm unlock
nethsm health state
nethsm health ready
```

### System modifications

The devices offer various system level actions, e.g.:

```sh
# reset device to factory settings
nethsm system factory-reset
```

```sh
# reboot device
nethsm system reboot
```

```sh
# shut down device
nethsm system shutdown
```

```bash
# get system info about the device
nethsm system info
```

#### Backups

The device offers backing up of keys and user data.

```bash
export NETHSM_BACKUP_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.backup-file.bkp')"
nethsm system backup
```

A backup can later on be used to restore a device:

```sh
export NETHSM_BACKUP_PASSPHRASE_FILE="$nethsm_backup_passphrase_file"
nethsm system restore "$NETHSM_BACKUP_OUTPUT_FILE"
```

#### Updates

Updates for the operating system/ firmware of the device are uploaded to the device and then applied or aborted.

```sh
nethsm system upload-update my-update-file.bin
# apply the update
nethsm system commit-update
# abort the update
nethsm system cancel-update
```

<!--
```bash
rm -r -- "$nethsm_tmpdir"
```
-->
## License

This project may be used under the terms of the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT) license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[NetHSM]: https://www.nitrokey.com/products/nethsm
[nethsm crate]: https://crates.io/crates/nethsm
[TOML]: https://toml.io/en/
