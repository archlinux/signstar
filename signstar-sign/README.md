# Signstar Sign

This crate offers an executable for processing signing requests.
Signing requests are created using the [`signstar-request-signature`] and specify everything that is needed for creating an artifact signature.
The signing response returned by this executable contains a raw, protocol-specific framing.
Currently, `signstar-sign` can created only OpenPGP signatures but the format is extensible and more could be implemented in the future.

<!--

The following sets up a dummy NetHSM device, which serves as a backend for storing private parts of the signing key.

```bash
# use a custom, temporary directory for all generated files
nethsm_tmpdir="$(mktemp --directory --suffix '.nethsm-test')"
# set a custom, temporary configuration file location
export NETHSM_CONFIG="$(mktemp --tmpdir="$nethsm_tmpdir" --suffix '-nethsm.toml' --dry-run)"
# add the container using unsafe TLS connection handling for testing
nethsm env add device --label test https://localhost:8443/api/v1 Unsafe
# prepare a temporary passphrase file for the initial admin user passphrase
nethsm_admin_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.admin-passphrase.txt')"
export NETHSM_PASSPHRASE_FILE="$nethsm_admin_passphrase_file"
printf 'my-very-unsafe-admin-passphrase' > "$NETHSM_PASSPHRASE_FILE"
# add the default admin user credentials
nethsm env add credentials admin Administrator
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
# prepare a temporary passphrase file for the initial unlock passphrase
export NETHSM_UNLOCK_PASSPHRASE_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.unlock-passphrase.txt')"
printf 'my-very-unsafe-unlock-passphrase' > "$NETHSM_UNLOCK_PASSPHRASE_FILE"
# reuse the initial admin passphrase
export NETHSM_ADMIN_PASSPHRASE_FILE="$nethsm_admin_passphrase_file"
nethsm provision

nethsm_admin1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.admin1-passphrase.txt')"
printf 'my-very-unsafe-admin1-passphrase' > "$nethsm_admin1_passphrase_file"
nethsm_operator1_passphrase_file="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.operator1-passphrase.txt')"
printf 'my-very-unsafe-operator1-passphrase' > "$nethsm_operator1_passphrase_file"

# add users
export NETHSM_PASSPHRASE_FILE="$nethsm_admin1_passphrase_file"
nethsm user add "Some Admin1" Administrator admin1
nethsm env add credentials admin1 Administrator
export NETHSM_PASSPHRASE_FILE="$nethsm_operator1_passphrase_file"
nethsm user add "Some Operator1" Operator operator1
nethsm env add credentials operator1 Operator

export NETHSM_KEY_CERT_OUTPUT_FILE="$(mktemp --tmpdir="$nethsm_tmpdir" --dry-run --suffix '-nethsm.openpgp-cert.pgp')"

# create a signing key
nethsm --user admin1 key generate --key-id signing1 --tags tag1 Curve25519 EdDsaSignature

# an R-Administrator can only modify system-wide users
nethsm --user admin1 user tag operator1 tag1

# add an openpgp certificate to the key
nethsm --user admin1 --user operator1 openpgp add --can-sign signing1 "Test signing1 key <test@example.org>"
nethsm --user operator1 key cert get --force signing1
rpacket dump "$NETHSM_KEY_CERT_OUTPUT_FILE" | grep "Test signing1 key"

# signing
export NETHSM_KEY_ID=signing1
```
-->

## `signstar-sign`

The following command takes a signing request, encoded in JSON, and produces a JSON response.
The JSON response contains a `signature` field, which is an armored OpenPGP signature.

```bash
signstar-sign < ../signstar-request-signature/tests/sample-request.json | jq --raw-output .signature | rsop dearmor | rpacket dump
```
