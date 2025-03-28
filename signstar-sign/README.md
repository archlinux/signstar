# Signstar Sign

This crate offers an executable for processing signing requests.
Signing requests are created using the [`signstar-request-signature`] and specify everything that is needed for creating an artifact signature.
The signing response returned by this executable contains a raw, protocol-specific framing.
Currently, `signstar-sign` can created only OpenPGP signatures but the format is extensible and more could be implemented in the future.

## `signstar-sign`

The following command takes a signing request, encoded in JSON, and produces a JSON response.
The JSON response contains a `signature` field, which is an armored OpenPGP signature.

```bash no_run
signstar-sign < ../signstar-request-signature/tests/sample-request.json | jq --raw-output .signature | rsop dearmor | rpacket dump
```
