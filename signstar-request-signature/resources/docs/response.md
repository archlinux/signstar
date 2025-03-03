# Signing Response specification

A signing response format for Signstar systems.

## Glossary

- *Client*: The application (here: [`signstar-request-signature`]) which computes a file digest and creates a *signing request*,
- *Server*: The application (currently: [`nethsm-cli`]) which receives a *signing request*, processes it and returns a *signature*,
- *Signing response*: Machine and human-readable description of the data signature.
  The exact format for the signing response is described below.
- *Signature*: Raw cryptographic signature in a technology-specific framing (e.g. in "packets" for [OpenPGP][9580]).

## Format specification

The *signing response* is a custom JSON encoded data format.

The below sample *signing response* is fully expanded for illustrative purposes:

```json
{
    "version": "1.0.0",
    "signature": "-----BEGIN PGP SIGNATURE-----\n\nwnUEABYKAB0WIQRfsO5nGa+i+6sgdPRTD9XY/kzu2QUCZ8WtVgAKCRBTD9XY/kzu\n2XCMAQCjsYYJ00u9wUE0O1CO8OOEi/4sXq1cDol6jhYep4awgwD8DtXJ/nCnSmRE\npSgPblgptDYtLdzJvvxd7G9kCSNS4AM=\n=XHyn\n-----END PGP SIGNATURE-----"
}
```

The fields are as follows:

- `version` - [Semantic Versioning][SV]-compatible version string. Incompatible changes to the format will result in a major version bump.

- `signature` - raw signature represented as a string. The [signature][SD] must be [ASCII-armored][ARMOR].

### Specification evolution

The specification can be extended by adding new fields or allowed values in minor version changes.
If fields are removed, this constitutes a major version change to the specification.
Old values are supported indefinitely (with the exception of security related changes).
This allows older clients to keep using the same API and only upgrade when they want to take advantage of additional features.

If the server sends a response that is not spec-compliant (e.g. a version field has not been provided) the client MUST reject the response.

Deprecation of values is handled in the same way: the old value is supported and the accepting party (i.e. the server) must transparently translate old, deprecated values to the new format.

Each change in the protocol must be documented in this specification.

Refer to the [design document] for an in-depth discussion of the technical details.

[9580]: https://www.rfc-editor.org/rfc/rfc9580
[ARMOR]: https://openpgp.dev/book/armor.html
[design document]: https://signstar.archlinux.page/signstar-request-signature/design.html
[`nethsm-cli`]: https://signstar.archlinux.page/nethsm-cli/index.html
[SD]: https://openpgp.dev/book/signing_data.html
[`signstar-request-signature`]: https://signstar.archlinux.page/signstar-request-signature/index.html
[SV]: https://semver.org/
