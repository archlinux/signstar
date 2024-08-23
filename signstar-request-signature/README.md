# Signstar Create Signing Request

This crate offers a library and an executable for creating, reading and writing of signing requests for files.

## Glossary

*Client* - the application (here: `signstar-request-signature`) which computes a file digest and creates a *signing request*,

*Server* - the application (currently: `nethsm-cli`) which receives a *signing request*, processes it and returns a *signature*,

*Signing request* - machine and human-readable description of the data that will be signed.
The exact format for the signing request is described below.

*Signature* - raw cryptographic signature in a technology-specific framing (e.g. in "packets" for [OpenPGP][9580]).

## Format specification

The *signing request* is a custom JSON encoded data format.
It is used to represent required information on data input (the hasher state type and the hasher state) and output (the requested signature type).
Additionally, arbitrary optional data can be provided.

The below sample *signing request* is fully expanded for illustrative purposes:

```json
{
    "version": "1.0.0",
    "required": {
        "input": {
            "type": "sha2-0.11-SHA512-state",
            "content": [8,201,188,243,103,230,9,106,59,167,202,132,133,174,103,187,43,248,148,254,114,243,110,60,241,54,29,95,58,245,79,165,209,130,230,173,127,82,14,81,31,108,62,43,140,104,5,155,107,189,65,251,171,217,131,31,121,33,126,19,25,205,224,91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,20,73,32,108,105,107,101,32,115,116,114,97,119,98,101,114,114,105,101,115,10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        },
        "output": {
            "type": "OpenPGPv4"
        }
    },
    "optional": {
        "request-time": 1728913277,
        "XHy1dHj": "https://gitlab.archlinux.org/archlinux/signstar/-/merge_requests/43"
    }
}
```

The fields are as follows:

- `version` - [Semantic Versioning][SV]-compatible version string. Incompatible changes to the format will result in a major version bump.

- `required` - a dictionary of fields that the client considers critical enough that the signing server should reject a signing request if any of these fields are not understood.
  This serves the same purpose as the ["critical bit" in OpenPGP][CB] and [X.509][X509].

[SV]: https://semver.org/
[9580]: https://www.rfc-editor.org/rfc/rfc9580
[CB]: https://www.rfc-editor.org/rfc/rfc9580#name-packet-criticality
[X509]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2

- `optional` - a dictionary of fields that are optional for the server to understand.
  Their presence may cause the signing server to act differently.
  If any field in this category is not understood by the server it must ignore it.

### Required category

This specification defines two fields in the Required category:

- `input` - the input to the signing process. It is an object with two fields:
  - `type` - type of the input content. Only one value is defined: `sha2-0.11-SHA512-state` which represents a hasher state, as expected by the [`sha2` crate][SHA2]. The format is [stable across minor versions][SHAST]. Note that due to [internal OpenPGP hashing mechanics][OM] this is *not* a digest of the data being signed (e.g. the package).
  - `content` - the actual bytes of the input content.

- `output` - the output of the signing process as expected by the client. This is an object with the following fields:
  - `type` - the type of the signature expected by the client. Only one value is permitted: `OpenPGPv4` for [OpenPGP v4 signatures][SD].

[SHA2]: https://crates.io/crates/sha2
[SHAST]: https://github.com/RustCrypto/traits/pull/1694/files
[OM]: https://mailarchive.ietf.org/arch/msg/openpgp/E5sRkcH0rg6NECNasz7gr18uyI4/
[SD]: https://openpgp.dev/book/signing_data.html

### Optional category

There are no defined fields in this category.

More technical explanation about the current design is in the `doc/design.md` document.
