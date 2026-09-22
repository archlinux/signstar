# NAME

**config.yaml** - Configuration file format for Signstar hosts.

# DESCRIPTION

A YAML configuration file that encodes the relevant system and HSM backend settings for a **Signstar**[1] host.

Each configuration file must be a regular file to be considered.

## Directories and precedence

The handling of configuration files is based on the **Configuration Files Specification**[2].

Both system and real users read **config.yaml** from the system directories "/usr/share/signstar/" and "/usr/local/share/signstar/", the volatile runtime directory "/run/signstar/" and the local administration directory "/etc/signstar/".
For real users, no other configuration file locations (e.g. those based on the **XDG Base Directory Specification**[3]) exist.

The order of the aforementioned directories describes the order of precedence in increasing priority.
A file from a directory with higher priority fully replaces one from a directory with lower priority (e.g. "/etc/signstar/config.yaml" replaces "/usr/share/signstar/config.yaml").

The **config.yaml** configuration file format neither supports drop-in configuration files, nor the masking of configuration files.

# FILE FORMAT

The file must contain valid YAML data and all of the following described required fields and values must be present.

## system

This top-level object describes settings relevant to the entire Signstar system.

### iteration

This non-negative number describes the version of the data in the configuration file.

The number should be incremented, if data changes in a breaking manner:

- a new administrative user is added
- a new user or key is added
- a user or key is removed
- the means of encryption for administrative or non-administrative credentials are changed

### admin\_secret\_handling

This describes the way administrative credentials are handled on the Signstar host and whether they are permanently persisted.

This must be one of the following two strings or the **shamirs-secret-sharing** object:

- **plaintext**: The administrative credentials are stored in plaintext files in Signstar's state directory.

  **NOTE**: The Signstar host does not provide integration to retrieve **plaintext** administrative credentials!
- **systemd-creds**: The administrative credentials are stored in files encrypted with **systemd-creds**(1) in Signstar's state directory.

  **NOTE**: The Signstar host does not provide integration to retrieve **systemd-creds** administrative credentials!
- **shamirs-secret-sharing**: This object describes the encryption and decryption of administrative credentials using **Shamir's Secret Sharing**[3].
  With this setup, several individuals are provided with cryptographic shares of the (encrypted) administrative credentials, which are not stored permanently on the Signstar host.
  A subset of these individual's cryptographic shares are required to decrypt the administrative credentials (see also the **share\_holder** object).
    - **number\_of\_shares**: The total number of shares used for **Shamir's Secret Sharing**[3].
    - **threshold**: The number of shares required for decrypting administrative credentials encrypted with **Shamir's Secret Sharing**[3].

**NOTE**: It is strongly recommended to expose administrative credentials only on an encrypted storage device (see **cryptsetup**(8)) on the Signstar host and to rely on encrypted files (therefore **shamirs-secret-sharing** is recommended over **systemd-creds** and **systemd-creds** is recommended over **plaintext**).
          Currently, only **plaintext** and **systemd-creds** support is available.

### non\_admin\_secret\_handling

The way non-administrative credentials are handled on the system.

This must be one of the following two strings:

- **plaintext**: The credentials are stored in plaintext files in Signstar's state directory.
- **systemd-creds**: The credentials are stored in files encrypted with **systemd-creds**(1) in Signstar's state directory.

**NOTE**: It is strongly recommended to expose non-administrative credentials only on an encrypted storage device (see **cryptsetup**(8)) and to rely on encrypted files (therefore **systemd-creds** is recommended over **plaintext**).

### mappings

A set of user mapping objects, that describe specific integration with the Signstar host, based on its system users.
The following entries are understood.

#### wireguard\_download

This object describes an _optional_ system user that is used to download WireGuard configuration files used by the Signstar host.

- **system\_user**: The unique Unix username of a user on the Signstar host.
  This user has access to the relevant WireGuard configuration.
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.

#### share\_holder

This object describes an _optional_ system user that is used to upload and download shares of the administrative credentials, encrypted using **Shamir's Secret Sharing**[3].

**NOTE**: The number of objects of this type must be the same as **number\_of\_shares**, if **shamirs-secret-sharing** is used for **admin\_secret\_handling** and otherwise always zero.

- **system\_user**: The unique Unix username of a user on the Signstar host.
  This user has access to a dedicated, user-specific location for the upload and download of shares of the administrative credentials, encrypted using **Shamirs Secret Sharing**[3].
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.

## nethsm

This top-level object describes settings relevant to **NetHSM**[4] backends.

**NOTE**: This object can only be used, if NetHSM support is compiled in!

### connections

A set of connections to a **NetHSM**[4] device.
Each connection is described by an object with URL and the TLS security chosen for it.

- **url**: The unique URL under which a NetHSM is available.

- **tls\_security**: The TLS security used for the **url**.

  This must be one of the following two strings, or the **root\_certificates** object:
    - **unsafe**: Always trust the TLS certificate associated with a host.

      **WARNING**: This does not check the host key, which allows for trivial man-in-the-middle attacks!
    - **native**: Use the native CA trust store for TLS certificate verification.
    - **root\_certificates**: A list of unique CA certificates in PEM format.
      These certificates are used to validate the host certificates of the connection.

### mappings

A set of user mapping objects, that each describe the integration of specific **NetHSM**[4] users with the Signstar host.
The following entries are understood.

#### admin

The unique username of an administrative user of the **NetHSM**[4].
Administrative users are used to

- create users
- namespaces
- create keys
- restore from backup

**NOTE**: The default administrative user is named _"admin"_ and can be reused (a random passphrase is chosen for it during provisioning of the device).

#### backup

This object describes a system user and its SSH authorized key, as well as a backend user for retrieving the backup of the **NetHSM**[4].

- **backend\_user**: The unique username of a backup user in the **NetHSM**[4].
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.
- **system\_user**: The unique Unix username of a user on the Signstar host.

#### certificate\_retrieval

This object describes a system user and its SSH authorized key, as well as a set of backend users for retrieving the certificates associated with each signing key of the **NetHSM**[4].

- **system\_wide**: The unique username of a system-wide operator user in the **NetHSM**[4].
  This operator user provides access to the certificates of system-wide keys.
- **namespaced**: A set of unique, namespaced usernames of operator users in the **NetHSM**[4].
  Each of these operator users provide access to the certificates in their respective namespace.
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.
- **system\_user**: The unique Unix username of a user on the Signstar host.

#### hermetic\_metrics

This object describes a system user, as well as backend users for retrieving metrics from the **NetHSM**[4] on the Signstar host.
This integration is useful for integration with other services, that are running on the Signstar host.

- **backend\_users**: This object contains information about a metrics user and one or more operator users of the **NetHSM**[4].
    - **metrics\_user**: The unique username of a system-wide metrics user in the **NetHSM**[4].
    - **operator\_users**: A set of unique operator usernames in the **NetHSM**[4].
- **system\_user**: The unique Unix username of a user on the Signstar host.

#### metrics

This object describes a system user and its SSH authorized key, as well as backend users for retrieving metrics of the **NetHSM**[4] from the Signstar host.

- **backend\_users**: This object contains information about a metrics user and one or more operator users of the **NetHSM**[4].
    - **metrics\_user**: The unique username of a metrics user in the **NetHSM**[4].
    - **operator\_users**: A set of unique operator usernames in the **NetHSM**[4].
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.
- **system\_user**: The unique Unix username of a user on the Signstar host.

#### signing

This object describes a system user and its SSH authorized key, as well as a backend user and a specific key for retrieving digital signatures from the **NetHSM**[4] via the Signstar host.

- **backend\_user**: The unique username of an operator user in the **NetHSM**[4].
  This operator user is assigned a **tag**, which is also assigned to the cryptographic key with the ID **signing\_key\_id** and thus is granted usage of this key.
- **signing\_key\_id**: A unique key ID in the **NetHSM**[4].

  **NOTE**: If the **backend\_user** is associated with a namespace, this key ID is only available in that particular namespace.
- **key\_setup**: This object describes the cryptographic key and what type of digital signatures can be created with it.

  **NOTE**: The combination of **key\_type**, **key\_mechanism** and **signature\_type** must be valid.
    - **key\_type**: The type of the cryptographic key.

      This must be one of the following strings:
        - **Curve25519**: for a Montgomery curve key over a prime field for the prime number 2^255-19
        - **EcBp256**: for an elliptic (Brainpool) curve key over a prime field for a prime of size 256 bit
        - **EcBp384**: for an elliptic (Brainpool) curve key over a prime field for a prime of size 384 bit
        - **EcBp512**: for an elliptic (Brainpool) curve key over a prime field for a prime of size 512 bit
        - **EcK256**: for an elliptic (Koblitz) curve key over a prime field for a prime of size 256 bit
        - **EcP224**: for an elliptic-curve key over a prime field for a prime of size 224 bit
        - **EcP256**: for an elliptic-curve key over a prime field for a prime of size 256 bit
        - **EcP384**: for an elliptic-curve key over a prime field for a prime of size 384 bit
        - **EcP521**: for an elliptic-curve key over a prime field for a prime of size 521 bit
        - **Generic**: for a generic key used for block ciphers
        - **Rsa**: for an RSA key
    - **key\_mechanisms**: The list of mechanisms supported by the cryptographic key.

      This must be one or more of the following strings:
        - **AesDecryptionCbc**: Decryption using the Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC)
        - **AesEncryptionCbc**: Encryption using the Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC)
        - **EcdsaSignature**: Signing following the Elliptic Curve Digital Signature Algorithm (ECDSA)
        - **EdDsaSignature**: Signing following the Edwards-curve Digital Signature Algorithm (EdDSA)
        - **RsaDecryptionOaepMd5**: RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using an MD-5 hash
        - **RsaDecryptionOaepSha1**: RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-1 hash
        - **RsaDecryptionOaepSha224**: RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-224 hash
        - **RsaDecryptionOaepSha256**: RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-256 hash
        - **RsaDecryptionOaepSha384**: RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-384 hash
        - **RsaDecryptionOaepSha512**: RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-512 hash
        - **RsaDecryptionPkcs1**: RSA decryption following the PKCS#1 standard
        - **RsaDecryptionRaw**: Raw RSA decryption
        - **RsaSignaturePkcs1**: RSA signing following the PKCS#1 standard
        - **RsaSignaturePssSha1**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-1 hash
        - **RsaSignaturePssSha224**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-224 hash
        - **RsaSignaturePssSha256**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-256 hash
        - **RsaSignaturePssSha384**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-384 hash
        - **RsaSignaturePssSha512**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-512 hash
    - **signature\_type**: The signature type supported by the cryptographic key.

      This must be one of the following strings:
        - **EcdsaK256**: Elliptic Curve Digital Signature Algorithm (ECDSA) signing using a (Koblitz) key over a prime field for a prime of size 256 bit
        - **EcdsaP224**: Elliptic Curve Digital Signature Algorithm (ECDSA) signing using a key over a prime field for a prime of size 224 bit
        - **EcdsaP256**: Elliptic Curve Digital Signature Algorithm (ECDSA) signing using a key over a prime field for a prime of size 256 bit,
        - **EcdsaP384**: Elliptic Curve Digital Signature Algorithm (ECDSA) signing using a key over a prime field for a prime of size 384 bit
        - **EcdsaP521**: Elliptic Curve Digital Signature Algorithm (ECDSA) signing using a key over a prime field for a prime of size 521 bit
        - **EdDsa**: Signing following the Edwards-curve Digital Signature Algorithm (EdDSA)
        - **Pkcs1**: RSA signing following the PKCS#1 standard
        - **PssSha1**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-1 hash
        - **PssSha224**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-224 hash
        - **PssSha256**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-256 hash
        - **PssSha384**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-384 hash
        - **PssSha512**: RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-512 hash
    - **key\_context**: This object or string describes the context in which the cryptographic key is used.

      This must be one of the following two options:
        - **raw**: If this string is used, the cryptographic key is used for raw cryptographic key operations.
        - **openpgp**: If this object is used, an **OpenPGP certificate**[5] is created using the cryptographic key and and then associated with it.
          This certificate is then stored in the NetHSM.
          This object describes properties of the **OpenPGP certificate**[5], as well as any **OpenPGP signature**[5] issued using the cryptographic key.
            - **notations**: This _optional_ hashmap consists of entries that each describe the key and value of an **OpenPGP notation**[6], that will be included in the signatures issued by this key.
            - **user\_ids**: A list of unique strings, each describing a valid **OpenPGP User ID**[7].
            - **version**: The version of OpenPGP used for the certificate and each digital signature issued using the cryptographic key.
              This must be one of the following strings:
                - **4**: for **RFC 4880**[8]
                - **6**: for **RFC 9580**[9]

              **NOTE**: Currently only **4** is supported!
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.
- **system\_user**: The unique Unix username of a user on the Signstar host.
- **tag**: A unique tag assigned to both **backend\_user** and **signing\_key\_id**.
  Tags are used as restrictions for users and keys.
  Only users with the same tag as a key can use that particular key.

## yubihsm2

This top-level object describes settings relevant to **YubiHSM2**[10] backends.

**NOTE**: This object can only be used, if YubiHSM2 support is compiled in!

### connections

A set of connections to a **YubiHSM2**[10].

This must be one or more of the following strings or objects:

- **usb**: This object describes a **YubiHSM2**[10] device connected over USB.
    - **serial_number**: A ten character long, number-only string, that encodes the unique serial number of a **YubiHSM2**[10] device.
- **mock**: This string enables the use of an emulated, in-memory HSM for testing purposes.

  **WARNING**: This option should only be used for testing purposes as it only provides transient data (per request) and it is only available, if YubiHSM2 mockhsm support is compiled in.

### mappings

A set of user mapping objects, that describe the integration of specific **YubiHSM2**[10] authentication keys with the Signstar host.
The following entries are understood.

#### admin

This object describes an administrative user of the **YubiHSM2**[10].

- **authentication\_key\_id**: The unique authentication key ID of the user.

  This must be a number larger than _0_ and smaller than _65535_.

  **NOTE**: The default authentication key ID of an unprovisioned device is _1_ and can be reused (a random passphrase is chosen for it during provisioning of the device).

Administrative users are used to

- create users
- create keys
- restore from backup

#### audit\_log

This object describes a system user and its SSH authorized key, as well as a backend user for retrieving the audit log of the **YubiHSM2**[10] via the Signstar host.

- **authentication\_key\_id**: The unique authentication key ID of the user.

  This must be a number larger than _0_ and smaller than _65535_.
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.
- **system\_user**: The unique Unix username of a user on the Signstar host.

#### backup

This object describes a system user and its SSH authorized key, as well as a backend user for retrieving the backup of the **YubiHSM2**[10].

- **authentication\_key\_id**: The unique authentication key ID of the user.

  This must be a number larger than _0_ and smaller than _65535_.
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.
- **system\_user**: The unique Unix username of a user on the Signstar host.

#### certificate\_retrieval

This object describes a system user and its SSH authorized key, as well as a backend user for retrieving the certificates associated with each signing key of the **YubiHSM2**[4].

- **authentication\_key\_id**: The unique authentication key ID of the user.

  This must be a number larger than _0_ and smaller than _65535_.
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.
- **system\_user**: The unique Unix username of a user on the Signstar host.

#### hermetic\_audit\_log

This object describes a system user, as well as a backend user for retrieving the audit log of the **YubiHSM2**[10] on the Signstar host.
This integration is useful for integration with other services, that are running on the Signstar host.

- **authentication\_key\_id**: The unique authentication key ID of the user.

  This must be a number larger than _0_ and smaller than _65535_.
- **system\_user**: The unique Unix username of a user on the Signstar host.

#### signing

This object describes a system user and its SSH authorized key, as well as a backend user and a specific key for retrieving digital signatures from the **YubiHSM2**[10] via the Signstar host.

- **authentication\_key\_id**: The unique authentication key ID of the user.

  This must be a number larger than _0_ and smaller than _65535_.
- **domain**: The unique domain, that the **authentication\_key\_id** and **signing_key_id** are part of.
  Domains partition the access capabilities of individual authentication keys to signing keys on the device.

  This must be a number between _1_ and _16_.
- **key\_setup**: This object describes the cryptographic key and what type of digital signatures can be created with it.

  **NOTE**: The combination of **key\_type**, **key\_mechanism** and **signature\_type** must be valid.
    - **key\_type**: The type of the cryptographic key.

      This must be one of the following strings:
        - **Curve25519**: for a Montgomery curve key over a prime field for the prime number 2^255-19
    - **key\_mechanisms**: The list of mechanisms supported by the cryptographic key.

      This must be one or more of the following strings:
        - **EdDsaSignature**: Signing following the Edwards-curve Digital Signature Algorithm (EdDSA)
    - **signature\_type**: The signature type supported by the cryptographic key.

      This must be one of the following strings:
        - **EdDsa**: Signing following the Edwards-curve Digital Signature Algorithm (EdDSA)
    - **key\_context**: This object or string describes the context in which the cryptographic key is used.

      This must be one of the following two options:
        - **raw**: If this string is used, the cryptographic key is used for raw cryptographic key operations.
        - **openpgp**: If this object is used, an **OpenPGP certificate**[5] is created using the cryptographic key and and then associated with it.
          This certificate is then stored in the NetHSM.

          The **openpgp** object describes properties of the **OpenPGP certificate**[5], as well as any **OpenPGP signature**[5] issued using the cryptographic key.
            - **notations**: This _optional_ hashmap consists of entries that each describe the key and value of an **OpenPGP notation**[6].
            - **user\_ids**: A list of unique strings, each describing a valid **OpenPGP User ID**[7].
            - **version**: The version of OpenPGP used for the certificate and each digital signature issued using the cryptographic key.
              This must be one of the following strings:
                - **4**: for **RFC 4880**[8]
                - **6**: for **RFC 9580**[9]

              **NOTE**: Currently only **4** is supported!
- **signing\_key\_id**: A unique key ID in the **YubiHSM2**[10].
- **ssh\_authorized\_key**: The unique SSH public key of the **system\_user**.
- **system\_user**: The unique Unix username of a user on the Signstar host.

# EXAMPLES

## All backends with plaintext secret handling

```yaml
system:
  iteration: 1
  admin_secret_handling: plaintext
  non_admin_secret_handling: plaintext
  mappings:
    - wireguard_download:
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host
        system_user: signstar-wireguard-download
nethsm:
  connections:
    - url: https://localhost:8080/
      tls_security: Unsafe
    - url: https://localhost:8081/
      tls_security: Unsafe
  mappings:
    - admin: admin
    - admin: ns1~admin
    - backup:
        backend_user: backup
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrIYA+bfMBThUP5lKbMFEHiytmcCPhpkGrB/85n0mAN user@host
        system_user: nethsm-backup
    - certificate_retrieval:
        system_wide: certificateretrieval
        namespaced:
          - ns1~certificateretrieval
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDvhXirK3o+KPoMqhLlpfPe1UQOqznnAaTOeNtmZraUv user@host
        system_user: nethsm-certificate-retrieval
    - hermetic_metrics:
        backend_users:
          metrics_user: hermeticmetrics
          operator_users:
            - hermetickeymetrics
        system_user: nethsm-hermetic-metrics
    - metrics:
        backend_users:
          metrics_user: metrics
          operator_users:
            - keymetrics
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host
        system_user: nethsm-metrics
    - signing:
        backend_user: signing
        signing_key_id: signing1
        key_setup:
          key_type: Curve25519
          key_mechanisms:
            - EdDsaSignature
          signature_type: EdDsa
          key_context:
            openpgp:
              notations:
                test: value
              user_ids:
                - Foobar McFooface <foobar@mcfooface.org>
              version: "4"
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host
        system_user: nethsm-signing
        tag: signing1
    - signing:
        backend_user: ns1~signing
        signing_key_id: signing1
        key_setup:
          key_type: Curve25519
          key_mechanisms:
            - EdDsaSignature
          signature_type: EdDsa
          key_context:
            openpgp:
              notations:
                test: value
              user_ids:
                - Barfoo McBarface <barfoo@mcbarface.org>
              version: "4"
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJr4wdlEv3ZKkDufEQTZSLOjDLO3DeNN2pqKmp00ufIu user@host
        system_user: nethsm-ns1-signing
        tag: signing1
yubihsm2:
  connections:
    - usb:
        serial_number: 12345678
    - usb:
        serial_number: 87654321
  mappings:
    - admin:
        authentication_key_id: 1
    - audit_log:
        authentication_key_id: 2
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host
        system_user: yubihsm2-audit-log
    - backup:
        authentication_key_id: 3
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host
        system_user: yubihsm2-backup
    - certificate_retrieval:
        authentication_key_id: 4
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDfCJD+futTp8vlKxx2Rd1hqY+vnMp9iXSRTeCLhcGmr user@host
        system_user: yubihsm2-certificate-retrieval
    - hermetic_audit_log:
        authentication_key_id: 5
        system_user: yubihsm2-hermetic-audit-log
    - signing:
        authentication_key_id: 6
        key_setup:
          key_type: Curve25519
          key_mechanisms:
            - EdDsaSignature
          signature_type: EdDsa
          key_context:
            openpgp:
              notations:
                test: value
              user_ids:
                - Foobar McFooface <foobar@mcfooface.org>
              version: "4"
        domain: 1
        signing_key_id: 1
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host
        system_user: yubihsm2-signing
```

## Shamirs Secret Sharing and systemd creds

```yaml
system:
  iteration: 1
  admin_secret_handling:
    shamirs-secret-sharing:
      number_of_shares: 3
      threshold: 2
  non_admin_secret_handling: systemd-creds
  mappings:
    - share_holder:
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host
        system_user: signstar-share-holder1
    - share_holder:
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host
        system_user: signstar-share-holder2
    - share_holder:
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host
        system_user: signstar-share-holder3
    - wireguard_download:
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host
        system_user: signstar-wireguard-download
nethsm:
  connections:
    - url: https://localhost:8080/
      tls_security: Unsafe
    - url: https://localhost:8081/
      tls_security: Unsafe
  mappings:
    - admin: admin
    - admin: ns1~admin
    - backup:
        backend_user: backup
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrIYA+bfMBThUP5lKbMFEHiytmcCPhpkGrB/85n0mAN user@host
        system_user: nethsm-backup
    - certificate_retrieval:
        system_wide: certificateretrieval
        namespaced:
          - ns1~certificateretrieval
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDvhXirK3o+KPoMqhLlpfPe1UQOqznnAaTOeNtmZraUv user@host
        system_user: nethsm-certificate-retrieval
    - hermetic_metrics:
        backend_users:
          metrics_user: hermeticmetrics
          operator_users:
            - hermetickeymetrics
        system_user: nethsm-hermetic-metrics
    - metrics:
        backend_users:
          metrics_user: metrics
          operator_users:
            - keymetrics
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host
        system_user: nethsm-metrics
    - signing:
        backend_user: signing
        signing_key_id: signing1
        key_setup:
          key_type: Curve25519
          key_mechanisms:
            - EdDsaSignature
          signature_type: EdDsa
          key_context:
            openpgp:
              user_ids:
                - Foobar McFooface <foobar@mcfooface.org>
              version: "4"
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host
        system_user: nethsm-signing
        tag: signing1
    - signing:
        backend_user: ns1~signing
        signing_key_id: signing1
        key_setup:
          key_type: Curve25519
          key_mechanisms:
            - EdDsaSignature
          signature_type: EdDsa
          key_context:
            openpgp:
              user_ids:
                - Barfoo McBarface <barfoo@mcbarface.org>
              version: "4"
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJr4wdlEv3ZKkDufEQTZSLOjDLO3DeNN2pqKmp00ufIu user@host
        system_user: nethsm-ns1-signing
        tag: signing1
yubihsm2:
  connections:
    - usb:
        serial_number: 12345678
    - usb:
        serial_number: 87654321
  mappings:
    - admin:
        authentication_key_id: 1
    - audit_log:
        authentication_key_id: 2
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host
        system_user: yubihsm2-audit-log
    - backup:
        authentication_key_id: 3
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host
        system_user: yubihsm2-backup
    - certificate_retrieval:
        authentication_key_id: 4
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDfCJD+futTp8vlKxx2Rd1hqY+vnMp9iXSRTeCLhcGmr user@host
        system_user: yubihsm2-certificate-retrieval
    - hermetic_audit_log:
        authentication_key_id: 5
        system_user: yubihsm2-hermetic-audit-log
    - signing:
        authentication_key_id: 6
        key_setup:
          key_type: Curve25519
          key_mechanisms:
            - EdDsaSignature
          signature_type: EdDsa
          key_context:
            openpgp:
              user_ids:
                - Foobar McFooface <foobar@mcfooface.org>
              version: "4"
        domain: 1
        signing_key_id: 1
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host
        system_user: yubihsm2-signing
```

## Systemd credentials

```yaml
system:
  iteration: 1
  admin_secret_handling: plaintext
  non_admin_secret_handling: systemd-creds
  mappings:
    - wireguard_download:
        system_user: wireguard-downloader
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host
nethsm:
  connections:
    - url: https://localhost:8080/
      tls_security: Unsafe
    - url: https://localhost:8081/
      tls_security: Unsafe
  mappings:
    - admin: admin
    - admin: ns1~admin
    - backup:
        backend_user: backup
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrIYA+bfMBThUP5lKbMFEHiytmcCPhpkGrB/85n0mAN user@host
        system_user: nethsm-backup
    - certificate_retrieval:
        system_wide: certificateretrieval
        namespaced:
          - ns1~certificateretrieval
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDvhXirK3o+KPoMqhLlpfPe1UQOqznnAaTOeNtmZraUv user@host
        system_user: nethsm-certificate-retrieval
    - hermetic_metrics:
        backend_users:
          metrics_user: hermeticmetrics
          operator_users:
            - hermetickeymetrics
        system_user: nethsm-hermetic-audit-log
    - metrics:
        backend_users:
          metrics_user: metrics
          operator_users:
            - keymetrics
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host
        system_user: nethsm-metrics
    - signing:
        backend_user: signing
        signing_key_id: signing1
        key_setup:
          key_type: Curve25519
          key_mechanisms:
            - EdDsaSignature
          signature_type: EdDsa
          key_context:
            openpgp:
              user_ids:
                - Foobar McFooface <foobar@mcfooface.org>
              version: "4"
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host
        system_user: nethsm-signing
        tag: signing1
    - signing:
        backend_user: ns1~signing
        signing_key_id: signing1
        key_setup:
          key_type: Curve25519
          key_mechanisms:
            - EdDsaSignature
          signature_type: EdDsa
          key_context:
            openpgp:
              user_ids:
                - Barfoo McBarface <barfoo@mcbarface.org>
              version: "4"
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJr4wdlEv3ZKkDufEQTZSLOjDLO3DeNN2pqKmp00ufIu user@host
        system_user: nethsm-ns1-signing
        tag: signing1
yubihsm2:
  connections:
    - usb:
        serial_number: 12345678
    - usb:
        serial_number: 87654321
  mappings:
    - admin:
        authentication_key_id: 1
    - audit_log:
        authentication_key_id: 2
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host
        system_user: yubihsm2-audit-log
    - backup:
        authentication_key_id: 3
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host
        system_user: yubihsm2-backup
    - certificate_retrieval:
        authentication_key_id: 4
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDfCJD+futTp8vlKxx2Rd1hqY+vnMp9iXSRTeCLhcGmr user@host
        system_user: yubihsm2-certificate-retrieval
    - hermetic_audit_log:
        authentication_key_id: 5
        system_user: yubihsm2-hermetic-audit-log
    - signing:
        authentication_key_id: 6
        key_setup:
          key_type: Curve25519
          key_mechanisms:
            - EdDsaSignature
          signature_type: EdDsa
          key_context:
            openpgp:
              user_ids:
                - Foobar McFooface <foobar@mcfooface.org>
              version: "4"
        domain: 1
        signing_key_id: 1
        ssh_authorized_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host
        system_user: yubihsm2-signing
```

# SEE ALSO

**nethsm**(1), **signstar-sign**(1), **signstar-configure**(1), **signstar-configure-build**(1), **systemd-creds**(1), **cryptsetup**(8)

# NOTES

1. **Signstar**

   <https://signstar.archlinux.page/>
1. **Configuration Files Specification**

   <https://uapi-group.org/specifications/specs/configuration_files_specification/>
1. **XDG Base Directory Specification**

   <https://specifications.freedesktop.org/basedir/latest/>
1. **Shamir's Secret Sharing**

   <https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing>
1. **NetHSM**

   <https://docs.nitrokey.com/nethsm/>
1. **OpenPGP certificate**

   <https://openpgp.dev/book/certificates.html>
1. **OpenPGP signature**

   <https://openpgp.dev/book/signatures.html>
1. **OpenPGP notation**

   <https://openpgp.dev/book/adv/signatures.html#notation-signature-subpackets>
1. **OpenPGP User ID**

   <https://openpgp.dev/book/certificates.html#user-ids>
1. **RFC 4880**

   <https://www.rfc-editor.org/info/rfc4880/>
1. **RFC 9580**

   <https://www.rfc-editor.org/info/rfc9580/>
1. **YubiHSM2**

   <https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/>
