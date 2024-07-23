# Evaluated setups

This document contains evaluated, but not considered setup concepts for signstar.

## Scenarios

In the below subsection all evaluated scenarios are listed.
The following list provides a more high-level overview of the evaluated features.

| Feature                                             | [A](#nethsm-directly) | [B](#signing-service-signing-hashes) | [C](#signing-service-signing-files-or-hashes) | [D](#signing-service-signing-files) | [E](#signing-service-signing-hashes-and-files-as-proxy) | [F](#signing-service-signing-files-as-proxy) |
|-----------------------------------------------------|-----------------------|--------------------------------------|-----------------------------------------------|-------------------------------------|---------------------------------------------------------|----------------------------------------------|
| attestation log                                     | ❌️                    | ✅️                                   | ✅️                                            | ❌️                                  | ✅️                                                      | ✅️                                           |
| central signing                                     | ❌️                    | ✅️                                   | ✅️                                            | ✅️                                  | ✅️                                                      | ✅️                                           |
| low complexity                                      | ✅️                    | ✅️                                   | ✅️                                            | ✅️                                  | ❌️                                                      | ❌️                                           |
| client crypto backend unaware [1]                   | ❌️                    | ✅️                                   | ✅️                                            | ✅️                                  | ✅️                                                      | ✅️                                           |
| no direct client access to hardware appliance       | ❌️                    | ✅️                                   | ✅️                                            | ✅️                                  | ✅️                                                      | ✅️                                           |
| no direct build server access to repo server        | ❌️                    | ❌️                                   | ✅️                                            | ❌️                                  | ✅️                                                      | ✅️                                           |
| no direct signing service access to repo server     | ✅️                    | ✅️                                   | ✅️                                            | ✅️                                  | ❌️                                                      | ❌️                                           |
| no transmission of files from build server          | ✅️                    | ✅️                                   | ✔️                                             | ❌️                                  | ✔️                                                       | ❌️                                           |
| no custom wire format                               | ✅️                    | ❌️                                   | ❌️                                            | ❌️                                  | ❌️                                                      | ❌️                                           |
| no workflow complexity offloaded to signing service | ✅️                    | ✅️                                   | ✅️                                            | ✅️                                  | ❌️                                                      | ❌️                                           |

[1]: https://openpgp.dev/book/signatures.html#creating-an-openpgp-signature-packet

### HSM directly

The clients directly interact with the hardware appliance (there is no signing service).

```mermaid
---
title: HSM directly
---
sequenceDiagram
    participant B as build server
    participant N as NetHSM
    participant R as repo server
    participant L as logging server
    participant M as metrics server

    Note over B: 1 NetHSM operator credential,<br/>1 certificate ID,<br/>1 repo server credential
    Note over B: PKCS11 based tooling for signing
    Note over R: 1 NetHSM operator credential,<br/>1 certificate ID
    Note over R: PKCS11 based tooling for signing

    loop package build
        B ->> B: get sources,<br/>build package(s),<br/>get signature,<br/>send to repo server
    end
    B-->>N: authenticate,<br/>transmit checksum and cert ID
    N->>B: raw cryptographic signature
    loop repository update
        R ->> R: receive package(s),<br/>generate sync databases,<br/>get signature,<br/>update repository
    end
    B ->> R: package(s) and OpenPGP signature(s)
    R -->> N: authenticate,<br/>transmit checksum and cert ID
    N ->> R: raw cryptographic signature

    loop metrics collection
        N --> M: read
        B --> M: read
        R --> M: read
    end
    loop log aggregation
        N -->> L: send via syslog
    end
```

### Signing service signing hashes

In this setup a microservice takes care of taking authenticated client requests and issuing signatures for the request via a PKCS#11 backend.

```mermaid
---
title: Signing service signing hashes
---
sequenceDiagram
    participant B as build server
    participant S as signing server
    participant N as NetHSM
    participant R as repo server
    participant L as logging server
    participant M as metrics server

    Note over B: 1 signing server credential,<br/>1 repo server credential
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings
    Note over S: PKCS11 based tooling for signing
    Note over R: 1 signing server credential

    loop package build
        B ->> B: get sources,<br/>build package(s),<br/>create OpenPGP hash,<br/>get signature,<br/>send to repo server
    end
    B -->> S: authenticate,<br/>transmit hash and file metadata
    S -->> N: authenticate for client,<br/>transmit hash and cert ID
    N ->> S: raw cryptographic signature
    S ->> B: OpenPGP signature
    loop repository update
        R ->> R: receive package(s),<br/>generate sync databases,<br/>create OpenPGP hash,<br/>get signature,<br/>update repository
    end
    B ->> R: package(s) and OpenPGP signature(s)
    R -->> S: authenticate,<br/>transmit hash
    S -->> N: authenticate for client,<br/>transmit hash and cert ID
    N ->> S: raw cryptographic signature
    S ->> R: OpenPGP signature

    loop metrics collection
        B --> M: read
        S --> M: read
        N --> M: read
        R --> M: read
    end
    loop log aggregation
        N -->> L: send via syslog
    end
```

The signing process in more detail may look as follows:

```mermaid
---
title: Signing process in "Signing service signing hashes" scenario
---
sequenceDiagram
    participant C as n clients
    participant S as signing server
    participant N as NetHSM

    Note over C: one signing server credential each,<br/>if build server: one repo server credential each
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings

    critical authentication
        C ->> C: create OpenPGP hash
        C -->>+ S: authenticate,<br/>transmit hash and file metadata
        S ->> S: log user access and request
    option login failure
        S -x C: failure
        S ->> S: log user login failure
    option login successful
        S ->> S: log user login success
        critical user mapping
            S ->> S: map client user to NetHSM user and certificate ID
            option mapping not found
                S ->> S: log user mapping failure
                S -x C: failure
            option mapping found
                S ->> S: log user mapping success
        end
    end
    critical data preparation
        S ->> S: check request
    option request is file
        S ->> S: create checksum for file
    end
    critical signing
        S -->>+ N: authenticate for client,<br/>transmit checksum and cert ID
    option authentication fails/ signature not created
        S ->> S: log signature failure
        S -x C: failure
        S ->> S: log signature return failure
    option authentication succeeds/ signature created
        N ->>- S: raw cryptographic signature
        S ->> S: log signature success
        S ->>- C: OpenPGP signature
        S ->> S: log signature return success
    end
```

Here, the `n clients` may be build servers or the repository server, as they are functionally equal in behavior.

### Signing service signing files or hashes

In this setup a microservice takes care of taking authenticated client requests and issuing signatures for the request via a PKCS#11 backend.
Clients may send checksums or entire files using a custom wire format.

On a build server the signed packages are exposed via a static webserver location.

```mermaid
---
title: Signing service signing files or hashes
---
sequenceDiagram
    participant B as build server
    participant S as signing server
    participant N as NetHSM
    participant R as repo server
    participant L as logging server
    participant M as metrics server

    Note over B: 1 signing server credential
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings
    Note over S: PKCS11 based tooling for signing
    Note over R: 1 signing server credential

    critical
        B ->> B: get sources,<br/>build package(s)
        loop get signature for each package
            critical
            option
                B ->> B: create checksum,<br/>gather metadata
                B ->> S: authenticate,<br/>send digest and metadata
            option
                B ->> B: gather metadata
                B ->> S: authenticate,<br/>send file and metadata
                S ->> S: create checksum for file
            end
            S ->> S: combine checksum and metadata to OpenPGP digest
            S ->> N: authenticate for client,<br/>transmit OpenPGP digest and cert ID
            N -->> S: raw cryptographic signature
            S ->> S: create OpenPGP signature
            S -->> B: receive OpenPGP signature
            B ->> B: move package file and OpenPGP signature<br/>to publicly accessible storage
        end
    end

    critical repository update
        R ->> R: order to add package(s) from build server to repo
        B ->> R: download package(s) and OpenPGP signature(s) to pool
        R ->> R: generate temporary sync databases
        loop get signature for each sync database
            critical
            option
                R ->> R: create checksum,<br/>gather metadata
                R ->> S: authenticate,<br/>send digest and metadata
            option
                R ->> R: gather metadata
                R ->> S: authenticate,<br/>send file and metadata
                S ->> S: create checksum for file
            end
            S ->> S: combine checksum and metadata to OpenPGP digest
            S ->> N: authenticate for client,<br/>transmit OpenPGP digest and cert ID
            N -->> S: raw cryptographic signature
            S ->> S: create OpenPGP signature
            S -->> R: receive OpenPGP signature
        end
        R ->> R: update repository
    end

    loop metrics collection
        B --> M: read
        S --> M: read
        N --> M: read
        R --> M: read
    end
    loop log aggregation
        N -->> L: send via syslog
    end
```

The signing process in more detail may look as follows:

```mermaid
---
title: Signing process in "Signing service signing files or hashes" scenario
---
sequenceDiagram
    participant C as n clients
    participant S as signing server
    participant A as attestation log
    participant N as NetHSM

    Note over C: one signing server credential each
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings

    critical authentication
        critical
        option
            C ->> C: create checksum, gather metadata
            C ->>+ S: authenticate,<br/>transmit hash and metadata
        option
            C ->> C: gather metadata
            C ->>+ S: authenticate,<br/>transmit file and metadata
        end
            S ->> A: log user access and request
    option login failure
        S -x C: failure
        S ->> A: log user login failure
    option login successful
        S ->> A: log user login success
        critical user mapping
            S ->> S: map client user to NetHSM user and certificate ID
            option mapping not found
                S ->> A: log user mapping failure
                S -x C: failure
            option mapping found
                S ->> A: log user mapping success
        end
    end
    critical data preparation
        S ->> S: check request
    option request is file
        S ->> S: create checksum for file
    end
    critical signing
        S ->>+ N: authenticate for client,<br/>transmit checksum and cert ID
    option authentication fails/ signature not created
        S ->> A: log signature failure
        S -x C: failure
        S ->> A: log signature return failure
    option authentication succeeds/ signature created
        N -->>- S: receive raw cryptographic signature
        S ->> A: log signature success
        S ->> S: create OpenPGP signature
        S -->>- C: receive OpenPGP signature
    end
```

Here, the `n clients` may be build servers or the repository server, as they are functionally equal in behavior.

### Signing service signing files

In this setup a microservice takes care of taking authenticated client requests and issuing signatures for the request via a PKCS#11 backend.
The client sends entire files to the service.

```mermaid
---
title: Signing service signing files
---
sequenceDiagram
    participant B as build server
    participant S as signing server
    participant N as NetHSM
    participant R as repo server
    participant L as logging server
    participant M as metrics server

    Note over B: 1 signing server credential,<br/>1 repo server credential
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings
    Note over S: PKCS11 based tooling for signing
    Note over R: 1 signing server credential

    loop package build
        B ->> B: get sources,<br/>build package(s),<br/>get signature,<br/>send to repo server
    end
    B -->> S: authenticate,<br/>transmit file
    S -->> N: authenticate for client,<br/>transmit checksum and cert ID
    N ->> S: raw cryptographic signature
    S ->> B: OpenPGP signature
    loop repository update
        R ->> R: receive package(s),<br/>generate sync databases,<br/>get signature,<br/>update repository
    end
    B ->> R: package(s) and OpenPGP signature(s)
    R -->> S: authenticate,<br/>transmit file
    S -->> N: authenticate for client,<br/>transmit checksum and cert ID
    N ->> S: raw cryptographic signature
    S ->> R: OpenPGP signature

    loop metrics collection
        B --> M: read
        S --> M: read
        N --> M: read
        R --> M: read
    end
    loop log aggregation
        N -->> L: send via syslog
    end
```

The signing process in more detail may look as follows:

```mermaid
---
title: Signing process in "Signing service signing files" scenario
---
sequenceDiagram
    participant C as n clients
    participant S as signing server
    participant N as NetHSM

    Note over C: one signing server credential each,<br/>if build server: one repo server credential each
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings

    critical authentication
        C -->>+ S: authenticate,<br/>transmit file
        S ->> S: log user access and request
    option login failure
        S -x C: failure
        S ->> S: log user login failure
    option login successful
        S ->> S: log user login success
        critical user mapping
            S ->> S: map client user to NetHSM user and certificate ID
            option mapping not found
                S ->> S: log user mapping failure
                S -x C: failure
            option mapping found
                S ->> S: log user mapping success
        end
    end
    critical data preparation
        S ->> S: create checksum for file
    end
    critical signing
        S -->>+ N: authenticate for client,<br/>transmit checksum and cert ID
    option authentication fails/ signature not created
        S ->> S: log signature failure
        S -x C: failure
        S ->> S: log signature return failure
    option authentication succeeds/ signature created
        N ->>- S: raw cryptographic signature
        S ->> S: log signature success
        S ->>- C: OpenPGP signature
        S ->> S: log signature return success
    end
```

Here, the `n clients` may be build servers or the repository server, as they are functionally equal in behavior.

### Signing service signing hashes and files as proxy

```mermaid
---
title: Signing service signing hashes and files as proxy
---
sequenceDiagram
    participant B as build server
    participant S as signing server
    participant N as NetHSM
    participant R as repo server
    participant L as logging server
    participant M as metrics server

    Note over B: 1 signing server credential
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings,<br/>1 repo server credential
    Note over S: PKCS11 based tooling for signing
    Note over R: 1 signing server credential

    loop package build
        B ->> B: get sources,<br/>build package(s),<br/>send to signing server
    end
    B -->> S: authenticate,<br/>transmit file
    S -->> N: authenticate for client,<br/>transmit checksum and cert ID
    N ->> S: raw cryptographic signature

    loop repository update
        R ->> R: receive package(s),<br/>generate sync databases,<br/>get signature,<br/>update repository
    end
    S ->> R: package(s) and OpenPGP signature(s)
    R -->> S: authenticate,<br/>transmit checksum or file
    S -->> N: authenticate for client,<br/>transmit checksum and cert ID
    N ->> S: raw cryptographic signature
    S ->> R: OpenPGP signature

    loop metrics collection
        B --> M: read
        S --> M: read
        N --> M: read
        R --> M: read
    end
    loop log aggregation
        N -->> L: send via syslog
    end
```

The signing process in more detail may look as follows:

```mermaid
---
title: Signing process in "Signing service signing hashes and files as proxy" scenario
---
sequenceDiagram
    participant B as n build clients
    participant R as one repo client
    participant S as signing server
    participant N as NetHSM

    Note over B: 1 signing server credential each
    Note over R: 1 signing server credential
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings,<br/>repo server credential

    critical data aggregation
        B ->> B: aggregate packages and metadata (e.g. target repo) in single file
    end
    critical authentication
        B -->>+ S: authenticate,<br/>transmit package(s) and target repo
        S ->> S: log user access and request
    option login failure
        break login failure
            S ->> S: log user login failure
            S -x B: failure
        end
    option login success
        S ->> S: log user login success
        critical user mapping
            S ->> S: map client user to NetHSM user and certificate ID
        option mapping not found
            break user mapping not found
                S ->> S: log user mapping failure
                S -x B: failure
            end
        option mapping found
            S ->> S: log user mapping success
            S ->> B: success
        end
    end

    loop data preparation
        S ->> S: create checksum for package
    end

    loop get signature(s)
        critical signing
            S ->>+ N: authenticate for client,<br/>transmit checksum and cert ID
        option authentication fails/ signature not created
            S ->> S: log signature failure
        option authentication succeeds/ signature created
            N ->>- S: raw cryptographic signature
            S ->> S: log signature success
        end
    end

    critical send to repo server
        S ->>- R: authenticate,<br/>transmit package(s), OpenPGP signature(s) and target repo
    option authentication failure
        S ->> S: log failure of transmitting package(s), OpenPGP signature(s) and target repo
    option authentication success
        S ->> S: log success of transmitting package(s), OpenPGP signature(s) and target repo
    end

    loop payload preparation
        R ->> R: create OpenPGP hash for database and collect file metadata
    end
    critical authentication
        R -->>+ S: authenticate,<br/>transmit OpenPGP hash and file metadata
        S ->> S: log user access and request
    option login failure
        break login failure
            S ->> S: log user login failure
            S -x R: failure
        end
    option login successful
        S ->> S: log user login success
        critical user mapping
            S ->> S: map client user to NetHSM user and certificate ID
        option mapping not found
            break user mapping not found
                S ->> S: log user mapping failure
                S -x R: failure
            end
        option mapping found
            S ->> S: log user mapping success
        end
    end

    loop get signature(s)
        critical signing
            S ->>+ N: authenticate for client,<br/>transmit checksum and cert ID
        option authentication fails/ signature not created
            break signature failure
                S ->> S: log signature failure
                S -x R: failure
            end
        option authentication succeeds/ signature created
            N ->>- S: raw cryptographic signature
            S ->> S: log signature success
        end
    end

    critical return of signature(s)
        S ->>- R: OpenPGP signature(s)
    option signature(s) not returned
        S ->> S: log failed return of OpenPGP signature(s)
    option signature(s) returned
        S ->> S: log successful return of OpenPGP signature(s)
    end
```

### Signing service signing files as proxy

```mermaid
---
title: Signing service signing files as proxy
---
sequenceDiagram
    participant B as build server
    participant S as signing server
    participant N as NetHSM
    participant R as repo server
    participant L as logging server
    participant M as metrics server

    Note over B: 1 signing server credential
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings,<br/>1 repo server credential
    Note over S: PKCS11 based tooling for signing
    Note over R: 1 signing server credential

    loop package build
        B ->> B: get sources,<br/>build package(s),<br/>send to signing server
    end
    B -->> S: authenticate,<br/>transmit file
    S -->> N: authenticate for client,<br/>transmit checksum and cert ID
    N ->> S: raw cryptographic signature
    loop repository update
        R ->> R: receive package(s),<br/>generate sync databases,<br/>get signature,<br/>update repository
    end
    S ->> R: package(s) and OpenPGP signature(s)
    R -->> S: authenticate,<br/>transmit checksum or file
    S -->> N: authenticate for client,<br/>transmit checksum and cert ID
    N ->> S: raw cryptographic signature
    S ->> R: OpenPGP signature

    loop metrics collection
        B --> M: read
        S --> M: read
        N --> M: read
        R --> M: read
    end
    loop log aggregation
        N -->> L: send via syslog
    end
```

The signing process in more detail may look as follows:

```mermaid
---
title: Signing process in "Signing service signing files as proxy" scenario
---
sequenceDiagram
    participant B as n build clients
    participant R as one repo client
    participant S as signing server
    participant N as NetHSM

    Note over B: 1 signing server credential each
    Note over R: 1 signing server credential
    Note over S: n NetHSM operator credentials,<br/>n NetHSM certificate IDs,<br/>n client to NetHSM mappings,<br/>repo server credential

    critical data aggregation
        B ->> B: aggregate packages and metadata (e.g. target repo) in single file
    end
    critical authentication
        B -->>+ S: authenticate,<br/>transmit package(s) and target repo
        S ->> S: log user access and request
    option login failure
        break login failure
            S ->> S: log user login failure
            S -x B: failure
        end
    option login success
        S ->> S: log user login success
        critical user mapping
            S ->> S: map client user to NetHSM user and certificate ID
        option mapping not found
            break user mapping not found
                S ->> S: log user mapping failure
                S -x B: failure
            end
        option mapping found
            S ->> S: log user mapping success
            S ->> B: success
        end
    end

    loop data preparation
        S ->> S: create checksum for package
    end

    loop get signature(s)
        critical signing
            S ->>+ N: authenticate for client,<br/>transmit checksum and cert ID
        option authentication fails/ signature not created
            S ->> S: log signature failure
        option authentication succeeds/ signature created
            N ->>- S: raw cryptographic signature
            S ->> S: log signature success
        end
    end

    critical send to repo server
        S ->>- R: authenticate,<br/>transmit package(s), OpenPGP signature(s) and target repo
    option authentication failure
        S ->> S: log failure of transmitting package(s), OpenPGP signature(s) and target repo
    option authentication success
        S ->> S: log success of transmitting package(s), OpenPGP signature(s) and target repo
    end

    critical authentication
        R -->>+ S: authenticate,<br/>transmit database(s)
        S ->> S: log user access and request
    option login failure
        break login failure
            S ->> S: log user login failure
            S -x R: failure
        end
    option login successful
        S ->> S: log user login success
        critical user mapping
            S ->> S: map client user to NetHSM user and certificate ID
        option mapping not found
            break user mapping not found
                S ->> S: log user mapping failure
                S -x R: failure
            end
        option mapping found
            S ->> S: log user mapping success
        end
    end

    loop data preparation
        S ->> S: create checksum for database
    end

    loop get signature(s)
        critical signing
            S ->>+ N: authenticate for client,<br/>transmit checksum and cert ID
        option authentication fails/ signature not created
            break signature failure
                S ->> S: log signature failure
                S -x R: failure
            end
        option authentication succeeds/ signature created
            N ->>- S: raw cryptographic signature
            S ->> S: log signature success
        end
    end

    critical return of signature(s)
        S ->>- R: OpenPGP signature(s)
    option signature(s) not returned
        S ->> S: log failed return of OpenPGP signature(s)
    option signature(s) returned
        S ->> S: log successful return of OpenPGP signature(s)
    end
```
