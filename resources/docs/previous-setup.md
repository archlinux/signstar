# Previous setup

This document provides an overview of the workflows and contexts for package creation and other artifacts on Arch Linux as it has been until at least 2024.

## Packages

The packaging infrastructure involves creating packages on `n` machines that `m` package maintainers have access to.

In many cases, the same machine is also used for cryptographically signing the resulting package file(s).
There is no overview over whether package maintainers use hardware tokens for this to prevent key exfiltration and no way to enforce it either.

From `n` machines that `m` package maintainers have access to, package and detached signature files are copied to a central package repository server.

```mermaid
---
title: Per package maintainer access
---
sequenceDiagram
    actor P as package maintainer
    participant B as n build machines
    participant R as repo server

    Note over B: 1 pair of build machine credentials
    Note over R: 1 pair of repo server credentials

    P ->> B: build and sign package(s)
    P ->> R: push built package and signature file(s)

    critical
        B ->> B: get sources,<br/>build package(s)
        B ->> B: sign package(s)
    end
```

## Repository sync databases

The central repository server is responsible for creating the repository sync database files, which define the state of each binary package repository.
Repository sync databases are not signed as that would involve either forwarding gpg-agent to the host from `n` machines that `m` package maintainers have access to (security and blocking issue), or to add a software key to the host (which may be exfiltrated easily).

## Release artifacts

Other artifacts such as installation media and virtual machine images are built semi-automatically or manually and are usually cryptographically signed.

Signing happens either with a software key in CI (in the case of virtual machine images) and is prone to exfiltration attacks, or manual on a single person's machine.

```mermaid
---
title: Building and signing of virtual machine images
---
sequenceDiagram
    participant C as Continuous Integration Pipeline
    participant R as repo server

    Note over R: 1 pair of repo server credentials

    C ->> R: push built installation media and signature file(s)

    critical
        C ->> C: get sources,<br/>build installation media
        C ->> C: sign installation media
    end
```

```mermaid
---
title: Building and signing of installation media
---
sequenceDiagram
    actor P as release manager
    participant B as n build machines
    participant R as repo server

    Note over B: 1 pair of build machine credentials
    Note over R: 1 pair of repo server credentials

    P ->> B: build and sign installation media
    P ->> R: push built installation media and signature file(s)

    critical
        B ->> B: get sources,<br/>build installation media
        B ->> B: sign installation media
    end
```

## Secure Boot Shim

There is so far no signed shim for Secure Boot, as the location and safe-keeping of a signing key as well as its use for signature creation in packaging is so far unsolved.

