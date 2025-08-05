# Threat model

This documents orients itself around the [threat modeling manifesto] and [threat modeling capabilities].
It is designed as a living document, which is meant to be extended in the future.

While threat models can be designed using [threat dragon], the authors chose to rely on a more basic approach based on [threat categories] and [response and mitigation categories].

## Description

An Arch Linux image-based operating system, running on a dedicated host, that is connected to an HSM device.
The system issues signatures for incoming signing requests based on a dedicated protocol by forwarding the raw cryptographic signature task to the HSM.
All authentication to the host is done using SSH.
Updates to the image-based OS are built using a dedicated key for secure boot/verity signing and the resulting payloads are signed using a dedicated set of OpenPGP keys.

## Assumptions

The following assumptions about the setup of the system provide a baseline for its operation:

- The physical security of the host is guaranteed by a non-malicious hoster.
- The hoster is provided with an HSM that they connect physically to the specific host.
- The HSM vendor is not malicious.
- Secure Boot on the host is available and the firmware provides it reliably.
- The host offers a TPM-2.0.
- Access to the firmware is guaranteed by KVM console.

## Potential threats

1. _Threat_ (**Elevation of Privileges**): Attacker boots a malicious payload on the host.\
   _Action_ (**Mitigate**): A passphrase is set for the host's firmware and the boot is locked to a pre-defined payload.\
   _Validation_: Attempt to boot the machine into a default recovery system.
1. _Threat_ (**Information disclosure**): Attacker has physical access to machine and creates a copy of the hard drive contents.\
   _Action_ (**Mitigate**): All data used long-term that deserves protection is placed on a partition, encrypted using the TPM-2.0 of the host.\
   If an attacker copies the contents of the harddrive, they are not able to decrypt the partition without the TPM-2.0 of the host.\
   _Validation_: Boot the machine into a recovery system, copy the contents of the harddrive to an image and attempt to decrypt the encrypted data partition.
1. _Threat_ (**Tampering**): Attacker provides a malicious upgrade to the image-based OS.\
   _Action_ (**Eliminate**): Upgrades to the image-based OS are cryptographically signed.
   The operating system only considers an upgrade, if a valid signature is found alongside the upgrade payload in a pre-configured location.\
   _Validation_: Add an unsigned upgrade to the image-based OS in the pre-configured location and ensure that the upgrade is not considered.
1. _Threat_ (**Elevation of privileges**): Attacker abuses a known vulnerability in a component used in the image-based operating system.\
   _Action_ (**Mitigate**): The vulnerable component is fixed/upgraded and a new version of the image-based OS is released.
   Components unnecessary to the prime function of the system are removed from each image of the dedicated operating system to reduce the attack surface.\
   _Validation_: A rigirous CI setup ensures that no known vulnerabilities are present in the components developed in the context of the project and that those are buildable on a daily basis.
   A separate CI ensures that updates to the image-based OS can be built on a daily basis.
1. _Threat_ (**Tampering**): Attacker manipulates the root filesystem of the host.\
   _Action_ (**Eliminate**): The filesystems of the host are verified using `dm-verity` (see e.g. [veritysetup]).\
   _Validation_: Boot into a recovery system, manipulate a file on the root filesystem and attempt to boot.
   Ensure, that the system fails to boot.
1. _Threat_ (**Tampering**): Attacker manipulates the filesystems of a running system.\
   _Action_ (**Eliminate**): All partitions, except the data partition, are mounted read-only. All partitions except the data partition use `dm-verity`.\
   _Validation_: A dedicated test application attempts to write to the read-only partitions during boot and leads the OS to fail its boot.
1. _Threat_ (**Repudiation**): Attacker manipulates logs or metrics to cover their tracks.\
   _Action_ (**Mitigate**): Logs and metrics are directly sent/forwarded to a central logging/metrics server.
   The system does not offer login shells.\
   _Validation_: A dedicated test application shuts down the logging service on the host, which can be observed on the loggine server.
1. _Threat_ (**Spoofing**): Attacker impersonates a client to the system.\
   _Action_ (**Transfer**): Clients are expected to guard their SSH private keys using a TPM-2.0.\
   _Action_ (**Mitigate**): If an impersonation is detected, a new version of the image-based operating system is released, that disables access for the affected SSH public key.\
   _Validation_: Ensure that after an update disabling an SSH public key, that the client can no longer log in.
1. _Threat_ (**Denial of service**): An attacker issues many failed attempts to authenticate and blocks other, legitimate clients from requesting a signature.\
   _Action_ (**Eliminate**): The system relies entirely on SSH public key authentication and does not support password authentication or brute-force-prevention mechanisms such as fail2ban, which could lead to legitimate clients to the system getting blocked.\
   _Validation_: Launch many failed attempts to authenticate as a known client and ensure that the legitimate client can still authenticate using their SSH private key.
1. _Threat_ (**Denial of service**): Attacker physically destroys the machine and HSM.\
   _Action_ (**Eliminate**): The host runs on commodity hardware and encrypted backups are created for the HSM.\
   _Validation_: Wipe the harddrive of a system (in a multi-system setup) and set it up from scratch.
   Afterwards provide the encrypted backup to the system to restore the HSM from.
1. _Threat_ (**Information disclosure**): Attacker copies the backup file for the HSM.\
   _Action_ (**Mitigate**): The backup file for the HSM is always encrypted.
   The passphrase for decryption is distributed to several individuals using Shamir's Secret Sharing.\
   _Validation_: Ensure that the encrypted backup works by restoring an existing system from it.
1. _Threat_ (**Information disclosure**): Attacker exfiltrates operator-level authentication tokens for the HSM from the running system.\
   _Action_ (**Mitigate**): The operator-level credentials for the HSM are kept in the encrypted partition and can only be used with the specific connected hardware device.
   Additionally, they are encrypted per system-user, using the TPM-2.0 of the host.\
   _Validation_: n/a
1. _Threat_ (**Information disclosure**): Attacker exfiltrates administrator-level authentication tokens for the HSM from the running system.\
   _Action_ (**Accept**): Shares of the administrator-level credentials for the HSM are briefly kept in a volatile filesystem during installation of the system or when restoring from backup and could be extracted during that timeframe.\
   In such a situation, the administrative credentials must be rotated and new shares of the shared secret be created using Shamir's Secret Sharing.\
   _Validation_: n/a
1. _Threat_ (**Information disclosure**): Attacker copies administrator-level authentication tokens for the HSM.\
   _Action_ (**Mitigate**): The administrator-level credentials for the HSM are split using Shamir's Secret Sharing and distributed among trusted individuals of the distribution.
   No individual has access to the complete administrator-level credentials.\
   _Validation_: Attempt to extract the administrator-level credentials from an insufficient amount of shares.
1. _Threat_ (**Elevation of privileges**): Attacker uses the HSM to create a signature.\
   _Action_ (**Mitigate**): A dedicated host with an image-based OS is connected to the HSM.
   It holds the operator-level credentials for the HSM and only briefly has access to the administrator-level credentials.
   Each HSM is configured with unique operator-level credentials.
   An HSM requires the specific host it was configured with to function.\
   _Validation_: Ensure that authentication against an HSM is not possible, after using it on another machine.
1. _Threat_ (**Information disclosure**): Attacker exfiltrates administrator-level and/or operator-level authentication tokens for the HSM from the running system and steals the HSM.\
   _Action_ (**Accept**): Shares of the administrator-level credentials for the HSM are briefly kept in a volatile filesystem during installation of the system and the operator-level credentials are kept in the encrypted data partition.
   If they are exfiltrated and the attacker also steals that specific HSM, the HSM can be used to issue signatures.\
   In such a situation, all affected private keys must be revoked, a public statement be made and afterwards an entirely new set of private keys be created.\
   _Validation_: n/a
1. _Threat_ (**Tampering**): Attacker manipulates the firmware bootloader.\
   _Action_ (**Transfer**): The firmware of the system host is locked by a passphrase, known to a dedicated set of people.
   Access to the firmware can only be granted by first requesting a KVM console from the hoster after passing two-factor authentication.\
   _Validation_: Ensure that ordering a KVM console is logged by the hoster.
1. _Threat_ (**Repudiation**): Attacker manipulates logs or metrics on the wire.\
   _Action_ (**Mitigate**): Both logs and metrics are transferred to a central logging server encrypted, through a VPN.\
   _Validation_: Ensure logs and metrics are not transmitted in the clear (e.g. with the help of wireshark).
1. _Threat_ (**Tampering**): Attacker uses a compromised client to create a signature for a malicious payload.\
   _Action_ (**Accept**): Requesting signatures for malicious payloads is possible.
   However, after the fact, the list of signatures requested since the client compromise can be correlated from the logs on the central logging server.
   The affected payloads need to be inspected and potentially re-created.\
   _Validation_: n/a
1. _Threat_ (**Spoofing**): Attacker forges a signature.\
   _Action_ (**Transfer**): The signing keys used by the HSM rely on strong cryptographic algorithms and only exist in the HSM or in encrypted backups.
   The certificate of each OpenPGP key is certified with at least three third-party certifications using PGPKI, through which a signature created using the key can be authenticated.
   Recipients of payload and signature need to verify the signature.\
   _Validation_: A foreign OpenPGP signature for a payload is attempted to be validated against a PKI and fails.
1. _Threat_ (**Elevation of Privilege**): Attacker compromises credentials of a specific system user and uses it to perform an action only valid for another user.\
   _Action_ (**Mitigate**): Each system user on the host is strongly tied to a specific role.
   An operator user can only ever created signatures using a specific key in the HSM, a metrics user can only ever create metrics for the system or a set of keys and a backup user can only ever download an encrypted backup.\
   _Validation_: Using the credentials of a backup system user, attempt to request a signature and ensure that the call fails.
1. _Threat_ (**Elevation of Privilege**): Attacker gains full control over the operating system of the host and issues signatures.\
   _Action_ (**Accept**): Shares of the administrator-level credentials for the HSM are briefly kept in a volatile filesystem during installation of the system or when restoring from backup and could be made use of during that timeframe.
   Operator-level credentials are available continuously in the encrypted data partition and could always be used.
   If an attacker gains full control over the system, they can create signatures using all private keys used in the HSM.
   In this case, the system should be shut down immediately and a new one needs to be setup from scratch.
   If administrator-level credentials have been exposed, this involves creating new keys and revoking all affected ones.\
   _Validation_: n/a
1. _Threat_ (**Elevation of Privilege**): Attacker exports all keys from the HSM.\
   _Action_ (**Mitigate**): Keys can only be exported from the HSM using administrative credentials, which are passed in to the host as a set of shares of a shared secret.
   The shares are maintained by a set of trusted individuals with dedicated authentication to the host.
   Beyond the brief time windows in which a sufficient amount of shares are available on the host in a volatile filesystem location, the operating system does not have access to the needed administrative credentials for exporting keys.\
   _Validation_: A dedicated test attempts to export keys from the HSM during boot and fails.
1. _Threat_ (**Tampering**): Attacker uses a compromised client to encrypt data instead of signing it.\
   _Action_ (**Eliminate**): Keys are bound to a specific scope that they are used in.
   This restriction is enforced in the HSM and on a protocol level (e.g. OpenPGP key usage flags).
   Additionally, the protocol for requesting a signature does not offer any other usage.\
   _Validation_: n/a
1. _Threat_ (**Elevation of Privilege**): Attacker compromises a sufficient amount of shareholders by exfiltrating their shares and SSH authentication and exfiltrates an encrypted backup file or steals one of the HSMs.\
   _Action_ (**Accept**): With a sufficient amount of shares, it is possible to decrypt the encrypted backup or to connect to the HSM and subsequently export all private key material.\
   In such a situation, all affected private keys must be revoked, a public statement be made and afterwards an entirely new set of private keys be created.\
   _Validation_: n/a
1. _Threat_ (**Elevation of Privilege**): Attacker exfiltrates the key for secure boot/verity signing and steals the host and HSM.\
   _Action_ (**Accept**): Each copy of the secure boot/verity signing key is supposed to be imported into a dedicated hardware token, so that it cannot be exfiltrated directly.
   With it, an attacker could build a valid image to boot on the host and create signatures, given operator-level credentials are present.
   If the key for secure boot/ verity signing operations is compromised, all affected hosts need to be shut down and reprovisioned using images that use a new key.\
   _Validation_: n/a
1. _Threat_ (**Elevation of Privilege**): Attacker provides a malicious HSM by impersonating the manufacturer, or is a malicious manufacturer.\
   _Action_ (**Accept**): Dedicated tooling interacts with the HSM in a reproducible way during normal operations.
   However, the HSM itself may act as a malicious entity, e.g. by turning into keyboard, or sending all created private keys to a remote entity without our knowledge.\
   _Validation_: n/a
1. _Threat_ (**Tamper**): Attacker uses a known (or unknown) vulnerability in the firmware of the host to e.g. circumvent Secure Boot.\
   _Action_ (**Mitigate**): With KVM console access to the host, its firmware can be upgraded.\
   _Validation_: n/a

[response and mitigation categories]: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html#response-and-mitigations
[threat categories]: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html#threat-identification
[threat dragon]: https://owasp.org/www-project-threat-dragon/
[threat modeling capabilities]: https://www.threatmodelingmanifesto.org/capabilities/
[threat modeling manifesto]: https://www.threatmodelingmanifesto.org/
[veritysetup]: https://man.archlinux.org/man/core/cryptsetup/veritysetup.8.en
