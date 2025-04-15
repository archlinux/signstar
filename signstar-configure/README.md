# Signstar configure

Runtime configuration tool for Signstar hosts.

Provides the `signstar-configure` executable which configures

- one or more [NetHSM] backends connected to a _Signstar host_,
- backend credentials for login users on a _Signstar host_ with the help of a Signstar configuration file,
- and administrative credentials (see [signstar-config]) during runtime.

Ultimately, the application tries to opportunistically configure all backends it is aware of in a way that is consistent with the Signstar configuration file on the _Signstar host_.

The executable must be run as root, and is meant to be run repeatedly on a timer after boot (e.g. using a [systemd.timer] unit).
Running the application repeatedly allows to react to changes with regards to the administrative credentials or backends, apply backups, etc.

An initial run of the executable is meant to be used in [Automatic Boot Assessment] scenarios to establish whether the system consistently fails to boot and reverting to a previous state of the _Signstar host_ should be attempted.
`signstar-configure` may fail for various reasons and exit with a non-zero status code.
Any possible failure is of one of the following two categories:

- **unrecoverable**: The Signstar system is irreparably broken and needs to be reset (potentially booted into a previous version).
- **recoverable**: The Signstar system is missing required input data or the backend is not available (the executable may succeed when rerunning it).

The `signstar-configure` executable is able to restore a [NetHSM] backend from backup.
Each backup file is tied to a very specific set of administrative credentials and a specific Signstar configuration file.
The specific set of administrative credentials allow to apply the backup and make use of all administrative accounts available in the backend.
The version match between backup file, Signstar configuration file and administrative credentials is referred to as an _iteration_.

## Dependencies

The `signstar-configure` executable depends on correct system time and should therefore only run after the system clock has been synchronized successfully.

## Configure

When running `signstar-configure`, the execution flow passes through several stages.
Each stage may have a set of **inputs**, **outputs** and/or **optional-outputs**.
All **outputs** and **optional-outputs** can be made available to the following stages.

Each stage may abort based on **unrecoverable** or **recoverable** errors.
Many stages may be skipped based on whether a **condition** can not be met.

### Read configuration

A Signstar configuration file on the system is read from one of the default locations.

- **input**: Signstar configuration file.
- **unrecoverable**: There is no configuration file, or the configuration file can not be read or is invalid.
- **output**: The configuration object, which covers general configuration options, a set of connections and a set of user mappings.

### Check connections

Each backend connection _configured_ in the Signstar configuration file is checked.
As a backup, the hardcoded default connection of an unprovisioned [NetHSM] backend is checked.

First, each exact _configured_ connection is probed for availability (the backend should be reachable and in either _locked_, _operational_ or _unprovisioned_ state).

If there is only one _configured_ connection and it is not reachable at the _configured_ address, the _default_ connection is probed instead.

If there is more than one connection, with none of them reachable, the default connection is probed instead for the first unreachable connection.

If there is more than one connection, with at least one of them in _locked_ or _operational_ state and one or more of them not reachable, the default connection is probed instead for the first unreachable connection.

- **input**: Signstar configuration object.
- **unrecoverable**: One of the connections fails due to TLS issues (e.g. the backend changed and does not provide the same TLS certificate as before).
- **recoverable**: A backend is not reachable (neither at its configured address, nor ath the hardcoded default address).
- **output**: A set of available connections.

### Read backup file

If a Signstar backup file has been uploaded to a runtime directory, read it.

- **input**: Signstar backup file.
- **condition**: Signstar backup file exists.
- **recoverable**: More than one backup file has been uploaded and all are removed.
- **recoverable**: A backup file is not well-formed and is removed.
- **output**: A backup file.

### Read administrative credentials

All administrative credentials present on the _Signstar host_ are read and validated.
Administrative credentials may exist as _plaintext_ files, _systemd-creds_ encrypted files or as shares of a shared secret using [Shamir's Secret Sharing].

- **input**: Signstar administrative credentials.
- **condition**: Signstar administrative credentials are present.
- **recoverable**: Administrative credentials are invalid and are removed.
- **output**: One or more sets of administrative credentials.

### Validate backup file with administrative credentials

If a Signstar backup file has been uploaded to a runtime directory,
use administrative credentials with a matching _iteration_ to validate the file.

- **input**: Signstar backup file.
- **input**: One or more sets of administrative credentials.
- **condition**: Signstar backup file exists.
- **condition**: Signstar administrative credentials are present.
- **recoverable**: Administrative credentials with a matching iteration can not be used for validating the Signstar backup file and the backup file is removed.
- **output**: Administrative credentials in particular iteration.

### Create administrative credentials

If all available connections are in _unprovisioned_ state and no backup file is present, create initial administrative credentials in a runtime directory.
Filename and location depend on the configuration for administrative secret handling, which may be one of

- _plaintext_: The credentials are stored in a plaintext file and are managed on the system.
- _systemd-creds_: The credentials are stored in a [`systemd-creds`] encrypted file and are managed on the system.
- _sss_: The credentials are created as a set of shares of a shared secret using [Shamir's Secret Sharing] in runtime directories and are later kept outside of the system.

- **input**: Signstar configuration object.
- **input**: Signstar backup file.
- **condition**: All available connections are in _unprovisioned_ state.
- **condition**: Signstar backup file does not exist.
- **unrecoverable**: Administrative credentials can not be created.
- **output**: Administrative credentials.

### Ensure all shares of a shared secret are downloaded

If [Shamir's Secret Sharing] is configured for the administrative credentials
and administrative credentials are present in a runtime directory
and all available connections are in _unprovisioned_ state
and no backup file is present
check if all shares of the shared secret are downloaded.

To track the download state of each share in the login user's respective runtime directory, `signstar-configure` relies on accompanying state files that indicate them being downloaded at least once.

- **input**: Signstar backup file.
- **input**: Administrative credentials.
- **condition**: All available connections are in _unprovisioned_ state.
- **condition**: Administrative credentials are available.
- **condition**: [Shamir's Secret Sharing] is used for administrative credentials.
- **condition**: Signstar backup file does not exist.
- **recoverable**: Not all shared secrets are downloaded.

### Create non-administrative secrets

If administrative credentials are available, non-administrative secrets for backend users associated with each login user on the _Signstar host_ are created in a persistent, per-user location.

- **input**: Administrative credentials.
- **input**: Signstar configuration object.
- **condition**: Administrative credentials are available.
- **condition**: Iteration of administrative credentials matches that of the Signstar configuration object.
- **recoverable**: Administrative credentials are not available.
- **unrecoverable**: Non-administrative secrets can not be created.
- **output**: Non-administrative secrets.

---

**TODO**: Figure out how to map iterations to the state of a [NetHSM] backend.
**TODO**: Figure out how to deal with multiple [NetHSM] backends in unprovisioned state (which will have the same IP address!).

---

### Provision first unprovisioned backend

If _all_ backends are in _unprovisioned_ state, no Signstar backup file exists,
and administrative credentials in an _iteration_ matching the Signstar configuration object are present on the system,
provision the first backend using the administrative credentials in the particular version.

- **input**: Administrative credentials.
- **input**: Non-administrative secrets.
- **input**: Signstar configuration object.
- **condition**: All backends are in _unprovisioned_ state.
- **condition**: Signstar backup file does not exist.
- **condition**: Iteration of administrative credentials matches that of the Signstar configuration object.
- **recoverable**: An error occurs while provisioning the backend because of connectivity issues and the non-administrative secrets are removed.

### Restore from backup file

If an uploaded Signstar backup file is present, restore all backends from it.

If not all backends are in _unprovisioned_ state, iteratively 
Afterwards, the non-administrative 
 but keep the administrative credentials with the matching iteration (if [Shamir's Secret Sharing] is _not_ used).
Finally, remove the uploaded backup file.

- **input**: Administrative credentials.
- **input**: Non-administrative secrets.
- **input**: Signstar configuration object.
- **input**: Signstar backup file.
- **condition**: Signstar backup file exists.
- **condition**: Iteration of administrative credentials matches that of the Signstar backup file and Signstar configuration object.
- **output**: State file for successful restore from backup to a specific iteration.

### Synchronize backend

If a state file for the successful restore from backup to a specific iteration exists,
use administrative credentials of that particular iteration to set the administrative credentials on the backend to the default administrative credentials.

Synchronize the state of the backend with all data available in the default administrative credentials and the Signstar configuration object.
Remove data from runtime directories.

- **input**: Administrative credentials.
- **input**: Signstar configuration object.
- **optional-input**: State file for successful restore from backup to a specific iteration.

## Documentation

- <https://signstar.archlinux.page/rustdoc/signstar_config/> for development version of the crate
- <https://docs.rs/signstar_config/latest/signstar_config/> for released versions of the crate

## Features

- `_containerized-integration-test` enables tests that require to be run in a separate, ephemeral container each.

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[Automatic Boot Assessment]: https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/
[MIT]: https://opensource.org/licenses/MIT
[NetHSM]: https://www.nitrokey.com/products/nethsm
[Shamir's Secret Sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
[contributing guidelines]: ../CONTRIBUTING.md
[signstar-configure-build]: https://signstar.archlinux.page/signstar-configure-build/index.html
[signstar-config]: https://signstar.archlinux.page/signstar-config/index.html
[systemd.timer]: https://man.archlinux.org/man/systemd.timer.5
[`systemd-creds`]: https://man.archlinux.org/man/systemd-creds.1
