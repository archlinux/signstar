# Signstar configure

Runtime configuration tool for Signstar hosts.

Provides the `signstar-configure` executable which configures a [NetHSM] backend and backend credentials used by login users with the help of a Signstar configuration file and administrative credentials (see [signstar-config]) during runtime.
Ultimately, the application tries to opportunistically configure all backends it is aware of.

The executable must be run as root, and is meant to be run repeatedly on a timer after boot (e.g. using a [systemd.timer] unit).

It is meant to be used in [Automatic Boot Assessment] scenarios to establish whether the system consistently fails to boot and reverting to a previous state should be attempted.
`signstar-configure` may fail for various reasons and exit with a non-zero status code.
Any possible failure is of one of the following two categories:

- **unrecoverable**: The Signstar system is irreparably broken and needs to be reset (potentially booted into a previous version).
- **recoverable**: The Signstar system is missing required input data or the backend is not available (the executable may succeed when rerunning it).

## Dependencies

The `signstar-configure` executable depends on correct system time and should therefore only run after the system clock has been synchronized successfully.

## Configure

When running `signstar-configure`, the execution flow passes through several stages.
Each stage may have a set of **inputs**, **outputs** and/or **optional-outputs**.
All **outputs** and **optional-outputs** can be made available to the following stages.

### Read configuration

A Signstar configuration file on the system is read from one of the default locations.

- **unrecoverable**: The configuration file can not be read or is invalid.
- **output**: The configuration object, which covers general configuration options, a set of connections and a set of user mappings.

### Check connections

Each backend connection configured in the Signstar configuration file is checked.

First, each exact configured connection is probed for availability (the backend should be in either _locked_, _operational_ or _unprovisioned_ state).

If there is only one configured connection and the configured connection is not available, the default connection is probed instead.

If there is more than one connection, with none of them available, the default connection is probed instead for the first unavailable connection.

If there is more than one connection, with at least one of them in _locked_ or _operational_ state and one or more of them not available, the default connection is probed instead for the first unavailable connection.

- **input**: Signstar configuration object.
- **unrecoverable**: One of the connections fails due to TLS issues.
- **recoverable**: A backend is not reachable.
- **output**: A set of available connections.

### Consume backup file

Backup files uploaded to runtime directories are read and validated.

- **recoverable**: A backup file is invalid and is removed.
- **output**: A backup file.

### Consume administrative credentials

Administrative credentials present on the system are read and validated.
If a Signstar backup file is present, the administrative credentials are used to try and decrypt it.

- **optional-input**: Signstar backup file.
- **recoverable**: Administrative credentials are invalid and are removed.
- **optional-output**: Administrative credentials.

### Consume administrative credentials for uploaded backup file

If an uploaded Signstar backup file is present in a runtime directory,
and the system's default administrative credentials can not be used to restore from it (due to different iteration),
look for and use an iteration compatible set of administrative credentials.

- **input**: Signstar backup file.
- **recoverable**: Administrative credentials with matching iteration are invalid and are removed.
- **recoverable**: Administrative credentials with matching iteration can not be used for restoring from the backup and the backup file is removed.
- **optional-output**: Administrative credentials in particular iteration.

### Create administrative credentials

If all available connections are in _unprovisioned_ state and no backup file is present, create initial administrative credentials in a runtime directory.
Filename and location depend on the configuration for administrative secret handling, which may be one of

- *plaintext*: The credentials are stored in a plaintext file and are managed on the system.
- *systemd-creds*: The credentials are stored in a [`systemd-creds`] encrypted file and are managed on the system.
- *sss*: The credentials are created as a set of shares of a shared secret using [Shamir's Secret Sharing] in runtime directories and are later kept outside of the system.

- **input**: Signstar configuration object.
- **optional-input**: Signstar backup file.
- **unrecoverable**: Administrative credentials can not be created.
- **optional-output**: Administrative credentials.

### Check if all shares of a shared secret are downloaded

If [Shamir's Secret Sharing] is configured for the administrative credentials
and administrative credentials are present in a runtime directory
and all available connections are in _unprovisioned_ state
and no backup file is present
check if all shares of the shared secret are downloaded.

- **optional-input**: Signstar backup file.
- **optional-input**: Administrative credentials.
- **recoverable**: Not all shared secrets are downloaded.
- **optional-output**: State file on the successful download of all shares.

### Create non-administrative secrets

If administrative credentials are available, non-administrative secrets for each login user on the system are created on-the-fly.

- **input**: Administrative credentials.
- **input**: Signstar configuration object.
- **recoverable**: Administrative credentials are not available.
- **unrecoverable**: Non-administrative secrets can not be created.
- **output**: State file on the successful creation of non-administrative secrets.

### Provision backend

If a backend is in _unprovisioned_ state,
and administrative credentials in a particular iteration are present on the system,
provision the backend using the administrative credentials in the particular version.

Otherwise if a backend is in _unprovisioned_ state,
provision the backend using the default administrative credentials.

- **input**: Administrative credentials.
- **input**: Signstar configuration object.
- **optional-input**: Administrative credentials in particular iteration.

### Restore from uploaded backup

If an uploaded Signstar backup file is present, restore from it.
Afterwards remove the uploaded backup file, but keep the administrative credentials with the matching iteration.

- **input**: Signstar backup file.
- **input**: Administrative credentials.
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
[Shamir's Secret Sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
[contributing guidelines]: ../CONTRIBUTING.md
[signstar-configure-build]: https://signstar.archlinux.page/signstar-configure-build/index.html
[signstar-config]: https://signstar.archlinux.page/signstar-config/index.html
[systemd.timer]: https://man.archlinux.org/man/systemd.timer.5
[`systemd-creds`]: https://man.archlinux.org/man/systemd-creds.1
