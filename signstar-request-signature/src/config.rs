//! Configuration file handling.

use std::{
    fs::File,
    io::{ErrorKind, Read},
    path::PathBuf,
};

use crate::Error;

/// The default config file below "/usr/".
pub const DEFAULT_CONFIG: &str = "/usr/share/signstar/request-signature.toml";

/// The override config file below "/run/".
pub const RUN_OVERRIDE_CONFIG: &str = "/run/signstar/request-signature.toml";

/// The override config file below "/etc/".
pub const ETC_OVERRIDE_CONFIG: &str = "/etc/signstar/request-signature.toml";

/// The order of configuration files.
///
/// The order follows [Configuration Files Specification] which is consistent with [systemd Search
/// Path]:
///
/// > For example, `/usr/lib/foo/bar.conf` provides the default configuration file. If
/// > `/run/foo/bar.conf` is present and supported, it would take precedence over
/// > `/usr/lib/foo/bar.conf`. Finally, a user can create `/etc/foo/bar.conf` which would take
/// > precedence and completely override both.
///
/// [Configuration Files Specification]: https://uapi-group.org/specifications/specs/configuration_files_specification/#storage-directories-and-overrides
/// [systemd Search Path]: https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html
pub const CONFIG_ORDER: &[&str] = &[ETC_OVERRIDE_CONFIG, RUN_OVERRIDE_CONFIG, DEFAULT_CONFIG];

/// Reads and returns the contents of the configuration file.
///
/// If the `path` parameter is set then it has the highest precedence, otherwise [configuration
/// paths][`CONFIG_ORDER`] are checked in that order.
///
/// # Errors
///
/// Returns an error ([`Error::Io`]) if reading the config fails or no configuration files exist
/// ([`Error::ConfigMissing`]).
pub fn read_config_file(path: Option<PathBuf>) -> Result<Vec<u8>, Error> {
    let candidates = path.into_iter().chain(CONFIG_ORDER.iter().map(Into::into));
    for file in candidates {
        match File::open(&file) {
            Ok(mut reader) => {
                let mut buf = vec![];
                reader
                    .read_to_end(&mut buf)
                    .map_err(|source| Error::Io { file, source })?;
                return Ok(buf);
            }
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(Error::Io { file, source });
            }
        }
    }
    Err(Error::ConfigMissing)
}
