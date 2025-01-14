//! Common data for all Signstar functionalities.
//!
//! # Examples
//!
//! ```
//! use signstar_common::common::get_data_home;
//!
//! // Get the directory below which all Signstar related data is stored.
//! println!("{:?}", get_data_home());
//! ```

use std::path::PathBuf;

/// The directory below which o store all Signstar related data.
const DATA_HOME: &str = "/var/lib/signstar/";

/// The file mode of directories containing credentials.
pub const CREDENTIALS_DIR_MODE: u32 = 0o100700;

/// The file mode of secret files.
pub const SECRET_FILE_MODE: u32 = 0o100600;

/// Get the directory below which all Signstar related data is stored.
pub fn get_data_home() -> PathBuf {
    PathBuf::from(DATA_HOME)
}
