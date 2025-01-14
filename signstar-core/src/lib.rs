//! A library that provides common components and data for Signstar crates

mod config;
mod ssh;
mod system_user;

pub use config::{
    DEFAULT_CONFIG_FILE,
    ETC_OVERRIDE_CONFIG_FILE,
    RUN_OVERRIDE_CONFIG_FILE,
    USR_LOCAL_OVERRIDE_CONFIG_FILE,
};
pub use ssh::{SSHD_DROPIN_CONFIG_DIR, SSH_AUTHORIZED_KEY_BASE_DIR};
pub use system_user::HOME_BASE_DIR;
