//! Integration tests for signstar-config modules.
#![cfg(feature = "_containerized-integration-test")]

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use std::{
    env::var,
    fs::copy,
    os::unix::fs::chown,
    path::{Path, PathBuf},
};

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use log::debug;
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use signstar_config::test::list_files_in_dir;
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use testresult::TestResult;

/// Environment variables that are passed in to a command call as a different user.
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
const ENV_LIST: &[&str] = &[
    "LLVM_PROFILE_FILE",
    "CARGO_LLVM_COV",
    "CARGO_LLVM_COV_SHOW_ENV",
    "CARGO_LLVM_COV_TARGET_DIR",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
];
/// The location of cargo-llvm-cov `.profraw` files when running a command as a different user.
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
const LLVM_PROFILE_FILE: &str = "/tmp/signstar-%p-%16m.profraw";

/// Collects all `.profraw` files from `path` and copies them to `CARGO_LLVM_COV_TARGET_DIR`.
///
/// Only copies files from `path` if the `CARGO_LLVM_COV_TARGET_DIR` environment variable is set.
/// Changes the ownership of files copied to `CARGO_LLVM_COV_TARGET_DIR` to root.
///
/// # Errors
///
/// Returns an error if
///
/// - `path` cannot be read,
/// - an entry in `path` cannot be read,
/// - copying a file from `path` to `CARGO_LLVM_COV_TARGET_DIR` fails,
/// - or changing the ownership permissions of a copied file in `CARGO_LLVM_COV_TARGET_DIR` to root
///   fails.
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
fn collect_coverage_files(path: impl AsRef<Path>) -> TestResult {
    let path = path.as_ref();
    list_files_in_dir(path)?;

    let Ok(cov_target_dir) = var("CARGO_LLVM_COV_TARGET_DIR") else {
        return Ok(());
    };
    debug!("Found CARGO_LLVM_COV_TARGET_DIR={cov_target_dir}");
    let cov_target_dir = PathBuf::from(cov_target_dir);

    for dir_entry in path.read_dir()? {
        let dir_entry = dir_entry?;
        let from = dir_entry.path();
        let Some(file_name) = &from.file_name() else {
            continue;
        };
        if let Some(extension) = from.extension()
            && extension == "profraw"
        {
            let target_file = cov_target_dir.join(file_name);
            debug!("Copying {from:?} to {target_file:?}");
            copy(&from, &target_file)?;
            chown(&target_file, Some(0), Some(0))?;
        }
    }

    Ok(())
}

pub mod admin_credentials;

pub mod config;

#[cfg(feature = "nethsm")]
pub mod non_admin_credentials;

pub mod usermapping;
