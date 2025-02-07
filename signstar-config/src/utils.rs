//! Utility functions.

use std::{fs::remove_file, path::Path};

/// Deletes a file without failing
///
/// This function does not error even if it can not delete the file (as the file may not
/// exist).
pub fn delete_tmp_file(path: &Path) {
    // print the error, but don't fail if the file can't be deleted as we can't
    // clean it up if we fail
    if let Err(error) = remove_file(path) {
        eprintln!("Deleting {:?} failed:\n{}", path, error)
    }
}
