use std::path::PathBuf;

use rstest::rstest;
use signstar_config::admin_credentials::AdminCredentials;
use signstar_core::admin_credentials::get_ephemeral_plaintext_credentials;
use testresult::TestResult;

#[rstest]
fn fail_to_load_on_missing_file() -> TestResult {
    let plaintext_file = get_ephemeral_plaintext_credentials();
    if let Err(error) = AdminCredentials::load(PathBuf::from(&plaintext_file).as_path()) {
        assert_eq!(
            error.to_string(),
            format!("No credentials file found at: \"{plaintext_file}\"")
        );
    } else {
        panic!("Did not return an error!")
    }
    Ok(())
}
