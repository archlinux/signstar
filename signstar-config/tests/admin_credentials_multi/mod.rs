use rstest::rstest;
use signstar_config::admin_credentials::AdminCredentials;
use signstar_core::admin_credentials::get_plaintext_credentials_file;
use testresult::TestResult;

#[rstest]
fn fail_to_load_on_missing_file() -> TestResult {
    let credentials_file = get_plaintext_credentials_file();
    if let Err(error) = AdminCredentials::load(credentials_file.as_path()) {
        assert_eq!(
            error.to_string(),
            format!("No credentials file found at: {credentials_file:?}")
        );
    } else {
        panic!("Did not return an error!")
    }
    Ok(())
}
