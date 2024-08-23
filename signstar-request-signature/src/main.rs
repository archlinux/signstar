use std::time::SystemTime;

use clap::Parser;
use rand::Rng;
use serde_json::Value;
use sha2::Digest;
use signstar_request_signature::{cli::Cli, Request, Required, SignatureRequestOutput};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let hasher = {
        let mut hasher = sha2::Sha512::new();
        std::io::copy(&mut std::fs::File::open(&args.input)?, &mut hasher)?;
        hasher
    };
    let required = Required {
        input: hasher.into(),
        output: SignatureRequestOutput::new_openpgp_v4(),
    };

    // Add "grease" so that the server can handle any optional data
    // See: https://lobste.rs/s/utmsph/age_plugins#c_i76hkd
    // See: https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417
    let grease: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();

    Request {
        version: semver::Version::new(1, 0, 0),
        required,
        optional: vec![
            (
                grease,
                Value::String(
                    "https://gitlab.archlinux.org/archlinux/signstar/-/merge_requests/43"
                        .to_string(),
                ),
            ),
            (
                "request-time".into(),
                Value::Number(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)?
                        .as_secs()
                        .into(),
                ),
            ),
            (
                "file-name".into(),
                args.input
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(Into::into)
                    .unwrap_or(Value::Null),
            ),
        ]
        .into_iter()
        .collect(),
    }
    .to_writer(std::io::stdout())?;

    Ok(())
}
