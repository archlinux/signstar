use std::process::ExitCode;

use clap::{Parser, crate_version};
use nethsm_config::{ConfigInteractivity, ConfigSettings, HermeticParallelConfig};
use signstar_configure_build::{
    Error,
    cli::{BIN_NAME, Cli},
    create_system_users,
    ensure_root,
};

fn run_command(cli: Cli) -> Result<(), Error> {
    if cli.version {
        println!("{} {}", BIN_NAME, crate_version!());
        return Ok(());
    }

    ensure_root()?;

    let config = HermeticParallelConfig::new_from_file(
        ConfigSettings::new(
            BIN_NAME.to_string(),
            ConfigInteractivity::NonInteractive,
            None,
        ),
        Some(cli.config.unwrap_or_default().as_ref()),
    )?;

    create_system_users(&config)?;

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = run_command(cli);

    if let Err(error) = result {
        eprintln!("{error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
