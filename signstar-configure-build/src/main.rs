use clap::{crate_version, Parser};
use nethsm_config::{ConfigInteractivity, ConfigSettings, HermeticParallelConfig};
use signstar_configure_build::{
    cli::{Cli, BIN_NAME},
    create_system_users,
    ensure_root,
    Error,
};

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

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
