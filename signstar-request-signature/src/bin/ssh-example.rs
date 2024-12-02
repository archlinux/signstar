use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use log::info;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let cli = Cli::parse();

    info!("Connecting to {}:{}", cli.host, cli.port);

    let mut ssh = signstar_request_signature::ssh::client::Session::connect(
        cli.known_hosts_file.clone(),
        cli.agent_sock.as_ref(),
        &cli.pubkey,
        cli.username,
        (cli.host, cli.port),
    )
    .await?;
    info!("Connected");

    let code = ssh.call(&cli.command, b"").await?;

    println!("Exitcode: {:?}", code);
    println!("STDOUT: <{}>", String::from_utf8_lossy(&ssh.stdout));
    ssh.close().await?;
    Ok(())
}

#[derive(clap::Parser)]
pub struct Cli {
    #[clap(index = 1)]
    host: String,

    #[clap(long, short, default_value_t = 22)]
    port: u16,

    #[clap(long, short)]
    username: String,

    #[clap(long)]
    pubkey: String,

    #[clap(long)]
    known_hosts_file: PathBuf,

    #[clap(long)]
    agent_sock: PathBuf,

    #[clap(index = 2, required = true)]
    command: String,
}
