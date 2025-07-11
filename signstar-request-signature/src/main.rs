//! Application for the creation of signing requests and their optional sending via SSH.

use std::process::ExitCode;

use clap::Parser;
use signstar_common::logging::setup_logging;
use signstar_request_signature::{
    Error,
    Request,
    Response,
    cli::{Cli, Command, SendCommand},
    ssh::client::ConnectOptions,
};

/// Sends a signing request over SSH.
///
/// # Errors
///
/// Returns an error if
/// - [`ConnectOptions`] can not be created from the `send_command`,
/// - an SSH session can not be created when connecting using the [`ConnectOptions`],
/// - sending a signing request for a file fails,
/// - receiving a signature for a signing request fails,
/// - closing the SSH connection fails.
async fn send_request_via_ssh(send_command: SendCommand) -> Result<Response, Error> {
    let options = ConnectOptions::target(send_command.host, send_command.port)
        .append_known_hosts_from_file(send_command.known_hosts)?
        .client_auth_agent_sock(send_command.agent_socket)
        .client_auth_public_key(send_command.user_public_key)?
        .user(send_command.user);
    let mut session = options.connect().await?;
    let response: Response = session
        .send(&Request::for_file(send_command.input)?)
        .await?;
    session.close().await?;
    Ok(response)
}

async fn run_command(args: Cli) -> Result<(), Error> {
    match args.command {
        Command::Prepare(prepare) => {
            Request::for_file(prepare.input)?.to_writer(std::io::stdout())?;
        }
        Command::Send(send_command) => {
            send_request_via_ssh(send_command)
                .await?
                .to_writer(std::io::stdout())?;
        }
    }
    Ok(())
}

/// Prepares and optionally sends a signing request.
///
/// # Errors
///
/// Returns an error if
/// - setting logging fails,
/// - preparing signing request fails,
/// - sending signing request fails.
#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();

    if let Err(error) = setup_logging(args.verbosity) {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    let result = run_command(args).await;

    if let Err(error) = result {
        log::error!(error:err; "Processing signing request failed: {error:#?}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
