use clap::Parser;
use signstar_request_signature::{
    Error,
    Request,
    Response,
    cli::{Cli, SendCommand},
    ssh::client::ConnectOptions,
};

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

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let args = Cli::parse();

    match args {
        Cli::Prepare(prepare) => {
            Request::for_file(prepare.input)?.to_writer(std::io::stdout())?;
        }
        Cli::Send(send_command) => {
            send_request_via_ssh(send_command)
                .await?
                .to_writer(std::io::stdout())?;
        }
    }
    Ok(())
}
