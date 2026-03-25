use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use clap::Parser;
use sqssh_core::protocol::{CtlRequest, CtlResponse};

#[derive(Parser)]
#[command(name = "sqsshctl", about = "sqssh server control utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Control socket path
    #[arg(short = 's', long, default_value = "/var/run/sqssh/control.sock")]
    socket: PathBuf,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Reload authorized_keys
    ReloadKeys {
        /// Reload all users (root only)
        #[arg(long)]
        all: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("sqsshctl: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let request = match cli.command {
        Command::ReloadKeys { all } => {
            if all {
                CtlRequest::ReloadAllKeys
            } else {
                CtlRequest::ReloadKeys
            }
        }
    };

    // Connect to control socket
    let mut stream = UnixStream::connect(&cli.socket)
        .map_err(|e| format!("failed to connect to {}: {e}", cli.socket.display()))?;

    // Send request (binary)
    let data = request.encode();
    stream.write_all(&data)?;

    // Read response (binary)
    let response = CtlResponse::decode(&mut stream)?;

    match response {
        CtlResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        CtlResponse::Error { message } => {
            Err(message.into())
        }
    }
}
