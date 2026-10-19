//! The command line: one binary, a handful of subcommands.
//!
//! The work is in the library next door (`ai_gateway_proxy`); this is the
//! part that turns arguments into a call and a call into an exit status.

use ai_gateway_proxy::{cli, install, log, socks5, status, uninstall, watchdog};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match cli::parse(&args) {
        Ok(command) => command,
        Err(message) => {
            log::err(&message);
            log::plain("");
            log::plain(cli::USAGE);
            return ExitCode::FAILURE;
        }
    };

    match command {
        cli::Command::Help => {
            log::plain(cli::USAGE);
            ExitCode::SUCCESS
        }
        cli::Command::Version => {
            log::plain(&format!("ai-gateway-proxy {}", cli::VERSION));
            ExitCode::SUCCESS
        }
        cli::Command::Install(options) => match install::run(&options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                log::err(&message);
                ExitCode::FAILURE
            }
        },
        cli::Command::Uninstall(options) => match uninstall::run_with(&options) {
            Ok(_) => ExitCode::SUCCESS,
            Err(message) => {
                log::err(&message);
                ExitCode::FAILURE
            }
        },
        cli::Command::Status => match status::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                log::err(&message);
                ExitCode::FAILURE
            }
        },
        cli::Command::Watchdog => match watchdog::run() {
            Ok(action) => {
                log::plain(&action);
                ExitCode::SUCCESS
            }
            Err(message) => {
                log::err(&message);
                ExitCode::FAILURE
            }
        },
        cli::Command::Serve(options) => match socks5::serve(&options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                log::err(&message);
                ExitCode::FAILURE
            }
        },
    }
}
