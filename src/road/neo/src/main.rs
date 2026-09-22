mod startup;
mod update;

use road_server::{DEFAULT_LISTEN_ADDRESS, ServerExit};
use std::path::PathBuf;

enum Command {
    Serve,
    Ping,
    Status,
    Install,
    Uninstall,
    ApplyUpdate { target: PathBuf },
}

struct Options {
    command: Command,
    listen_address: String,
    cleanup_path: Option<PathBuf>,
}

fn main() {
    let options = match parse_options(std::env::args().skip(1).collect()) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            print_usage();
            std::process::exit(2);
        }
    };

    if let Some(path) = options.cleanup_path.as_deref() {
        update::remove_stale_updater(path);
    }

    let result = match options.command {
        Command::Serve => run_server(&options.listen_address),
        Command::Ping => {
            println!("{}", road_server::ping_text());
            Ok(())
        }
        Command::Status => {
            print!("{}", road_server::status_text());
            Ok(())
        }
        Command::Install => startup::install(&options.listen_address),
        Command::Uninstall => startup::uninstall(),
        Command::ApplyUpdate { target } => {
            update::apply_windows_update(&target, &options.listen_address)
        }
    };

    if let Err(error) = result {
        eprintln!("neo: {error}");
        std::process::exit(1);
    }
}

fn run_server(listen_address: &str) -> Result<(), String> {
    match road_server::serve(listen_address, update::prepare)? {
        ServerExit::Update => update::activate(listen_address),
    }
}

fn parse_options(arguments: Vec<String>) -> Result<Options, String> {
    let mut command = None;
    let mut listen_address = DEFAULT_LISTEN_ADDRESS.to_string();
    let mut cleanup_path = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "serve" => set_command(&mut command, Command::Serve)?,
            "ping" => set_command(&mut command, Command::Ping)?,
            "status" => set_command(&mut command, Command::Status)?,
            "install" => set_command(&mut command, Command::Install)?,
            "uninstall" => set_command(&mut command, Command::Uninstall)?,
            "--listen" => {
                index += 1;
                listen_address = arguments
                    .get(index)
                    .ok_or_else(|| "--listen requires an address".to_string())?
                    .clone();
            }
            "--cleanup" => {
                index += 1;
                cleanup_path = Some(PathBuf::from(
                    arguments
                        .get(index)
                        .ok_or_else(|| "--cleanup requires a path".to_string())?,
                ));
            }
            "--apply-update" => {
                index += 1;
                let target = PathBuf::from(
                    arguments
                        .get(index)
                        .ok_or_else(|| "--apply-update requires a target path".to_string())?,
                );
                set_command(&mut command, Command::ApplyUpdate { target })?;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
        index += 1;
    }
    Ok(Options {
        command: command.unwrap_or(Command::Serve),
        listen_address,
        cleanup_path,
    })
}

fn set_command(slot: &mut Option<Command>, command: Command) -> Result<(), String> {
    if slot.is_some() {
        return Err("only one neo command can be specified".to_string());
    }
    *slot = Some(command);
    Ok(())
}

fn print_usage() {
    println!(
        "neo [serve] [--listen ADDRESS]\nneo ping\nneo status\nneo install [--listen ADDRESS]\nneo uninstall\n\nThe remote transport is plaintext and unauthenticated."
    );
}
