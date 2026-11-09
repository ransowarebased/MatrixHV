mod analysis_cli;
mod commands;
mod investigation;
mod matrix;
#[path = "memory_cli.rs"]
mod memory;
mod output;
mod process;
use neo::protocol;
mod server;
mod startup;
mod telemetry;
#[path = "../../update.rs"]
pub mod update;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(target_os = "windows")]
    let result = if arguments.first().map(String::as_str) == Some("--runtime-elevated") {
        commands::run_elevated_matrix(arguments.into_iter().skip(1).collect())
    } else {
        commands::run(arguments)
    };
    #[cfg(not(target_os = "windows"))]
    let result = commands::run(arguments);
    match result {
        Ok(exit_code) => {
            if let Err(error) = output::finish(exit_code) {
                eprintln!("neo: {error}");
                std::process::exit(1);
            }
            std::process::exit(exit_code);
        }
        Err(error) => {
            if output::is_json() {
                if let Err(error) = output::failure(&error) {
                    eprintln!("neo: {error}");
                }
            } else {
                eprintln!("neo: {error}");
            }
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/neo_json_tests.rs"]
mod json_tests;
#[cfg(test)]
#[path = "../../../tests/neo_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "../../../tests/update_tests.rs"]
mod update_tests;

#[cfg(test)]
#[path = "../../../tests/memory_tests.rs"]
mod memory_tests;

#[cfg(test)]
#[path = "../../../tests/tracking_tests.rs"]
mod tracking_tests;

#[cfg(test)]
#[path = "../../../tests/interception_tests.rs"]
mod interception_tests;
