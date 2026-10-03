mod commands;
mod matrix;
#[path = "../../../protocol.rs"]
pub mod protocol;
mod server;
mod startup;
mod telemetry;
#[path = "../../../update.rs"]
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
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("neo: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
#[path = "../../../../tests/neo_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "../../../../tests/update_tests.rs"]
mod update_tests;
