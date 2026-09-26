mod commands;
mod server;
mod startup;
mod telemetry;

fn main() {
    match commands::run(std::env::args().skip(1).collect()) {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("neo: {error}");
            std::process::exit(1);
        }
    }
}
