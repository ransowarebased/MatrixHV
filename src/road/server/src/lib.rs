mod hypervisor;
pub mod protocol;

use protocol::{Request, RequestKind, Response, read_request, write_response};
use std::io;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

pub const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:4040";
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CAPTURED_STREAM_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum ServerExit {
    Update,
}

pub fn serve(
    listen_address: &str,
    mut prepare_update: impl FnMut(&[u8]) -> Result<(), String>,
) -> Result<ServerExit, String> {
    let listener = TcpListener::bind(listen_address)
        .map_err(|error| format!("failed to bind {listen_address}: {error}"))?;
    println!("neo listening on {listen_address} (plaintext, unauthenticated)");

    loop {
        let (mut stream, peer_address) = listener
            .accept()
            .map_err(|error| format!("failed to accept a connection: {error}"))?;
        if let Err(error) = configure_stream(&stream) {
            eprintln!("connection from {peer_address} rejected: {error}");
            continue;
        }
        match handle_connection(&mut stream, &mut prepare_update) {
            Ok(true) => return Ok(ServerExit::Update),
            Ok(false) => {}
            Err(error) => eprintln!("connection from {peer_address} failed: {error}"),
        }
    }
}

fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))
}

fn handle_connection(
    stream: &mut TcpStream,
    prepare_update: &mut impl FnMut(&[u8]) -> Result<(), String>,
) -> Result<bool, String> {
    let (request_id, request) = read_request(stream).map_err(|error| error.to_string())?;
    let (response, update) = match request {
        Request::Ping => (Response::success(RequestKind::Ping, "pong"), None),
        Request::Status => (Response::success(RequestKind::Status, status_text()), None),
        Request::Exec { arguments } => (execute(arguments), None),
        Request::Update { binary } => {
            let response =
                match validate_update_binary(&binary).and_then(|()| prepare_update(&binary)) {
                    Ok(()) => Response::success(RequestKind::Update, "update accepted"),
                    Err(error) => Response::failure(RequestKind::Update, error),
                };
            let update = response.success.then_some(());
            (response, update)
        }
    };
    write_response(stream, request_id, &response).map_err(|error| error.to_string())?;
    Ok(update.is_some())
}

pub fn status_text() -> String {
    let status = hypervisor::query();
    let binary_fingerprint = current_binary_fingerprint()
        .map(|fingerprint| format!("{fingerprint:016x}"))
        .unwrap_or_else(|_| "unavailable".to_string());
    format!(
        "agent=neo\nversion={}\nprocess_id={}\nbinary_fingerprint={}\nos={}\narch={}\nhypervisor_present={}\nhypervisor_vendor={}\nmatrixhv_present={}\nmatrixhv_protocol={}\n",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        binary_fingerprint,
        std::env::consts::OS,
        std::env::consts::ARCH,
        status.hypervisor_present,
        status.hypervisor_vendor,
        status.matrixhv_present,
        status.matrixhv_protocol,
    )
}

fn current_binary_fingerprint() -> Result<u64, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve the neo executable: {error}"))?;
    let mut file = std::fs::File::open(&executable)
        .map_err(|error| format!("failed to open {}: {error}", executable.display()))?;
    let mut fingerprint = 0xcbf2_9ce4_8422_2325u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read {}: {error}", executable.display()))?;
        if count == 0 {
            return Ok(fingerprint);
        }
        for byte in &buffer[..count] {
            fingerprint ^= u64::from(*byte);
            fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

pub fn ping_text() -> String {
    "pong".to_string()
}

fn execute(arguments: Vec<String>) -> Response {
    let Some((program, program_arguments)) = arguments.split_first() else {
        return Response::failure(RequestKind::Exec, "no executable was provided");
    };
    match Command::new(program).args(program_arguments).output() {
        Ok(output) => {
            let exit_code = output.status.code();
            let success = output.status.success();
            Response {
                request_kind: RequestKind::Exec,
                success,
                exit_code,
                message: if success {
                    "process completed".to_string()
                } else {
                    "process failed".to_string()
                },
                stdout: truncate(output.stdout),
                stderr: truncate(output.stderr),
            }
        }
        Err(error) => Response::failure(
            RequestKind::Exec,
            format!("failed to start {program}: {error}"),
        ),
    }
}

fn truncate(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() > MAX_CAPTURED_STREAM_SIZE {
        bytes.truncate(MAX_CAPTURED_STREAM_SIZE);
    }
    bytes
}

fn validate_update_binary(binary: &[u8]) -> Result<(), String> {
    if binary.is_empty() {
        return Err("update binary is empty".to_string());
    }
    #[cfg(target_os = "windows")]
    if !binary.starts_with(b"MZ") {
        return Err("update is not a Windows PE executable".to_string());
    }
    #[cfg(target_os = "linux")]
    if !binary.starts_with(b"\x7fELF") {
        return Err("update is not a Linux ELF executable".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{execute, status_text};

    #[test]
    fn status_is_machine_readable() {
        let status = status_text();
        assert!(status.contains("agent=neo\n"));
        assert!(status.contains("process_id="));
        assert!(status.contains("binary_fingerprint="));
        assert!(status.contains("os="));
        assert!(status.contains("matrixhv_present="));
    }

    #[test]
    fn missing_executable_is_reported_without_a_shell() {
        let response = execute(vec!["matrixhv-command-that-does-not-exist".to_string()]);
        assert!(!response.success);
        assert!(response.message.contains("failed to start"));
    }
}
