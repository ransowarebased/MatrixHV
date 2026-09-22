use road_server::protocol::{Request, RequestKind, Response, read_response, write_request};
use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

enum Action {
    Ping,
    Status,
    Exec(Vec<String>),
    Update(Option<PathBuf>),
}

struct Options {
    remote: String,
    timeout: Duration,
    action: Action,
}

struct RemoteStatus {
    operating_system: String,
    process_id: u32,
    binary_fingerprint: String,
}

fn main() {
    let options = match parse_options(std::env::args().skip(1).collect()) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("control: {error}");
            print_usage();
            std::process::exit(2);
        }
    };

    let result = run(options);
    match result {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("control: {error}");
            std::process::exit(1);
        }
    }
}

fn run(options: Options) -> Result<i32, String> {
    match options.action {
        Action::Ping => {
            let started = Instant::now();
            let response = transact(&options.remote, options.timeout, Request::Ping)?;
            ensure_kind(&response, RequestKind::Ping)?;
            if !response.success {
                return Err(response.message);
            }
            println!(
                "{} time_ms={}",
                response.message,
                started.elapsed().as_millis()
            );
            Ok(0)
        }
        Action::Status => {
            let response = transact(&options.remote, options.timeout, Request::Status)?;
            ensure_kind(&response, RequestKind::Status)?;
            if !response.success {
                return Err(response.message);
            }
            print!("{}", response.message);
            Ok(0)
        }
        Action::Exec(arguments) => {
            let response = transact(
                &options.remote,
                options.timeout,
                Request::Exec { arguments },
            )?;
            ensure_kind(&response, RequestKind::Exec)?;
            io::stdout()
                .write_all(&response.stdout)
                .map_err(|error| format!("failed to write process stdout: {error}"))?;
            io::stderr()
                .write_all(&response.stderr)
                .map_err(|error| format!("failed to write process stderr: {error}"))?;
            if !response.message.is_empty() && !response.success {
                if let Some(exit_code) = response.exit_code {
                    eprintln!("{} exit_code={exit_code}", response.message);
                } else {
                    eprintln!("{}", response.message);
                }
            }
            Ok(response
                .exit_code
                .unwrap_or(if response.success { 0 } else { 1 }))
        }
        Action::Update(binary_path) => {
            let status_before = remote_status(&options.remote, options.timeout)?;
            let path = match binary_path {
                Some(path) => path,
                None => select_adjacent_binary(&status_before.operating_system)?,
            };
            let binary = std::fs::read(&path)
                .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
            let expected_fingerprint = fingerprint(&binary);
            let response = transact(&options.remote, options.timeout, Request::Update { binary })?;
            ensure_kind(&response, RequestKind::Update)?;
            if !response.success {
                return Err(response.message);
            }
            let status_after = wait_for_update(
                &options.remote,
                options.timeout,
                status_before.process_id,
                &expected_fingerprint,
            )?;
            println!(
                "{} source={} process_id={} fingerprint={}",
                response.message,
                path.display(),
                status_after.process_id,
                status_after.binary_fingerprint
            );
            Ok(0)
        }
    }
}

fn transact(remote: &str, timeout: Duration, request: Request) -> Result<Response, String> {
    let addresses: Vec<_> = remote
        .to_socket_addrs()
        .map_err(|error| format!("invalid remote address {remote}: {error}"))?
        .collect();
    if addresses.is_empty() {
        return Err(format!("remote address {remote} did not resolve"));
    }
    let mut last_error = None;
    let mut connected = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut stream = connected
        .ok_or_else(|| format!("failed to connect to {remote}: {}", last_error.unwrap()))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("failed to configure TCP_NODELAY: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("failed to configure read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("failed to configure write timeout: {error}"))?;
    let request_id = request_id();
    write_request(&mut stream, request_id, &request).map_err(|error| error.to_string())?;
    let (response_id, response) = read_response(&mut stream).map_err(|error| error.to_string())?;
    if response_id != request_id {
        return Err(format!(
            "response request id mismatch: expected {request_id}, received {response_id}"
        ));
    }
    Ok(response)
}

fn ensure_kind(response: &Response, expected: RequestKind) -> Result<(), String> {
    if response.request_kind == expected {
        Ok(())
    } else {
        Err(format!(
            "response kind mismatch: expected {expected:?}, received {:?}",
            response.request_kind
        ))
    }
}

fn remote_status(remote: &str, timeout: Duration) -> Result<RemoteStatus, String> {
    let status = transact(remote, timeout, Request::Status)?;
    ensure_kind(&status, RequestKind::Status)?;
    if !status.success {
        return Err(status.message);
    }
    let operating_system = status_field(&status.message, "os")?.to_string();
    let process_id = status_field(&status.message, "process_id")?
        .parse()
        .map_err(|_| "remote status reported an invalid process id".to_string())?;
    let binary_fingerprint = status_field(&status.message, "binary_fingerprint")?.to_string();
    Ok(RemoteStatus {
        operating_system,
        process_id,
        binary_fingerprint,
    })
}

fn status_field<'a>(status: &'a str, key: &str) -> Result<&'a str, String> {
    let prefix = format!("{key}=");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| format!("remote status did not report {key}"))
}

fn select_adjacent_binary(target_os: &str) -> Result<PathBuf, String> {
    let file_name = match target_os {
        "windows" => "neo.exe",
        "linux" => "neo",
        other => return Err(format!("updates are not supported for remote OS {other}")),
    };
    let controller = std::env::current_exe()
        .map_err(|error| format!("failed to resolve control.exe: {error}"))?;
    let parent = controller
        .parent()
        .ok_or_else(|| "control.exe has no parent directory".to_string())?;
    Ok(parent.join(file_name))
}

fn wait_for_update(
    remote: &str,
    timeout: Duration,
    previous_process_id: u32,
    expected_fingerprint: &str,
) -> Result<RemoteStatus, String> {
    let deadline = Instant::now() + timeout.min(Duration::from_secs(30));
    let probe_timeout = timeout.min(Duration::from_secs(2));
    let mut last_observation = "agent did not reconnect".to_string();
    while Instant::now() < deadline {
        match remote_status(remote, probe_timeout) {
            Ok(status)
                if status.process_id != previous_process_id
                    && status.binary_fingerprint == expected_fingerprint =>
            {
                return Ok(status);
            }
            Ok(status) => {
                last_observation = format!(
                    "process_id={} fingerprint={}",
                    status.process_id, status.binary_fingerprint
                );
            }
            Err(error) => last_observation = error,
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "update was staged but not verified: expected a new process with fingerprint {expected_fingerprint}; last observation: {last_observation}"
    ))
}

fn fingerprint(bytes: &[u8]) -> String {
    let mut fingerprint = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        fingerprint ^= u64::from(*byte);
        fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{fingerprint:016x}")
}

fn request_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn parse_options(arguments: Vec<String>) -> Result<Options, String> {
    if arguments.first().map(String::as_str) != Some("neo") {
        return Err("the first argument must be neo".to_string());
    }
    let mut remote = None;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut update = false;
    let mut binary = None;
    let mut positional = Vec::new();
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--remote" => {
                index += 1;
                remote = Some(
                    arguments
                        .get(index)
                        .ok_or_else(|| "--remote requires ADDRESS:PORT".to_string())?
                        .clone(),
                );
            }
            "--timeout" => {
                index += 1;
                let seconds: u64 = arguments
                    .get(index)
                    .ok_or_else(|| "--timeout requires seconds".to_string())?
                    .parse()
                    .map_err(|_| "--timeout must be an integer number of seconds".to_string())?;
                if seconds == 0 {
                    return Err("--timeout must be greater than zero".to_string());
                }
                timeout = Duration::from_secs(seconds);
            }
            "--update" => update = true,
            "--binary" => {
                index += 1;
                binary = Some(PathBuf::from(
                    arguments
                        .get(index)
                        .ok_or_else(|| "--binary requires a path".to_string())?,
                ));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    let remote = remote.ok_or_else(|| "--remote ADDRESS:PORT is required".to_string())?;
    let action = if update {
        if !positional.is_empty() {
            return Err("--update cannot be combined with ping, status, or exec".to_string());
        }
        Action::Update(binary)
    } else {
        if binary.is_some() {
            return Err("--binary requires --update".to_string());
        }
        match positional.first().map(String::as_str) {
            Some("ping") if positional.len() == 1 => Action::Ping,
            Some("status") if positional.len() == 1 => Action::Status,
            Some("exec") if positional.len() >= 2 => Action::Exec(positional[1..].to_vec()),
            Some("exec") => return Err("exec requires an executable".to_string()),
            Some(command) => return Err(format!("unknown command: {command}")),
            None => return Err("ping, status, exec, or --update is required".to_string()),
        }
    };
    Ok(Options {
        remote,
        timeout,
        action,
    })
}

fn print_usage() {
    println!(
        "control neo --remote ADDRESS:PORT ping\ncontrol neo --remote ADDRESS:PORT status\ncontrol neo --remote ADDRESS:PORT exec PROGRAM [ARGUMENT ...]\ncontrol neo --remote ADDRESS:PORT --update [--binary PATH]\n\nThe remote transport is plaintext and unauthenticated."
    );
}

#[cfg(test)]
mod tests {
    use super::{fingerprint, status_field};

    #[test]
    fn fingerprint_uses_stable_fnv1a_encoding() {
        assert_eq!(fingerprint(b""), "cbf29ce484222325");
        assert_eq!(fingerprint(b"hello"), "a430d84680aabd0b");
    }

    #[test]
    fn status_fields_are_read_by_exact_key() {
        let status = "process_id=42\nbinary_fingerprint=abcd\n";
        assert_eq!(status_field(status, "process_id").unwrap(), "42");
        assert_eq!(status_field(status, "binary_fingerprint").unwrap(), "abcd");
    }
}
