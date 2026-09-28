use crate::server::protocol::{Request, RequestKind, Response, read_response, write_request};
use crate::server::{self, DEFAULT_LISTEN_ADDRESS, ServerExit};
use crate::{matrix, startup, telemetry};
use std::io::{self, BufRead, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

enum Action {
    Shell,
    Matrix(matrix::Command),
    Serve,
    Ping,
    Status,
    Exec(Vec<String>),
    Update(Option<PathBuf>),
    Telemetry(telemetry::CaptureOptions),
    TelemetryControl(telemetry::Control),
    TelemetryControlTrace(telemetry::ControlTraceOptions),
    Install,
    Uninstall,
    ApplyUpdate(PathBuf),
}

struct Options {
    remote: Option<String>,
    timeout: Duration,
    action: Action,
    listen_address: String,
    cleanup_path: Option<PathBuf>,
}

struct RemoteStatus {
    operating_system: String,
    process_id: u32,
    binary_fingerprint: String,
}

pub fn run(arguments: Vec<String>) -> Result<i32, String> {
    let Some(options) = parse_options(arguments)? else {
        return Ok(0);
    };
    if let Some(path) = options.cleanup_path.as_deref() {
        startup::remove_stale_updater(path);
    }
    if let Some(remote) = options.remote.as_deref() {
        run_remote(remote, options.timeout, options.action)
    } else {
        run_local(options.action, &options.listen_address)
    }
}

#[cfg(target_os = "windows")]
pub fn run_elevated_matrix(mut arguments: Vec<String>) -> Result<i32, String> {
    if arguments.len() < 4 {
        return Err("the elevated helper requires a result channel and a MatrixHV command".into());
    }
    let port: u16 = arguments[0]
        .parse()
        .map_err(|_| "invalid UAC result channel port".to_string())?;
    if port == 0 {
        return Err("the UAC result channel port must be nonzero".into());
    }
    let nonce: u128 = arguments[1]
        .parse()
        .map_err(|_| "invalid UAC result channel nonce".to_string())?;
    arguments.drain(..2);
    let command = parse_elevated_matrix(arguments)?;
    matrix::execute_elevated(command, port, nonce)
}

#[cfg(target_os = "windows")]
fn parse_elevated_matrix(arguments: Vec<String>) -> Result<matrix::Command, String> {
    let options = parse_options(arguments)?
        .ok_or_else(|| "the elevated helper requires a MatrixHV command".to_string())?;
    match options.action {
        Action::Matrix(command) if options.remote.is_none() && options.cleanup_path.is_none() => {
            Ok(command)
        }
        _ => Err("the elevated helper only accepts local MatrixHV commands".into()),
    }
}

fn run_local(action: Action, listen_address: &str) -> Result<i32, String> {
    match action {
        Action::Shell => startup::run_shell(),
        Action::Matrix(command) => {
            if command == matrix::Command::On
                && !confirm_matrix_on(&mut io::stdin().lock(), &mut io::stdout().lock())
                    .map_err(|error| format!("failed to confirm MatrixHV activation: {error}"))?
            {
                println!("MatrixHV activation cancelled.");
                return Ok(0);
            }
            print!("{}", matrix::execute(command)?);
            Ok(0)
        }
        Action::Serve => {
            match server::serve(listen_address, startup::prepare, telemetry::request_text)? {
                ServerExit::Update => startup::activate(listen_address)?,
            }
            Ok(0)
        }
        Action::Ping => {
            println!("{}", server::ping_text());
            Ok(0)
        }
        Action::Status => {
            print!("{}", server::status_text());
            Ok(0)
        }
        Action::Telemetry(options) => {
            telemetry::capture(options, |mode, control| {
                telemetry::request_text(mode as u32, control as u32)
            })?;
            Ok(0)
        }
        Action::TelemetryControl(control) => {
            print!(
                "{}",
                telemetry::request_text(telemetry::Mode::General as u32, control as u32)?
            );
            Ok(0)
        }
        Action::TelemetryControlTrace(options) => {
            telemetry::capture_control(options)?;
            Ok(0)
        }
        Action::Install => {
            startup::install(listen_address)?;
            Ok(0)
        }
        Action::Uninstall => {
            startup::uninstall()?;
            Ok(0)
        }
        Action::ApplyUpdate(target) => {
            startup::apply_windows_update(&target, listen_address)?;
            Ok(0)
        }
        Action::Exec(_) | Action::Update(_) => {
            Err("the command requires --remote ADDRESS:PORT".to_string())
        }
    }
}

pub(crate) fn confirm_matrix_on(
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<bool> {
    writeln!(
        output,
        "WARNING: Turning MatrixHV ON can crash running emulators or virtual machines.\nClose them before continuing."
    )?;
    loop {
        write!(output, "Turn MatrixHV ON? [Y/N] (default N): ")?;
        output.flush()?;
        let mut answer = String::new();
        if input.read_line(&mut answer)? == 0 {
            return Ok(false);
        }
        match answer.trim() {
            answer if answer.eq_ignore_ascii_case("y") => return Ok(true),
            answer if answer.is_empty() || answer.eq_ignore_ascii_case("n") => return Ok(false),
            _ => writeln!(output, "Enter Y or N.")?,
        }
    }
}

fn run_remote(remote: &str, timeout: Duration, action: Action) -> Result<i32, String> {
    match action {
        Action::Ping => {
            let started = Instant::now();
            let response = transact(remote, timeout, Request::Ping)?;
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
            let response = transact(remote, timeout, Request::Status)?;
            ensure_kind(&response, RequestKind::Status)?;
            if !response.success {
                return Err(response.message);
            }
            print!("{}", response.message);
            Ok(0)
        }
        Action::Exec(arguments) => {
            let response = transact(remote, timeout, Request::Exec { arguments })?;
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
            let status_before = remote_status(remote, timeout)?;
            let path = match binary_path {
                Some(path) => path,
                None => select_adjacent_binary(&status_before.operating_system)?,
            };
            let binary = std::fs::read(&path)
                .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
            let expected_fingerprint = fingerprint(&binary);
            let response = transact(remote, timeout, Request::Update { binary })?;
            ensure_kind(&response, RequestKind::Update)?;
            if !response.success {
                return Err(response.message);
            }
            let status_after = wait_for_update(
                remote,
                timeout,
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
        Action::Telemetry(options) => {
            telemetry::capture(options, |mode, control| {
                let response = transact(
                    remote,
                    timeout,
                    Request::Telemetry {
                        mode: mode as u32,
                        control: control as u32,
                    },
                )?;
                ensure_kind(&response, RequestKind::Telemetry)?;
                if response.success {
                    Ok(response.message)
                } else {
                    Err(response.message)
                }
            })?;
            Ok(0)
        }
        Action::TelemetryControl(control) => {
            let response = transact(
                remote,
                timeout,
                Request::Telemetry {
                    mode: telemetry::Mode::General as u32,
                    control: control as u32,
                },
            )?;
            ensure_kind(&response, RequestKind::Telemetry)?;
            if !response.success {
                return Err(response.message);
            }
            print!("{}", response.message);
            Ok(0)
        }
        Action::Shell
        | Action::Matrix(_)
        | Action::TelemetryControlTrace(_)
        | Action::Serve
        | Action::Install
        | Action::Uninstall
        | Action::ApplyUpdate(_) => Err("the command cannot be used with --remote".to_string()),
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
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve neo executable: {error}"))?;
    let parent = executable
        .parent()
        .ok_or_else(|| "neo executable has no parent directory".to_string())?;
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

fn parse_options(arguments: Vec<String>) -> Result<Option<Options>, String> {
    let mut remote = None;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut timeout_given = false;
    let mut listen_address = DEFAULT_LISTEN_ADDRESS.to_string();
    let mut listen_given = false;
    let mut cleanup_path = None;
    let mut apply_update = None;
    let mut update = false;
    let mut binary = None;
    let mut seconds = None;
    let mut interval_ms = None;
    let mut output = None;
    let mut selected_cpu = None;
    let mut positional = Vec::new();
    let mut index = 0;
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
                let timeout_seconds: u64 = arguments
                    .get(index)
                    .ok_or_else(|| "--timeout requires seconds".to_string())?
                    .parse()
                    .map_err(|_| "--timeout must be an integer number of seconds".to_string())?;
                if timeout_seconds == 0 {
                    return Err("--timeout must be greater than zero".to_string());
                }
                timeout = Duration::from_secs(timeout_seconds);
                timeout_given = true;
            }
            "--listen" => {
                index += 1;
                listen_address = arguments
                    .get(index)
                    .ok_or_else(|| "--listen requires ADDRESS:PORT".to_string())?
                    .clone();
                listen_given = true;
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
                apply_update =
                    Some(PathBuf::from(arguments.get(index).ok_or_else(|| {
                        "--apply-update requires a target path".to_string()
                    })?));
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
            "--seconds" => {
                index += 1;
                let duration: u64 = arguments
                    .get(index)
                    .ok_or_else(|| "--seconds requires a duration".to_string())?
                    .parse()
                    .map_err(|_| "--seconds must be an integer".to_string())?;
                if !(1..=3600).contains(&duration) {
                    return Err("--seconds must be in 1..=3600".to_string());
                }
                seconds = Some(duration);
            }
            "--interval-ms" => {
                index += 1;
                let interval: u64 = arguments
                    .get(index)
                    .ok_or_else(|| "--interval-ms requires milliseconds".to_string())?
                    .parse()
                    .map_err(|_| "--interval-ms must be an integer".to_string())?;
                if !(50..=60_000).contains(&interval) {
                    return Err("--interval-ms must be in 50..=60000".to_string());
                }
                interval_ms = Some(interval);
            }
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(
                    arguments
                        .get(index)
                        .ok_or_else(|| "--output requires a path".to_string())?,
                ));
            }
            "--cpu" => {
                index += 1;
                if selected_cpu.is_some() {
                    return Err("--cpu may be specified only once".to_string());
                }
                let cpu: u32 = arguments
                    .get(index)
                    .ok_or_else(|| "--cpu requires a processor index".to_string())?
                    .parse()
                    .map_err(|_| "--cpu must be a processor index".to_string())?;
                if cpu >= 64 {
                    return Err("--cpu must be in 0..64".to_string());
                }
                selected_cpu = Some(cpu);
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(None);
            }
            "-t" if positional.is_empty() => positional.push("telemetry".to_string()),
            "exec" if positional.is_empty() => {
                positional.push("exec".to_string());
                positional.extend_from_slice(&arguments[index + 1..]);
                break;
            }
            value if value.starts_with('-') => return Err(format!("unknown option: {value}")),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    if update && (!positional.is_empty() || apply_update.is_some()) {
        return Err("--update cannot be combined with another command".to_string());
    }
    if binary.is_some() && !update {
        return Err("--binary requires --update".to_string());
    }
    if apply_update.is_some() && !positional.is_empty() {
        return Err("--apply-update cannot be combined with another command".to_string());
    }
    let telemetry_options_given = seconds.is_some() || interval_ms.is_some() || output.is_some();
    let action = if let Some(target) = apply_update {
        Action::ApplyUpdate(target)
    } else if update {
        Action::Update(binary)
    } else {
        match positional.first().map(String::as_str) {
            Some("matrix") if positional.len() == 2 => {
                Action::Matrix(match positional[1].as_str() {
                    "on" => matrix::Command::On,
                    "off" => selected_cpu
                        .map(matrix::Command::OffProcessor)
                        .unwrap_or(matrix::Command::Off),
                    "status" => matrix::Command::Status,
                    value => return Err(format!("unknown matrix command: {value}")),
                })
            }
            Some("matrix") => return Err("matrix requires on, off, or status".to_string()),
            Some("serve") if positional.len() == 1 => Action::Serve,
            Some("shell") if positional.len() == 1 => Action::Shell,
            Some("ping") if positional.len() == 1 => Action::Ping,
            Some("status") if positional.len() == 1 => Action::Status,
            Some("install") if positional.len() == 1 => Action::Install,
            Some("uninstall") if positional.len() == 1 => Action::Uninstall,
            Some("telemetry") if positional.len() == 2 && positional[1] == "control" => {
                if interval_ms.is_some() {
                    return Err(
                        "control tracing polls continuously and does not accept --interval-ms"
                            .into(),
                    );
                }
                Action::TelemetryControlTrace(telemetry::ControlTraceOptions {
                    cpu: selected_cpu
                        .ok_or_else(|| "control tracing requires --cpu".to_string())?,
                    seconds: seconds.unwrap_or(60),
                    output: output
                        .clone()
                        .ok_or_else(|| "control tracing requires --output".to_string())?,
                })
            }
            Some("telemetry")
                if positional.len() == 2
                    && matches!(positional[1].as_str(), "enable" | "disable") =>
            {
                Action::TelemetryControl(if positional[1] == "enable" {
                    telemetry::Control::Enable
                } else {
                    telemetry::Control::Disable
                })
            }
            Some("telemetry") if positional.len() <= 2 => {
                let mode = match positional.get(1).map(String::as_str) {
                    None => telemetry::Mode::General,
                    Some("watchdog") => telemetry::Mode::Watchdog,
                    Some("eptdiag") => telemetry::Mode::EptDiagnostics,
                    Some(value) => return Err(format!("unknown telemetry mode: {value}")),
                };
                if interval_ms.is_some() && seconds.is_none() {
                    return Err("--interval-ms requires --seconds".to_string());
                }
                Action::Telemetry(telemetry::CaptureOptions {
                    mode,
                    seconds,
                    interval: Duration::from_millis(interval_ms.unwrap_or(200)),
                    output,
                })
            }
            Some("exec") if positional.len() >= 2 => Action::Exec(positional[1..].to_vec()),
            Some("exec") => return Err("exec requires an executable".to_string()),
            Some(command) => return Err(format!("unknown command or extra argument: {command}")),
            None if remote.is_some() => Action::Status,
            None if cfg!(target_os = "windows") => Action::Shell,
            None => Action::Serve,
        }
    };
    if !matches!(
        &action,
        Action::Telemetry(_) | Action::TelemetryControlTrace(_)
    ) && telemetry_options_given
    {
        return Err("telemetry options require the telemetry command".to_string());
    }
    if selected_cpu.is_some()
        && !matches!(
            &action,
            Action::Matrix(matrix::Command::OffProcessor(_)) | Action::TelemetryControlTrace(_)
        )
    {
        return Err("--cpu requires matrix off or telemetry control".to_string());
    }
    if remote.is_some() && (listen_given || cleanup_path.is_some()) {
        return Err("--listen and --cleanup require local server mode".to_string());
    }
    if remote.is_some() && matches!(&action, Action::Matrix(_)) {
        return Err("matrix commands require the local Windows runtime bridge".to_string());
    }
    if remote.is_some() && matches!(&action, Action::Shell) {
        return Err("the interactive shell requires local execution".to_string());
    }
    if remote.is_some() && matches!(&action, Action::TelemetryControlTrace(_)) {
        return Err("control tracing requires a local observer CPU".to_string());
    }
    if remote.is_none() && timeout_given {
        return Err("--timeout requires --remote".to_string());
    }
    if listen_given
        && !matches!(
            &action,
            Action::Serve | Action::Install | Action::ApplyUpdate(_)
        )
    {
        return Err("--listen requires serve or install".to_string());
    }
    Ok(Some(Options {
        remote,
        timeout,
        action,
        listen_address,
        cleanup_path,
    }))
}

fn print_usage() {
    if cfg!(target_os = "windows") {
        println!(
            "Launching neo without a command opens the Matrix interactive shell.\nUse install to register automatic startup at Windows sign-in.\n"
        );
    }
    println!(
        "neo shell\nneo serve [--listen ADDRESS:PORT]\nneo ping | status | install | uninstall\nneo matrix on | off [--cpu INDEX] | status\nneo telemetry enable | disable\nneo telemetry control --cpu INDEX --output FILE [--seconds 1..3600]\nneo telemetry | -t [watchdog | eptdiag] [--seconds 1..3600] [--interval-ms 50..60000] [--output FILE]\nneo --remote ADDRESS:PORT [status | ping | telemetry [enable | disable | watchdog | eptdiag] | -t [watchdog | eptdiag] | exec PROGRAM [ARGUMENT ...]]\nneo --remote ADDRESS:PORT --update [--binary PATH]\n\nCounters and basic records start disabled; use telemetry enable/disable to control collection.\nDisabling collection preserves snapshots and stops watchdog capture.\nWatchdog renews a 15-second lease; its interval must not exceed 5000 ms.\nControl tracing selects a separate observer CPU and saves native context/stack .bin files beside FILE when supported by the EFI.\nThe remote transport is plaintext and unauthenticated."
    );
}

#[cfg(test)]
mod tests {
    use super::{Action, parse_options};
    use crate::matrix::Command;

    #[test]
    fn default_launch_opens_windows_shell() {
        let options = parse_options(Vec::new()).unwrap().unwrap();
        if cfg!(target_os = "windows") {
            assert!(matches!(options.action, Action::Shell));
        } else {
            assert!(matches!(options.action, Action::Serve));
        }
    }

    #[test]
    fn startup_child_and_remote_client_do_not_reinstall() {
        let server = parse_options(vec![
            "serve".to_string(),
            "--listen".to_string(),
            "127.0.0.1:4041".to_string(),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(server.action, Action::Serve));
        assert_eq!(server.listen_address, "127.0.0.1:4041");
        let client = parse_options(vec!["--remote".to_string(), "127.0.0.1:4040".to_string()])
            .unwrap()
            .unwrap();
        assert!(matches!(client.action, Action::Status));
    }

    #[test]
    fn matrix_commands_require_an_explicit_local_operation() {
        for (word, expected) in [
            ("on", Command::On),
            ("off", Command::Off),
            ("status", Command::Status),
        ] {
            let options = parse_options(vec!["matrix".into(), word.into()])
                .unwrap()
                .unwrap();
            assert!(matches!(options.action, Action::Matrix(command) if command == expected));
        }
        assert!(parse_options(vec!["matrix".into()]).is_err());
        assert!(parse_options(vec!["matrix".into(), "toggle".into()]).is_err());
        let one_cpu = parse_options(vec![
            "matrix".into(),
            "off".into(),
            "--cpu".into(),
            "0".into(),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(
            one_cpu.action,
            Action::Matrix(Command::OffProcessor(0))
        ));
        assert!(
            parse_options(vec![
                "matrix".into(),
                "on".into(),
                "--cpu".into(),
                "0".into(),
            ])
            .is_err()
        );
        assert!(
            parse_options(vec![
                "matrix".into(),
                "off".into(),
                "--cpu".into(),
                "64".into(),
            ])
            .is_err()
        );
        assert!(
            parse_options(vec![
                "--remote".into(),
                "127.0.0.1:4040".into(),
                "matrix".into(),
                "off".into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn control_trace_requires_a_local_target_and_output_file() {
        let arguments = vec![
            "telemetry".into(),
            "control".into(),
            "--cpu".into(),
            "0".into(),
            "--output".into(),
            "control.txt".into(),
        ];
        let options = parse_options(arguments.clone()).unwrap().unwrap();
        assert!(matches!(
            options.action,
            Action::TelemetryControlTrace(trace) if trace.cpu == 0 && trace.seconds == 60
        ));
        assert!(parse_options(arguments[..4].to_vec()).is_err());
        let mut remote = vec!["--remote".into(), "127.0.0.1:4040".into()];
        remote.extend(arguments);
        assert!(parse_options(remote).is_err());
    }
}
