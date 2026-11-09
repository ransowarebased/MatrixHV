use crate::server::protocol::{
    DEFAULT_EXEC_TIMEOUT_MS, MAX_FRAME_SIZE, ProtocolError, Request, RequestKind, Response,
    read_response, write_request,
};
use crate::server::{self, DEFAULT_LISTEN_ADDRESS, ServerExit};
use crate::{matrix, output, startup, telemetry};
use serde_json::json;
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
    Exec {
        arguments: Vec<String>,
        timeout_ms: u64,
    },
    Update(Option<PathBuf>),
    Telemetry(telemetry::CaptureOptions),
    TelemetryControl(telemetry::Control),
    TelemetryControlTrace(telemetry::ControlTraceOptions),
    IntelPt {
        operation: String,
        output: Option<PathBuf>,
    },
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

pub fn run(mut arguments: Vec<String>) -> Result<i32, String> {
    output::begin(&mut arguments);
    if output::is_json()
        && arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
        && !arguments.iter().any(|argument| argument == "exec")
    {
        return Err("--json requires a command result; use --help without --json".into());
    }
    if let Some((arguments, remote, timeout, timeout_ms)) = memory_options(&arguments)? {
        if let Some(remote) = remote {
            let status = transact(&remote, timeout, Request::Status)?;
            ensure_kind(&status, RequestKind::Status)?;
            if !status.success {
                return Err(status.message);
            }
            let executable = status_field(&status.message, "executable_path")?;
            let session_query = matches!(arguments.as_slice(), [command, action, ..]
                if command == "session" && action == "query");
            let mut command = vec![executable.to_string()];
            if output::is_json() {
                command.push("--json".into());
            }
            command.extend(arguments);
            let timeout = timeout.max(Duration::from_millis(timeout_ms) + Duration::from_secs(10));
            if session_query && status_field(&status.message, "exec_stream") == Ok("true") {
                return stream_execution(&remote, timeout, command, timeout_ms);
            }
            let response = transact(
                &remote,
                timeout,
                Request::Exec {
                    arguments: command,
                    timeout_ms,
                },
            )?;
            ensure_kind(&response, RequestKind::Exec)?;
            if session_query
                && response.stdout.len() >= server::MAX_CAPTURED_STREAM_SIZE
                && !response.message.starts_with("process timed out")
            {
                output::set_error("REMOTE_OUTPUT_LIMIT", false);
                return Err("remote server reached its output limit; update Neo on the server to stream session queries".into());
            }
            return print_execution(response, true);
        }
        return run_memory(&arguments);
    }
    let Some(options) = parse_options(arguments)? else {
        return Ok(0);
    };
    if output::is_json()
        && matches!(
            &options.action,
            Action::Shell | Action::Serve | Action::ApplyUpdate(_) | Action::Matrix(_)
        )
    {
        return Err("--json requires a noninteractive status, ping, telemetry, PT, memory, startup, update, or exec command".into());
    }
    if let Some(path) = options.cleanup_path.as_deref() {
        startup::remove_stale_updater(path);
    }
    if let Some(remote) = options.remote.as_deref() {
        run_remote(remote, options.timeout, options.action)
    } else {
        run_local(options.action, &options.listen_address)
    }
}

type MemoryOptions = (Vec<String>, Option<String>, Duration, u64);

fn memory_options(arguments: &[String]) -> Result<Option<MemoryOptions>, String> {
    let mut operands = Vec::new();
    let mut remote = None;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut timeout_ms = DEFAULT_EXEC_TIMEOUT_MS;
    let mut timeout_given = false;
    let mut index = 0;
    while index < arguments.len() {
        let option = &arguments[index];
        if option == "exec" && operands.is_empty() {
            return Ok(None);
        }
        if matches!(
            option.as_str(),
            "--remote" | "--timeout" | "--exec-timeout-ms"
        ) {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| format!("{option} requires a value"))?;
            match option.as_str() {
                "--remote" => remote = Some(value.clone()),
                "--timeout" => {
                    timeout = Duration::from_secs(parse_duration(value, "--timeout", 3600)?);
                    timeout_given = true;
                }
                _ => {
                    timeout_ms = parse_duration(value, "--exec-timeout-ms", 3_600_000)?;
                    timeout_given = true;
                }
            }
            index += 2;
        } else {
            operands.push(option.clone());
            index += 1;
            if matches!(
                option.as_str(),
                "--output"
                    | "--kernel-cr3"
                    | "--kernel-image"
                    | "--symbols"
                    | "--pid"
                    | "--cr3"
                    | "--gva"
                    | "--pages"
                    | "--alternate-cr3"
                    | "--lease-ms"
                    | "--process"
                    | "--pattern"
                    | "--start"
                    | "--end"
                    | "--max-hits"
                    | "--token"
                    | "--dr3"
                    | "--dr7-mask"
                    | "--dr7-value"
                    | "--thread-teb"
            ) && index < arguments.len()
            {
                operands.push(arguments[index].clone());
                index += 1;
            }
        }
    }
    if !matches!(
        operands.first().map(String::as_str),
        Some(
            "read"
                | "write"
                | "watch"
                | "context"
                | "session"
                | "syscall"
                | "hook"
                | "debug-registers"
                | "ad-bitmap"
                | "cpuid"
                | "memmap"
                | "modules"
                | "scan"
                | "disasm"
        )
    ) {
        return Ok(None);
    }
    if remote.is_none() && timeout_given {
        return Err("--timeout and --exec-timeout-ms require --remote".into());
    }
    Ok(Some((operands, remote, timeout, timeout_ms)))
}

fn parse_duration(value: &str, option: &str, maximum: u64) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| (1..=maximum).contains(value))
        .ok_or_else(|| format!("{option} must be an integer in 1..={maximum}"))
}

fn run_memory(arguments: &[String]) -> Result<i32, String> {
    if arguments
        .first()
        .is_some_and(|command| command == "session")
        || matches!(
            (
                arguments.first().map(String::as_str),
                arguments.get(1).map(String::as_str)
            ),
            (Some("watch"), Some("record"))
        )
    {
        return crate::investigation::run(arguments);
    }
    if arguments
        .first()
        .is_some_and(|command| matches!(command.as_str(), "memmap" | "modules" | "scan" | "disasm"))
    {
        return crate::analysis_cli::run(arguments);
    }
    if matches!(
        arguments.first().map(String::as_str),
        Some("watch" | "context" | "syscall")
    ) {
        return crate::memory::run_observation(arguments);
    }
    if matches!(
        arguments.first().map(String::as_str),
        Some("hook" | "debug-registers" | "cpuid")
    ) {
        return crate::memory::run_interception(arguments);
    }
    if arguments.first().map(String::as_str) == Some("ad-bitmap") {
        return crate::memory::run_bitmap(arguments);
    }
    if matches!(
        arguments.first().map(String::as_str),
        Some("read" | "write")
    ) {
        return crate::memory::run(arguments);
    }
    Err("unknown memory command".into())
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
            output::text(&format!("{}\n", server::ping_text()))?;
            Ok(0)
        }
        Action::Status => {
            output::text(&server::status_text())?;
            Ok(0)
        }
        Action::Telemetry(options) => {
            telemetry::capture(options, |mode, control| {
                telemetry::request_text(mode as u32, control as u32)
            })?;
            Ok(0)
        }
        Action::TelemetryControl(control) => {
            output::text(&telemetry::request_text(
                telemetry::Mode::General as u32,
                control as u32,
            )?)?;
            Ok(0)
        }
        Action::IntelPt { operation, output } => {
            output::text(&telemetry::intel_pt(&operation, output.as_deref())?)?;
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
        Action::Exec { .. } | Action::Update(_) => {
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
            if output::is_json() {
                output::success(
                    json!({"message": response.message, "time_ms": output::hex(started.elapsed().as_millis() as u64)}),
                )?;
            } else {
                println!(
                    "{} time_ms={}",
                    response.message,
                    started.elapsed().as_millis()
                );
            }
            Ok(0)
        }
        Action::Status => {
            let response = transact(remote, timeout, Request::Status)?;
            ensure_kind(&response, RequestKind::Status)?;
            if !response.success {
                return Err(response.message);
            }
            output::text(&response.message)?;
            Ok(0)
        }
        Action::Exec {
            arguments,
            timeout_ms,
        } => {
            let response = transact(
                remote,
                timeout.max(Duration::from_millis(timeout_ms) + Duration::from_secs(10)),
                Request::Exec {
                    arguments,
                    timeout_ms,
                },
            )?;
            ensure_kind(&response, RequestKind::Exec)?;
            print_execution(response, false)
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
            if output::is_json() {
                output::success(
                    json!({"message": response.message, "source": path, "process_id": status_after.process_id, "binary_fingerprint": status_after.binary_fingerprint}),
                )?;
            } else {
                println!(
                    "{} source={} process_id={} fingerprint={}",
                    response.message,
                    path.display(),
                    status_after.process_id,
                    status_after.binary_fingerprint
                );
            }
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
            output::text(&response.message)?;
            Ok(0)
        }
        Action::Shell
        | Action::Matrix(_)
        | Action::TelemetryControlTrace(_)
        | Action::IntelPt { .. }
        | Action::Serve
        | Action::Install
        | Action::Uninstall
        | Action::ApplyUpdate(_) => Err("the command cannot be used with --remote".to_string()),
    }
}

fn print_execution(response: Response, self_command: bool) -> Result<i32, String> {
    let exit_code = response
        .exit_code
        .unwrap_or(if response.success { 0 } else { 1 });
    if output::is_json() {
        if self_command
            && !response.stdout.is_empty()
            && !response.message.starts_with("process timed out")
        {
            let invalid_output = |message| {
                output::set_error("REMOTE_OUTPUT_INVALID", false);
                message
            };
            let mut rows = Vec::new();
            for line in response.stdout.split(|&byte| byte == b'\n') {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let row: serde_json::Value = serde_json::from_slice(line).map_err(|error| {
                    invalid_output(format!(
                        "remote command did not return complete JSON rows: {error}"
                    ))
                })?;
                let ok = row
                    .get("ok")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or_else(|| invalid_output("remote JSON row has no result status".into()))?;
                rows.push((row, ok));
            }
            if rows.last().map(|(_, ok)| *ok) != Some(response.success) {
                return Err(invalid_output(
                    "remote JSON result does not match the process exit status".into(),
                ));
            }
            for (row, _) in rows {
                output::write(&row)?;
            }
        } else {
            let data = json!({"exit_code": response.exit_code, "stdout": String::from_utf8_lossy(&response.stdout), "stderr": String::from_utf8_lossy(&response.stderr), "stdout_may_be_truncated": response.stdout.len() >= 16 * 1024 * 1024, "stderr_may_be_truncated": response.stderr.len() >= 16 * 1024 * 1024});
            if response.success {
                output::success(data)?;
            } else {
                let (code, _) = output::classify(&response.message);
                output::partial(data, code, &response.message)?;
            }
        }
    } else {
        io::stdout()
            .write_all(&response.stdout)
            .map_err(|error| format!("failed to write process stdout: {error}"))?;
        io::stderr()
            .write_all(&response.stderr)
            .map_err(|error| format!("failed to write process stderr: {error}"))?;
        if !response.success {
            eprintln!("{} exit_code={exit_code}", response.message);
        }
    }
    Ok(exit_code)
}

fn stream_execution(
    remote: &str,
    timeout: Duration,
    arguments: Vec<String>,
    timeout_ms: u64,
) -> Result<i32, String> {
    let (mut stream, id) = send_request(
        remote,
        timeout,
        Request::ExecStream {
            arguments,
            timeout_ms,
        },
    )?;
    let mut pending = Vec::new();
    let mut last_ok = None;
    let json = output::is_json();
    let response = loop {
        let response = receive_response(&mut stream, id)?;
        ensure_kind(&response, RequestKind::ExecStream)?;
        if response.exit_code.is_some() {
            break response;
        }
        if !response.success
            || !response.message.is_empty()
            || response.stdout.is_empty() && response.stderr.is_empty()
        {
            output::set_error("PROTOCOL_ERROR", false);
            return Err("invalid remote execution stream frame".into());
        }
        io::stderr()
            .write_all(&response.stderr)
            .map_err(|error| error.to_string())?;
        if !json {
            io::stdout()
                .write_all(&response.stdout)
                .and_then(|()| io::stdout().flush())
                .map_err(|error| error.to_string())?;
            continue;
        }
        let complete = response
            .stdout
            .iter()
            .rposition(|&byte| byte == b'\n')
            .map_or(0, |last| pending.len() + last + 1);
        pending.extend_from_slice(&response.stdout);
        for line in pending[..complete].split_inclusive(|&byte| byte == b'\n') {
            if line.len() > MAX_FRAME_SIZE {
                output::set_error("REMOTE_OUTPUT_LIMIT", false);
                return Err("remote JSON row exceeds the maximum size".into());
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let row: serde_json::Value = serde_json::from_slice(line).map_err(|error| {
                output::set_error("REMOTE_OUTPUT_INVALID", false);
                format!("invalid JSON row from remote command: {error}")
            })?;
            last_ok = row.get("ok").and_then(serde_json::Value::as_bool);
            if last_ok.is_none() {
                output::set_error("REMOTE_OUTPUT_INVALID", false);
                return Err("remote JSON row has no result status".into());
            }
            output::write(&row)?;
        }
        pending.drain(..complete);
        if pending.len() > MAX_FRAME_SIZE {
            output::set_error("REMOTE_OUTPUT_LIMIT", false);
            return Err("remote JSON row exceeds the maximum size".into());
        }
    };

    let exit_code = response.exit_code.unwrap();
    if response.success != (exit_code == 0)
        || !response.stdout.is_empty()
        || !response.stderr.is_empty()
    {
        output::set_error("PROTOCOL_ERROR", false);
        return Err("invalid terminal frame from remote command".into());
    }
    if json && response.success && (!pending.is_empty() || last_ok != Some(true)) {
        output::set_error("REMOTE_OUTPUT_INVALID", false);
        return Err("remote command did not finish with a complete JSON result".into());
    }
    if !response.success {
        if json && (last_ok != Some(false) || !pending.is_empty() || exit_code == 124) {
            let (code, _) = output::classify(&response.message);
            output::partial(json!({"exit_code": exit_code}), code, &response.message)?;
        } else if !json {
            eprintln!("{} exit_code={exit_code}", response.message);
        }
    }
    Ok(exit_code)
}

fn transact(remote: &str, timeout: Duration, request: Request) -> Result<Response, String> {
    let (mut stream, id) = send_request(remote, timeout, request)?;
    receive_response(&mut stream, id)
}

fn send_request(
    remote: &str,
    timeout: Duration,
    request: Request,
) -> Result<(TcpStream, u64), String> {
    output::clear_error();
    let addresses: Vec<_> = remote
        .to_socket_addrs()
        .map_err(|error| {
            output::set_error("INVALID_REMOTE_ADDRESS", false);
            format!("invalid remote address {remote}: {error}")
        })?
        .collect();
    if addresses.is_empty() {
        output::set_error("INVALID_REMOTE_ADDRESS", false);
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
    let mut stream = connected.ok_or_else(|| {
        output::set_error("CONNECTION_FAILED", true);
        format!("failed to connect to {remote}: {}", last_error.unwrap())
    })?;
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
    write_request(&mut stream, request_id, &request).map_err(transport_error)?;
    Ok((stream, request_id))
}

fn receive_response(stream: &mut TcpStream, request_id: u64) -> Result<Response, String> {
    let (response_id, response) = read_response(stream).map_err(transport_error)?;
    if response_id != request_id {
        output::set_error("PROTOCOL_ERROR", false);
        return Err(format!(
            "response request id mismatch: expected {request_id}, received {response_id}"
        ));
    }
    Ok(response)
}

fn transport_error(error: ProtocolError) -> String {
    let code = match &error {
        ProtocolError::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            "CONNECTION_TIMEOUT"
        }
        ProtocolError::Io(_) => "CONNECTION_LOST",
        _ => "PROTOCOL_ERROR",
    };
    output::set_error(code, false);
    error.to_string()
}

fn ensure_kind(response: &Response, expected: RequestKind) -> Result<(), String> {
    if response.request_kind == expected {
        Ok(())
    } else {
        output::set_error("PROTOCOL_ERROR", false);
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
    let mut exec_timeout_ms = DEFAULT_EXEC_TIMEOUT_MS;
    let mut exec_timeout_given = false;
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
    let mut benchmark = false;
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
            "--exec-timeout-ms" => {
                index += 1;
                exec_timeout_ms = parse_duration(
                    arguments
                        .get(index)
                        .ok_or("--exec-timeout-ms requires milliseconds")?,
                    "--exec-timeout-ms",
                    3_600_000,
                )?;
                exec_timeout_given = true;
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
            "--benchmark" => {
                if benchmark {
                    return Err("--benchmark may be specified only once".to_string());
                }
                benchmark = true;
            }
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
    let matrix_update = positional == ["matrix", "update"];
    if binary.is_some() && !update && !matrix_update {
        return Err("--binary requires --update or matrix update".to_string());
    }
    if apply_update.is_some() && !positional.is_empty() {
        return Err("--apply-update cannot be combined with another command".to_string());
    }
    let telemetry_options_given =
        seconds.is_some() || interval_ms.is_some() || output.is_some() || benchmark;
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
                    "update" => matrix::Command::Update(
                        binary
                            .ok_or_else(|| "matrix update requires --binary PACKAGE".to_string())?,
                    ),
                    value => return Err(format!("unknown matrix command: {value}")),
                })
            }
            Some("matrix") => {
                return Err(
                    "matrix requires on, off, status, or update --binary PACKAGE".to_string(),
                );
            }
            Some("pt") if positional.len() == 2 => {
                let operation = positional[1].as_str();
                if !matches!(operation, "start" | "stop" | "status" | "dump") {
                    return Err(
                        "pt requires start, stop, status, or dump --output DIRECTORY".into(),
                    );
                }
                if seconds.is_some()
                    || interval_ms.is_some()
                    || (operation != "dump" && output.is_some())
                {
                    return Err("pt only accepts --output with dump".into());
                }
                if operation == "dump" && output.is_none() {
                    return Err("pt dump requires --output DIRECTORY".into());
                }
                Action::IntelPt {
                    operation: operation.into(),
                    output: output.clone(),
                }
            }
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
                    None if benchmark => telemetry::Mode::Benchmark,
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
            Some("exec") if positional.len() >= 2 => Action::Exec {
                arguments: positional[1..].to_vec(),
                timeout_ms: exec_timeout_ms,
            },
            Some("exec") => return Err("exec requires an executable".to_string()),
            Some(command) => return Err(format!("unknown command or extra argument: {command}")),
            None if remote.is_some() => Action::Status,
            None if cfg!(target_os = "windows") => Action::Shell,
            None => Action::Serve,
        }
    };
    if benchmark
        && !matches!(&action, Action::Telemetry(options) if options.mode == telemetry::Mode::Benchmark)
    {
        return Err("--benchmark requires telemetry without another mode or control".to_string());
    }
    if !matches!(
        &action,
        Action::Telemetry(_) | Action::TelemetryControlTrace(_) | Action::IntelPt { .. }
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
    if remote.is_some() && matches!(&action, Action::IntelPt { .. }) {
        return Err("Intel PT commands require local execution".into());
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
    if exec_timeout_given && !matches!(&action, Action::Exec { .. }) {
        return Err("--exec-timeout-ms requires exec or a remote memory command".into());
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
    println!(
        "neo cpuid set CR3 [--token TOKEN] --record LEAF SUBLEAF MASK EAX EBX ECX EDX KEEP_EAX KEEP_EBX KEEP_ECX KEEP_EDX [--record ...] [--dr3 ADDRESS --dr7-mask MASK --dr7-value VALUE] [--alternate-cr3 CR3] [--lease-ms MS | --no-lease] [--tsc-offset]\nneo cpuid clear TOKEN | cpuid status\nneo memmap PID|NAME CR3|auto [--resident] [--output PATH]\nneo modules PID|NAME CR3|auto [--sections] [--exports] [--output PATH]\nneo scan PID|NAME CR3|auto --pattern \"48 8B ??\" [--start ADDRESS --end ADDRESS] [--max-hits COUNT] [--disasm] [--output PATH]\nneo disasm PID|NAME CR3|auto ADDRESS SIZE [--output PATH]\nneo read PID|NAME CR3|auto ADDRESS SIZE [--disasm]\nneo watch|context filter TOKEN [--thread-teb TEB] [--rip-include START END] [--rip-exclude START END]\nneo watch fetch TOKEN CPU CURSOR COUNT [--process PID|NAME] [--disasm] [--unwind]\nneo context snapshot TOKEN CPU CURSOR COUNT [--process PID|NAME] [--disasm] [--unwind]\nneo context stack TOKEN CPU SEQUENCE COUNT --unwind [--process PID|NAME]\nneo session set CR3 TOKEN [--sample] [--exceptions MASK] [--region ADDRESS SIZE ...] [--entry ADDRESS --return ADDRESS ...] [--exception-dispatch ADDRESS] [--no-lease | --lease-ms MS]\nneo session clear TOKEN\nneo session record TOKEN --output FILE.jsonl [--seconds N] [--interval-ms N] [--cpu CPU] [--process PID|NAME] [--disasm] [--unwind]\nneo watch record TOKEN --output FILE.jsonl [--seconds N] [--interval-ms N] [--cpu CPU] [--process PID|NAME] [--disasm] [--unwind]\nneo session query FILE.jsonl [--kind KIND] [--cpu CPU] [--sequence N] [--thread-teb TEB] [--invocation ID] [--limit N] [--disasm] [--unwind]\nneo session tree FILE.jsonl [--thread-teb TEB]\nUnwind options include --frames N, --dynamic-list HEAD, and repeatable --table BASE START END ADDRESS COUNT (sorted AMD64 runtime functions). Capture code, function tables and unwind metadata with --region for offline analysis.\nAnalysis accepts --kernel-cr3 CR3 --kernel-image PATH --symbols DIRECTORY, --json and --remote HOST:PORT. Paths refer to the target host.\nADDRESS accepts integers, module!export (including forwarded exports and #ordinals), and module+offset. Symbolic interception addresses require --process PID|NAME.\n--private-shared-data requires a full 4096-byte hook patch at 0x7ffe0000 and a lease; VMFUNC, concurrent writes, persistent data and data-shadow on that page are incompatible.\nCPUID gates are optional on updated hypervisors; specify all three DR options to enable gating. Keep masks preserve native bits before replacement values are ORed.\nFilters use exclusive range ends, exclusions win, and an empty filter clears restrictions. Filters persist within the session and affect future captures. Watch RIP is post-instruction.\nEvent snapshots retain 32 instruction bytes, up to 2048 stack bytes and four selected regions of up to 1024 bytes each. Peer CPUs can still modify shared memory during the VM exit. Probes require an entry address and the caller continuation address after CALL. They share the four debug slots with watchpoints and redirects. Hardware exceptions use a bit mask by x86 vector. --exception-dispatch accepts the address of native AMD64 RtlDispatchException and records the dispatched Windows exception. AMD64 unwind supports version 1 PE and dynamic tables. A missing snapshot range stops unwind with a partial stack. Legacy context stack on older EFI uses live reads and labels them accordingly.\n"
    );
    println!(
        "Use --json with status, ping, telemetry, PT, memory, startup, update, or remote exec. JSON results use {{\"ok\":true,\"data\":...}} or {{\"ok\":false,\"error\":{{\"code\":...,\"message\":...,\"retryable\":...}}}}. All u64 values use fixed-width hexadecimal strings. Telemetry emits one JSON object per sample (JSONL), including --output files. Memory commands accept --remote ADDRESS:PORT; paths refer to the remote host. Use --exec-timeout-ms 1..3600000 before exec, or anywhere with remote memory commands (default 290000 ms). The server terminates the process tree on timeout. Socket waits allow the execution deadline plus cleanup time.\n"
    );
    println!(
        "neo telemetry --benchmark [--seconds 1..3600] [--interval-ms 50..60000] [--output FILE]\nBenchmark measures CPUID leaf 0 from guest to guest, including VM exit, handling and reentry.\nIt pins each available registered CPU and reports raw/calibrated TSC ticks, nanoseconds and min/mean/p50/p95/p99/max.\nCollection settings stay unchanged; compare telemetry disabled/enabled in separate runs.\nAn invariant TSC and clock diagnostics are required; release profiles using TSC compensation first.\nWith --remote, the benchmark runs on the remote server.\n"
    );
    println!(
        "neo hook install CR3 ADDRESS HEX [...] [--alternate-cr3 CR3] [--vmfunc] [--concurrent-writes] [--persistent-data] [--data-shadow] [--lease-ms MS | --no-lease] [--tsc-offset]\nneo hook add TOKEN ADDRESS HEX [...] [--data-shadow] | hook remove TOKEN [ID] | hook list TOKEN\nneo hook context-add TOKEN CR3 [...] | hook context-remove TOKEN CR3 [...] | hook context-list TOKEN\nneo hook renew TOKEN [--lease-ms MS] | hook watch TOKEN [--lease-ms MS] | hook release TOKEN | hook status\nneo debug-registers set CR3 ADDRESS REDIRECT_RIP [...] [--alternate-cr3 CR3] [--lease-ms MS | --no-lease] [--tsc-offset]\nneo debug-registers clear TOKEN | debug-registers status\nneo watch set CR3 TOKEN ADDRESS write|rw LENGTH [...] [--no-lease]\nneo watch fetch TOKEN CPU CURSOR COUNT | watch clear TOKEN\nneo context set CR3 TOKEN [--no-lease] | context snapshot TOKEN CPU CURSOR COUNT\nneo context stack TOKEN CPU SEQUENCE COUNT | context clear TOKEN\nneo syscall set CR3 TOKEN CALLBACK LSTAR [--no-lease] | syscall clear TOKEN\nUse TOKEN=0 for a new profile; successful setup returns the shared current token.\nWatch RIP is the post-access PC. Context stack follows a bounded RBP chain; optimized frames may be omitted.\nVMFUNC uses EAX=0 and ECX=0 (execute) or 1 (data) from unhooked code.\nData shadows keep private page contents, including guest writes allowed by the original PTE.\nOne profile admits the primary CR3 and validated aliases. Conflicting original writes revoke the profile.\nThe default lease is 30 seconds; hook watch renews it until the process exits. --no-lease requires explicit release and does not need a VMX preemption timer.\nTSC compensation is CPU-local and requires an invariant TSC without Hyper-V Reference TSC or scaling. Guest CPU migration can expose clock skew.\n"
    );
    if cfg!(target_os = "windows") {
        println!(
            "Launching neo without a command opens the Matrix interactive shell.\nUse install to register automatic startup at Windows sign-in.\n"
        );
    }
    println!(
        "neo read PID|NAME CR3|auto [ADDRESS SIZE ...] [--kernel-cr3 CR3]\nneo write PID|NAME CR3|auto ADDRESS HEX [ADDRESS HEX ...] [--kernel-cr3 CR3]\nneo ad-bitmap start --pid PID [--gva GVA --pages COUNT]\nneo ad-bitmap start --cr3 CR3 --gva GVA --pages COUNT\nneo ad-bitmap stop SESSION [--output DIRECTORY]\nneo ad-bitmap dump SESSION --output DIRECTORY\nneo ad-bitmap release SESSION | cancel SESSION | status\nneo shell\nneo serve [--listen ADDRESS:PORT]\nneo ping | status | install | uninstall\nneo matrix on | off [--cpu INDEX] | status\nneo matrix update --binary PACKAGE\nneo pt start | stop | status\nneo pt dump --output DIRECTORY\nneo telemetry enable | disable\nneo telemetry control --cpu INDEX --output FILE [--seconds 1..3600]\nneo telemetry | -t [watchdog | eptdiag] [--seconds 1..3600] [--interval-ms 50..60000] [--output FILE]\nneo --remote ADDRESS:PORT [status | ping | telemetry [enable | disable | watchdog | eptdiag] | -t [watchdog | eptdiag] | exec PROGRAM [ARGUMENT ...]]\nneo --remote ADDRESS:PORT --update [--binary PATH]\n\nIntel PT captures VMX root handlers only after pt start; pt dump stops capture and exports per-CPU raw .pt files and decoding metadata. It requires PT/ToPA support in VMX and an available engine.\nCounters and basic records start disabled; use telemetry enable/disable to control collection.\nDisabling collection preserves snapshots and stops watchdog capture.\nWatchdog renews a 15-second lease; its interval must not exceed 5000 ms.\nControl tracing selects a separate observer CPU and saves native context/stack .bin files beside FILE when supported by the EFI.\nThe remote transport is plaintext and unauthenticated."
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
    fn resident_update_is_distinct_from_neo_self_update_and_preserves_the_package_path() {
        let path = std::path::PathBuf::from(r"C:\Matrix Updates\signed.mxcore");
        let arguments = vec![
            "matrix".into(),
            "update".into(),
            "--binary".into(),
            path.display().to_string(),
        ];
        let options = parse_options(arguments.clone()).unwrap().unwrap();
        assert!(matches!(options.action, Action::Matrix(Command::Update(value)) if value == path));
        let own_update = parse_options(vec![
            "--remote".into(),
            "127.0.0.1:4040".into(),
            "--update".into(),
            "--binary".into(),
            path.display().to_string(),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(own_update.action, Action::Update(Some(value)) if value == path));
        assert!(parse_options(vec!["matrix".into(), "update".into()]).is_err());
        for suffix in [
            vec!["--cpu".into(), "0".into()],
            vec!["--update".into()],
            vec!["--remote".into(), "127.0.0.1:4040".into()],
        ] {
            let mut invalid = arguments.clone();
            invalid.extend(suffix);
            assert!(parse_options(invalid).is_err());
        }
    }

    #[test]
    fn intel_pt_requires_explicit_runtime_operation_and_dump_directory() {
        for operation in ["start", "stop", "status"] {
            let options = parse_options(vec!["pt".into(), operation.into()])
                .unwrap()
                .unwrap();
            assert!(matches!(
                options.action,
                Action::IntelPt { output: None, .. }
            ));
        }
        let dump = parse_options(vec![
            "pt".into(),
            "dump".into(),
            "--output".into(),
            "trace".into(),
        ])
        .unwrap()
        .unwrap();
        assert!(
            matches!(dump.action, Action::IntelPt { output: Some(path), .. } if path == std::path::PathBuf::from("trace"))
        );
        for arguments in [
            vec!["pt", "dump"],
            vec!["pt", "invalid"],
            vec!["pt", "start", "--output", "trace"],
            vec!["pt", "start", "--seconds", "1"],
            vec!["--remote", "localhost:4040", "pt", "start"],
        ] {
            assert!(parse_options(arguments.into_iter().map(str::to_owned).collect()).is_err());
        }
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
