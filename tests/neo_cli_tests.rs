use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct ServerProcess(Child);

struct TelemetryState<'a> {
    executable: &'a std::path::Path,
    address: String,
    enabled: bool,
}

impl Drop for TelemetryState<'_> {
    fn drop(&mut self) {
        let _ = Command::new(self.executable)
            .args([
                "--remote",
                &self.address,
                "telemetry",
                if self.enabled { "enable" } else { "disable" },
            ])
            .output();
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn json_cli_preserves_envelopes_for_local_remote_memory_and_timeouts() {
    let executable = env!("CARGO_BIN_EXE_neo");
    let local = Command::new(executable)
        .args(["status", "--json"])
        .output()
        .unwrap();
    assert!(local.status.success());
    assert!(local.stderr.is_empty());
    let status: serde_json::Value = serde_json::from_slice(&local.stdout).unwrap();
    assert_eq!(status["ok"], true);
    assert_eq!(status["data"]["agent"], "neo");
    assert_eq!(status["data"]["exec_timeout"], true);
    assert!(status["data"]["matrixhv_present"].is_boolean());
    assert!(status["data"]["matrixhv_protocol"].is_number());
    assert_eq!(
        status["data"]["binary_fingerprint"].as_str().unwrap().len(),
        18
    );

    let invalid = Command::new(executable)
        .args(["--json", "read"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(invalid.stderr.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(error["ok"], false);
    assert_eq!(error["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(error["error"]["retryable"], false);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let _server = ServerProcess(
        Command::new(executable)
            .args(["serve", "--listen", &address.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_err() {
        assert!(Instant::now() < deadline, "neo server did not start");
        thread::sleep(Duration::from_millis(20));
    }
    let address = address.to_string();
    let remote = Command::new(executable)
        .args(["--remote", &address, "status", "--json"])
        .output()
        .unwrap();
    assert!(remote.status.success());
    assert!(remote.stderr.is_empty());
    let status: serde_json::Value = serde_json::from_slice(&remote.stdout).unwrap();
    assert_eq!(status["ok"], true);
    assert_eq!(status["data"]["agent"], "neo");

    for command in [
        "read",
        "write",
        "watch",
        "context",
        "syscall",
        "hook",
        "debug-registers",
        "ad-bitmap",
        "cpuid",
        "memmap",
        "modules",
        "scan",
        "disasm",
    ] {
        let remote = Command::new(executable)
            .args([command, "--remote", &address, "--json"])
            .output()
            .unwrap();
        assert!(!remote.status.success(), "{command}");
        assert!(remote.stderr.is_empty(), "{command}: {:?}", remote.stderr);
        let result: serde_json::Value = serde_json::from_slice(&remote.stdout).unwrap();
        assert_eq!(result["ok"], false, "{command}");
        assert_eq!(
            result["error"]["code"], "INVALID_ARGUMENT",
            "{command}: {result}"
        );
    }

    for arguments in [
        vec!["scan", "123", "auto", "--pattern", "GG"],
        vec!["watch", "filter", "1", "--rip-include", "2", "1"],
        vec!["cpuid", "set", "0x2000"],
        vec![
            "context",
            "stack",
            "1",
            "0",
            "1",
            "0",
            "--unwind",
            "--process",
            "123",
        ],
    ] {
        let remote = Command::new(executable)
            .args(["--remote", &address, "--json"])
            .args(&arguments)
            .output()
            .unwrap();
        assert!(!remote.status.success(), "{arguments:?}");
        assert!(remote.stderr.is_empty());
        let result: serde_json::Value = serde_json::from_slice(&remote.stdout).unwrap();
        assert_eq!(
            result["error"]["code"], "INVALID_ARGUMENT",
            "{arguments:?}: {result}"
        );
    }

    #[cfg(target_os = "windows")]
    let sleeper = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Start-Sleep -Seconds 60",
    ];
    #[cfg(not(target_os = "windows"))]
    let sleeper = ["sh", "-c", "sleep 60"];
    let started = Instant::now();
    let timeout = Command::new(executable)
        .args([
            "--remote",
            &address,
            "--json",
            "--exec-timeout-ms",
            "50",
            "exec",
        ])
        .args(sleeper)
        .output()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(timeout.status.code(), Some(124));
    assert!(timeout.stderr.is_empty());
    let result: serde_json::Value = serde_json::from_slice(&timeout.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], "EXEC_TIMEOUT");
    assert_eq!(result["error"]["retryable"], false);
    assert_eq!(result["data"]["exit_code"], 124);
}

#[test]
fn one_neo_binary_serves_remote_status_and_ping() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let executable = env!("CARGO_BIN_EXE_neo");
    let server = ServerProcess(
        Command::new(executable)
            .args(["serve", "--listen", &address.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_err() {
        assert!(Instant::now() < deadline, "neo server did not start");
        thread::sleep(Duration::from_millis(20));
    }

    let status = Command::new(executable)
        .args(["--remote", &address.to_string(), "status"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let status_text = String::from_utf8(status.stdout).unwrap();
    assert!(status_text.contains("agent=neo\n"));
    assert!(status_text.contains("matrixhv_protocol="));
    assert!(status_text.contains("process_id="));
    assert!(status_text.contains("binary_fingerprint="));
    assert!(status_text.contains("capabilities="));
    assert!(status_text.contains("logical_processor_count="));
    let telemetry_state =
        status_text
            .contains("telemetry_control=true\n")
            .then(|| TelemetryState {
                executable: std::path::Path::new(executable),
                address: address.to_string(),
                enabled: status_text.contains("telemetry_enabled=1\n"),
            });
    let protocol = status_text
        .lines()
        .find_map(|line| line.strip_prefix("matrixhv_protocol="))
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let supports_telemetry =
        status_text.contains("matrixhv_present=true\n") && (4..=7).contains(&protocol);
    let telemetry_format = if protocol >= 5 {
        "format=matrixhv-telemetry-v3"
    } else {
        "format=matrixhv-telemetry-v2"
    };

    let ping = Command::new(executable)
        .args(["--remote", &address.to_string(), "ping"])
        .output()
        .unwrap();
    assert!(ping.status.success());
    assert!(
        String::from_utf8(ping.stdout)
            .unwrap()
            .starts_with("pong time_ms=")
    );

    let missing_program = Command::new(executable)
        .args([
            "--remote",
            &address.to_string(),
            "exec",
            "matrixhv-command-that-does-not-exist",
        ])
        .output()
        .unwrap();
    assert!(!missing_program.status.success());
    assert!(
        String::from_utf8(missing_program.stderr)
            .unwrap()
            .contains("failed to start")
    );

    let telemetry = Command::new(executable)
        .args(["--remote", &address.to_string(), "telemetry"])
        .output()
        .unwrap();
    if supports_telemetry {
        assert!(telemetry.status.success());
        assert!(
            String::from_utf8(telemetry.stdout)
                .unwrap()
                .contains(telemetry_format)
        );
    } else {
        assert!(!telemetry.status.success());
        let error = String::from_utf8(telemetry.stderr).unwrap();
        assert!(
            error.contains("MatrixHV is not present") || error.contains("unsupported MatrixHV")
        );
    }

    for mode in ["watchdog", "eptdiag"] {
        for command in ["telemetry", "-t"] {
            let output = Command::new(executable)
                .args(["--remote", &address.to_string(), command, mode])
                .output()
                .unwrap();
            if supports_telemetry {
                if mode == "watchdog" && status_text.contains("telemetry_enabled=0\n") {
                    assert!(!output.status.success());
                    assert!(
                        String::from_utf8(output.stderr)
                            .unwrap()
                            .contains("telemetry is disabled")
                    );
                    continue;
                }
                assert!(output.status.success());
                assert!(
                    String::from_utf8(output.stdout)
                        .unwrap()
                        .contains(&format!("mode={mode}\n"))
                );
            } else {
                assert!(!output.status.success());
                let error = String::from_utf8(output.stderr).unwrap();
                assert!(
                    error.contains("MatrixHV is not present")
                        || error.contains("unsupported MatrixHV")
                );
            }
        }
    }

    for control in ["enable", "disable"] {
        let output = Command::new(executable)
            .args(["--remote", &address.to_string(), "telemetry", control])
            .output()
            .unwrap();
        if status_text.contains("telemetry_control=true\n") {
            assert!(output.status.success());
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains(telemetry_format));
            assert!(text.contains(&format!(
                ".telemetry_enabled={}\n",
                u8::from(control == "enable")
            )));
        } else {
            assert!(!output.status.success());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(
                error.contains("MatrixHV is not present")
                    || error.contains("unsupported MatrixHV")
                    || error.contains("does not support telemetry enable/disable")
            );
        }
    }

    for arguments in [
        vec!["telemetry", "enable", "--seconds", "1"],
        vec!["telemetry", "disable", "--output", "unused.txt"],
    ] {
        let output = Command::new(executable).args(arguments).output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("telemetry options require")
        );
    }

    let invalid = Command::new(executable)
        .args(["-t", "watchdog", "--seconds", "1", "--interval-ms", "6000"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(
        String::from_utf8(invalid.stderr)
            .unwrap()
            .contains("must not exceed 5000 ms")
    );

    drop(telemetry_state);
    drop(server);
}

#[test]
fn investigation_reopens_offline_and_unwinds_jit_frames_from_captured_regions() {
    use serde_json::{Value, json};
    use std::io::Write;

    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../builds/tests/neo");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("investigation-{}.jsonl", std::process::id()));
    let mut file = std::fs::File::create(&path).unwrap();
    let rows = [
        json!({"type":"session", "format":"neo-investigation-v1", "catalog": {
            "modules":[], "dynamic_list":null, "dynamic":[
                {"base":4096,"start":4096,"end":4352,"address":8192,"count":1,"kind":0}
            ]
        }}),
        json!({"type":"event","kind":"entry","invocation":"0x1","parent":"0x0","address":"0x1010",
            "context":{"cpu":"0x1","sequence":"0x4","thread_teb":"0x5000","cpl":"0x3",
                "rip":"0x1010","rsp":"0x3000","rax":"0x0","rcx":"0x0","rdx":"0x0","rbx":"0x0",
                "rbp":"0x0","rsi":"0x0","rdi":"0x0","r8":"0x0","r9":"0x0","r10":"0x0",
                "r11":"0x0","r12":"0x0","r13":"0x0","r14":"0x0","r15":"0x0"},
            "segments":[{"address":"0x1010","requested":32,"status":0,"bytes":"90"},
                {"address":"0x3000","requested":8,"status":0,"bytes":"0000000000000000"},
                {"address":"0x2000","requested":12,"status":0,"bytes":"000000000001000000110000"},
                {"address":"0x2100","requested":4,"status":0,"bytes":"01000000"},
                {"address":"0x0","requested":0,"status":0,"bytes":""},
                {"address":"0x0","requested":0,"status":0,"bytes":""}]}),
        json!({"type":"event","kind":"return","invocation":"0x1","parent":"0x0","address":"0x1010",
            "context":{"cpu":"0x0","sequence":"0x3","thread_teb":"0x5000"}}),
        json!({"type":"end","complete":true}),
    ];
    for row in rows {
        writeln!(file, "{row}").unwrap();
    }
    drop(file);
    let run = |operation: &str, extra: &[&str]| {
        let result = Command::new(env!("CARGO_BIN_EXE_neo"))
            .args(["session", operation, path.to_str().unwrap(), "--json"])
            .args(extra)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        String::from_utf8(result.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>()
    };
    let result = run("query", &["--unwind", "--disasm", "--kind", "entry"]);
    assert_eq!(result[0]["data"]["unwind"]["complete"], true, "{result:?}");
    assert_eq!(
        result[0]["data"]["unwind"]["frames"][0]["method"],
        "dynamic_pdata"
    );
    assert_eq!(result[0]["data"]["instructions"][0]["text"], "nop");
    let result = run("tree", &[]);
    assert_eq!(result[0]["data"]["calls"][0]["status"], "returned");
    assert_eq!(result[0]["data"]["calls"][0]["entry"]["cpu"], "0x1");
    assert_eq!(result[0]["data"]["calls"][0]["end"]["cpu"], "0x0");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let address_text = address.to_string();
    let executable = env!("CARGO_BIN_EXE_neo");
    let _server = ServerProcess(
        Command::new(executable)
            .args(["serve", "--listen", &address_text])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_err() {
        assert!(Instant::now() < deadline, "server did not bind");
        thread::sleep(Duration::from_millis(10));
    }
    let output = Command::new(executable)
        .args([
            "--remote",
            &address_text,
            "--json",
            "session",
            "query",
            path.to_str().unwrap(),
            "--unwind",
            "--kind",
            "entry",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let rows: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["data"]["unwind"]["complete"], true);
    assert_eq!(rows[1]["data"]["type"], "query_summary");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn remote_investigation_query_streams_all_1500_events_past_the_capture_limit() {
    use serde_json::{Value, json};
    use std::io::{BufWriter, Write};

    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../builds/tests/neo");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("large-investigation-{}.jsonl", std::process::id()));
    let mut journal = BufWriter::new(std::fs::File::create(&path).unwrap());
    writeln!(
        journal,
        "{}",
        json!({
            "type": "session", "format": "neo-investigation-v1",
            "catalog": {"modules": [], "dynamic": [], "dynamic_list": null},
        })
    )
    .unwrap();
    let payload = "\u{e1}0123456789".repeat(1100);
    for sequence in 1..=1500 {
        writeln!(
            journal,
            "{}",
            json!({
                "type": "event", "kind": "watch",
                "context": {"sequence": format!("0x{sequence:016x}"), "cpu": "0x0"},
                "payload": payload,
            })
        )
        .unwrap();
    }
    writeln!(journal, "{}", json!({"type": "end", "complete": true})).unwrap();
    journal.flush().unwrap();
    drop(journal);

    let executable = env!("CARGO_BIN_EXE_neo");
    let arguments = ["session", "query", path.to_str().unwrap(), "--json"];
    let local = Command::new(executable).args(arguments).output().unwrap();
    assert!(local.status.success());
    assert!(local.stdout.len() > 16 * 1024 * 1024);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let address_text = address.to_string();
    let _server = ServerProcess(
        Command::new(executable)
            .args(["serve", "--listen", &address_text])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_err() {
        assert!(Instant::now() < deadline, "server did not bind");
        thread::sleep(Duration::from_millis(10));
    }
    let remote = |extra: &[&str]| {
        Command::new(executable)
            .args(["--remote", &address_text])
            .args(extra)
            .args(arguments)
            .output()
            .unwrap()
    };
    let result = remote(&[]);
    assert!(
        result.status.success(),
        "remote exit {:?}, output bytes {}, stderr {}",
        result.status.code(),
        result.stdout.len(),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        result.stdout == local.stdout,
        "remote and local JSONL differ"
    );
    let mut rows = result
        .stdout
        .strip_suffix(b"\n")
        .unwrap()
        .split(|&byte| byte == b'\n');
    assert_eq!(
        rows.next_back()
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .unwrap()["data"]["events"],
        "0x00000000000005dc"
    );
    assert_eq!(rows.count(), 1500);

    let result = remote(&["--exec-timeout-ms", "1"]);
    assert_eq!(result.status.code(), Some(124));
    let terminal: Value = serde_json::from_slice(
        result
            .stdout
            .strip_suffix(b"\n")
            .unwrap()
            .rsplit(|&byte| byte == b'\n')
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(terminal["error"]["code"], "EXEC_TIMEOUT");
    std::fs::remove_file(path).unwrap();
}
