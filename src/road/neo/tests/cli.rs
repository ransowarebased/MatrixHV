use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct ServerProcess(Child);

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

    drop(server);
}
