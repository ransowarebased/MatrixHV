use crate::output;
use crate::server::protocol::{Request, read_request, write_request};
use neo::memory::Transfer;
use std::io::Write;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn analysis_packets_validate_cli_fields_and_preserve_json_option_values() {
    let args = |values: &[&str]| {
        values
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>()
    };
    let mut arguments = args(&[
        "cpuid",
        "set",
        "0x2000",
        "--record",
        "1",
        "0",
        "0",
        "1",
        "2",
        "4",
        "8",
        "0",
        "0",
        "0",
        "0",
        "--dr3",
        "0x3000",
        "--dr7-mask",
        "255",
        "--dr7-value",
        "64",
    ]);
    let bytes = crate::memory::cpuid_packet(&arguments).unwrap();
    assert_eq!(neo::protocol::memory::quad(&bytes, 24), 0x3000);
    assert_eq!(neo::protocol::memory::quad(&bytes, 144), 255);
    arguments.push("--no-lease".into());
    arguments.extend(args(&["--lease-ms", "100"]));
    assert!(crate::memory::cpuid_packet(&arguments).is_err());
    let bytes = crate::memory::filter_packet(&args(&[
        "watch",
        "filter",
        "1",
        "--thread-teb",
        "0x3000",
        "--rip-include",
        "0x1000",
        "0x2000",
        "--rip-exclude",
        "0x1100",
        "0x1200",
    ]))
    .unwrap();
    assert_eq!(neo::protocol::memory::word(&bytes, 32), 2);
    assert_eq!(neo::protocol::memory::quad(&bytes, 24), 0x3000);
    assert!(
        crate::memory::filter_packet(&args(&[
            "context",
            "filter",
            "1",
            "--rip-include",
            "2",
            "1"
        ]))
        .is_err()
    );
    let mut arguments = args(&["scan", "123", "auto", "--pattern", "--json", "--json"]);
    output::begin(&mut arguments);
    assert!(output::is_json());
    assert_eq!(
        arguments,
        args(&["scan", "123", "auto", "--pattern", "--json"])
    );
}

#[test]
fn u64_fields_and_memory_results_preserve_every_bit() {
    let mut arguments = vec!["--json".into()];
    output::begin(&mut arguments);
    let fields = output::fields(
        "matrixhv_protocol=8\nlogical_processor_count=64\ntelemetry_enabled=1\ncpu0.rip=18446744073709551615\ncpu0.cr3=0xffff800000001000\ncapabilities=0x12\nbinary_fingerprint=ffffffffffffffff\n",
    );
    assert_eq!(fields["matrixhv_protocol"], 8);
    assert_eq!(fields["logical_processor_count"], 64);
    assert_eq!(fields["telemetry_enabled"], true);
    assert_eq!(fields["cpu0.rip"], "0xffffffffffffffff");
    assert_eq!(fields["cpu0.cr3"], "0xffff800000001000");
    assert_eq!(fields["capabilities"], "0x0000000000000012");
    assert_eq!(fields["binary_fingerprint"], "0xffffffffffffffff");
    let results = crate::memory::transfers_json(&[
        Transfer {
            address: u64::MAX - 7,
            status: 0,
            transferred: 4,
            requested: 8,
            bytes: vec![0, 1, 0xfe, 0xff],
        },
        Transfer {
            address: 0x2000,
            status: 14,
            transferred: 8,
            requested: 8,
            bytes: Vec::new(),
        },
        Transfer {
            address: 0x3000,
            status: crate::protocol::memory::ROAD_STATUS_DEMAND_ZERO,
            transferred: 2,
            requested: 2,
            bytes: vec![0, 0],
        },
    ]);
    assert_eq!(results[0]["address"], "0xfffffffffffffff8");
    assert_eq!(results[0]["data"], "0001feff");
    assert_eq!(results[0]["code"], "PARTIAL_TRANSFER");
    assert_eq!(results[1]["code"], "WRITE_COMMITTED_MERGE_CONFLICT");
    assert_eq!(results[1]["retryable"], false);
    assert_eq!(results[1]["transferred"], 8);
    assert_eq!(results[2]["complete"], true);
}

#[test]
fn json_flag_preserves_child_arguments_and_option_values() {
    for (input, expected, enabled) in [
        (
            vec![
                "--json",
                "--remote",
                "localhost:4040",
                "exec",
                "program",
                "--json",
            ],
            vec!["--remote", "localhost:4040", "exec", "program", "--json"],
            true,
        ),
        (
            vec!["telemetry", "--output", "--json"],
            vec!["telemetry", "--output", "--json"],
            false,
        ),
        (
            vec!["read", "exec", "auto", "--json"],
            vec!["read", "exec", "auto"],
            true,
        ),
        (vec!["--json", "status", "--json"], vec!["status"], true),
    ] {
        let mut arguments = input.into_iter().map(str::to_string).collect();
        output::begin(&mut arguments);
        assert_eq!(arguments, expected);
        assert_eq!(output::is_json(), enabled);
    }
}

#[test]
fn error_codes_preserve_retry_and_committed_write_semantics() {
    output::begin(&mut Vec::new());
    for (message, expected) in [
        (
            "MatrixHV memory transport is unavailable; boot the updated EFI",
            ("HYPERVISOR_INACTIVE", false),
        ),
        ("MatrixHV is not present", ("HYPERVISOR_INACTIVE", false)),
        ("process 123 was not found", ("PROCESS_NOT_FOUND", false)),
        ("interception lease expired", ("LEASE_EXPIRED", false)),
        ("process timed out after 100 ms", ("EXEC_TIMEOUT", false)),
        (
            "I/O error: operation timed out",
            ("CONNECTION_TIMEOUT", false),
        ),
        (
            "failed to connect to localhost",
            ("CONNECTION_FAILED", true),
        ),
        ("unknown option: --invalid", ("INVALID_ARGUMENT", false)),
    ] {
        assert_eq!(output::classify(message), expected);
    }
    assert_eq!(output::memory_status(10), ("SESSION_BUSY", true));
    assert_eq!(
        output::memory_status(14),
        ("WRITE_COMMITTED_MERGE_CONFLICT", false)
    );
    assert_eq!(
        output::memory_status(15),
        ("WRITE_COMMITTED_REFRESH_FAILED", false)
    );
}

#[test]
fn telemetry_jsonl_files_keep_full_width_values_and_escaped_text() {
    let mut arguments = vec!["--json".into()];
    output::begin(&mut arguments);
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../builds/neo-json-tests");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!(
        "telemetry-{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    crate::telemetry::capture(crate::telemetry::CaptureOptions {
        mode: crate::telemetry::Mode::General,
        seconds: None,
        interval: Duration::from_millis(200),
        output: Some(path.clone()),
    }, |_, _| Ok("cpu0.rip=0xffffffffffffffff\ncpu0.exits=18446744073709551615\nmessage=quoted \"value\" and \\slash\n".into())).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 1);
    let value: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["cpu0.rip"], "0xffffffffffffffff");
    assert_eq!(value["data"]["cpu0.exits"], "0xffffffffffffffff");
    assert_eq!(value["data"]["message"], "quoted \"value\" and \\slash");
    assert!(
        value["data"]["sample_unix_ms"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn observation_and_hook_json_reject_truncation_and_keep_register_precision() {
    use crate::protocol::memory::*;
    assert!(crate::memory::observation_json(&[], WATCH_FETCH).is_err());
    assert!(crate::memory::interception_json(&[]).is_err());
    let mut bytes = vec![0u8; HEADER_BYTES + WATCH_RECORD_BYTES];
    bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[HEADER_BYTES + 24..HEADER_BYTES + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[HEADER_BYTES + 208..HEADER_BYTES + 216].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    let data = crate::memory::observation_json(&bytes, WATCH_FETCH).unwrap();
    assert_eq!(data["token"], "0xffffffffffffffff");
    assert_eq!(data["records"][0]["rip"], "0xffffffffffffffff");
    assert_eq!(data["records"][0]["address"], "0xfffffffffffffffe");
    bytes[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(crate::memory::observation_json(&bytes, WATCH_FETCH).is_err());
}

#[test]
fn execution_frames_accept_legacy_deadlines_and_reject_invalid_extensions() {
    let request = Request::Exec {
        arguments: vec!["program".into(), "argument with spaces".into()],
        timeout_ms: 1234,
    };
    let mut frame = Vec::new();
    write_request(&mut frame, u64::MAX, &request).unwrap();
    assert_eq!(
        read_request(&mut frame.as_slice()).unwrap(),
        (u64::MAX, request)
    );
    let mut legacy = frame.clone();
    legacy.truncate(legacy.len() - 8);
    let size = (legacy.len() - 20) as u32;
    legacy[8..12].copy_from_slice(&size.to_le_bytes());
    let (_, Request::Exec { timeout_ms, .. }) = read_request(&mut legacy.as_slice()).unwrap()
    else {
        panic!("wrong request kind")
    };
    assert_eq!(timeout_ms, 290_000);
    let (_, default_request) = read_request(&mut legacy.as_slice()).unwrap();
    let mut encoded = Vec::new();
    write_request(&mut encoded, u64::MAX, &default_request).unwrap();
    assert_eq!(encoded, legacy);
    for timeout in [0u64, 3_600_001, u64::MAX] {
        let mut invalid = frame.clone();
        let offset = invalid.len() - 8;
        invalid[offset..].copy_from_slice(&timeout.to_le_bytes());
        assert!(read_request(&mut invalid.as_slice()).is_err());
        let mut encoded = Vec::new();
        assert!(
            write_request(
                &mut encoded,
                1,
                &Request::Exec {
                    arguments: vec!["program".into()],
                    timeout_ms: timeout
                }
            )
            .is_err()
        );
        assert!(encoded.is_empty());
    }
    frame.pop();
    let size = (frame.len() - 20) as u32;
    frame[8..12].copy_from_slice(&size.to_le_bytes());
    assert!(read_request(&mut frame.as_slice()).is_err());
}

fn launch_leaf() -> std::process::Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "json_tests::exec_leaf_fixture",
        "--ignored",
        "--nocapture",
    ]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
    let child = command.spawn().unwrap();
    println!("fixture_pid={}", child.id());
    std::io::stdout().flush().unwrap();
    child
}

#[test]
#[ignore = "subprocess fixture invoked by execution deadline regression tests"]
fn exec_leaf_fixture() {
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
#[ignore = "subprocess fixture invoked by execution deadline regression tests"]
fn exec_waiting_fixture() {
    let mut child = launch_leaf();
    child.wait().unwrap();
}

#[test]
#[ignore = "subprocess fixture invoked by execution deadline regression tests"]
fn exec_exited_fixture() {
    drop(launch_leaf());
}

#[test]
fn execution_deadline_kills_descendants_even_after_the_parent_exits() {
    for fixture in [
        "json_tests::exec_waiting_fixture",
        "json_tests::exec_exited_fixture",
    ] {
        let started = Instant::now();
        let response = crate::server::execute(
            vec![
                std::env::current_exe().unwrap().display().to_string(),
                "--exact".into(),
                fixture.into(),
                "--ignored".into(),
                "--nocapture".into(),
            ],
            1000,
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!response.success, "{response:?}");
        assert_eq!(response.exit_code, Some(124), "{response:?}");
        assert!(response.message.starts_with("process timed out"));
        let stdout = String::from_utf8(response.stdout).unwrap();
        let pid: u32 = stdout
            .lines()
            .find_map(|line| line.strip_prefix("fixture_pid="))
            .expect("fixture must launch its descendant before timeout")
            .parse()
            .unwrap();
        #[cfg(target_os = "windows")]
        unsafe {
            use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
            use windows_sys::Win32::System::Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if !process.is_null() {
                let mut exit_code = 0;
                let queried = GetExitCodeProcess(process, &mut exit_code);
                CloseHandle(process);
                assert_ne!(queried, 0);
                assert_ne!(
                    exit_code, STILL_ACTIVE as u32,
                    "descendant survived the deadline"
                );
            }
        }
        #[cfg(not(target_os = "windows"))]
        assert!(pid != 0);
    }
}
