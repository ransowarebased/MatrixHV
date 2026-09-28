#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
mod control_trace {
    use crate::telemetry::{
        NATIVE_SNAPSHOT_FIELDS, NativeSnapshotLayout, control_stage_name, native_snapshot_fields,
        save_native_frame,
    };
    use std::arch::x86_64::CpuidResult;
    use std::io::Write;

    fn layout() -> NativeSnapshotLayout {
        NativeSnapshotLayout::from_cpuid(CpuidResult {
            eax: 16592,
            ebx: 208,
            ecx: 16384,
            edx: 24,
        })
        .unwrap()
    }

    fn published(count: u64, sequence: u64) -> CpuidResult {
        CpuidResult {
            eax: count as u32,
            ebx: (count >> 32) as u32,
            ecx: sequence as u32,
            edx: (sequence >> 32) as u32,
        }
    }

    fn snapshot(layout: NativeSnapshotLayout) -> Vec<u8> {
        let mut bytes = vec![0; layout.snapshot_bytes];
        let mut fields =
            std::array::from_fn::<_, 26, _>(|index| 0x1122_3344_5566_0000 + index as u64);
        fields[0] = 11;
        fields[1] = 0xffff_f800_1234_5678;
        fields[8] = 0xffff_8000_1000_0000;
        fields[9] = fields[8] + layout.stack_bytes as u64;
        fields[2] = fields[9] - 32;
        for (chunk, value) in bytes[..layout.stack_offset].chunks_exact_mut(8).zip(fields) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        for (index, byte) in bytes[layout.stack_offset..].iter_mut().enumerate() {
            *byte = index.wrapping_mul(17) as u8;
        }
        bytes
    }

    fn payload(bytes: &[u8], subleaf: u32, frame_index: u32) -> CpuidResult {
        let offset = (subleaf - 0x4000 - frame_index * (bytes.len() / 16) as u32) as usize * 16;
        let words: [u32; 4] = std::array::from_fn(|index| {
            u32::from_le_bytes(
                bytes[offset + index * 4..offset + index * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        CpuidResult {
            eax: words[0],
            ebx: words[1],
            ecx: words[2],
            edx: words[3],
        }
    }

    #[test]
    fn snapshot_preserves_every_stack_byte_and_full_width_register() {
        let layout = layout();
        let bytes = snapshot(layout);
        let sequence = 0xfedc_ba98_7654_3210;
        let mut query = |subleaf| match subleaf {
            51 => published(24, sequence),
            _ => payload(&bytes, subleaf, 23),
        };
        let captured = layout
            .read_frame(23, sequence, &mut query)
            .unwrap()
            .unwrap();
        assert_eq!(captured, bytes);
        let fields = native_snapshot_fields(&captured);
        assert_eq!(fields[1], 0xffff_f800_1234_5678);
        for (index, name) in NATIVE_SNAPSHOT_FIELDS.iter().enumerate().skip(10) {
            assert_eq!(
                fields[index],
                0x1122_3344_5566_0000 + index as u64,
                "{name}"
            );
        }
        assert_eq!(captured[layout.stack_offset..].len(), 16384);
        assert_eq!(control_stage_name(fields[0]), "before_invept");
        assert_eq!(control_stage_name(10), "vmcs_cleared");
        assert_eq!(control_stage_name(12), "before_invvpid");
    }

    #[test]
    fn snapshot_rejects_sequence_changes_and_count_resets_during_read() {
        let layout = layout();
        let bytes = snapshot(layout);
        for after in [(2, 8), (1, 7)] {
            let mut publications = 0;
            let mut query = |subleaf| {
                if subleaf == 51 {
                    publications += 1;
                    let state = if publications == 1 { (2, 7) } else { after };
                    published(state.0, state.1)
                } else {
                    payload(&bytes, subleaf, 0)
                }
            };
            assert!(layout.read_frame(0, 7, &mut query).unwrap().is_none());
        }
    }

    #[test]
    fn snapshot_accepts_new_published_frames_without_discarding_immutable_bytes() {
        let layout = layout();
        let bytes = snapshot(layout);
        let mut publications = 0;
        let mut query = |subleaf| {
            if subleaf == 51 {
                publications += 1;
                published(publications, 7)
            } else {
                payload(&bytes, subleaf, 0)
            }
        };
        assert_eq!(layout.read_frame(0, 7, &mut query).unwrap().unwrap(), bytes);
    }

    #[test]
    fn snapshot_rejects_header_changes_even_if_publication_state_matches() {
        let layout = layout();
        let bytes = snapshot(layout);
        let mut reads = 0;
        let mut query = |subleaf| {
            if subleaf == 51 {
                published(1, 7)
            } else {
                reads += 1;
                let mut result = payload(&bytes, subleaf, 0);
                if reads > layout.snapshot_bytes / 16 {
                    result.eax ^= 1;
                }
                result
            }
        };
        assert!(layout.read_frame(0, 7, &mut query).unwrap().is_none());
    }

    #[test]
    fn unpublished_frames_and_invalid_counts_never_read_payload() {
        let layout = layout();
        for (count, sequence) in [(0, 7), (1, 8), (25, 7)] {
            let mut query = |subleaf| {
                assert_eq!(subleaf, 51);
                published(count, sequence)
            };
            let result = layout.read_frame(0, 7, &mut query);
            if count > layout.capacity {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_none());
            }
        }
    }

    #[test]
    fn layout_rejects_invalid_abi_and_subleaf_address_overflow() {
        for result in [
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
            CpuidResult {
                eax: 16592,
                ebx: 200,
                ecx: 16392,
                edx: 24,
            },
            CpuidResult {
                eax: 16584,
                ebx: 208,
                ecx: 16376,
                edx: 24,
            },
            CpuidResult {
                eax: 16592,
                ebx: 208,
                ecx: 16384,
                edx: 0,
            },
            CpuidResult {
                eax: 16592,
                ebx: 208,
                ecx: 16384,
                edx: 48,
            },
            CpuidResult {
                eax: 131280,
                ebx: 208,
                ecx: 131072,
                edx: 1,
            },
        ] {
            assert!(NativeSnapshotLayout::from_cpuid(result).is_err());
        }
    }

    #[test]
    fn snapshot_rejects_stack_bounds_that_do_not_cover_the_saved_allocation() {
        let layout = layout();
        for field in [2, 9] {
            let mut bytes = snapshot(layout);
            bytes[field * 8..field * 8 + 8].copy_from_slice(&0u64.to_le_bytes());
            let mut query = |subleaf| match subleaf {
                51 => published(1, 7),
                _ => payload(&bytes, subleaf, 0),
            };
            assert!(layout.read_frame(0, 7, &mut query).is_err());
        }
    }

    #[test]
    fn persisted_frame_matches_binary_and_duplicate_capture_cannot_overwrite_it() {
        let layout = layout();
        let bytes = snapshot(layout);
        let run = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../builds/neo-control-trace-tests")
            .join(format!("{}-{run}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let trace_path = directory.join("trace.txt");
        let mut trace = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&trace_path)
            .unwrap();
        save_native_frame(&trace_path, &mut trace, 0, 7, 0, layout, &bytes).unwrap();
        trace.flush().unwrap();
        let frame_path = directory.join("trace.txt.cpu0.seq0000000000000007.frame00.bin");
        assert_eq!(std::fs::read(&frame_path).unwrap(), bytes);
        let record = std::fs::read_to_string(&trace_path).unwrap();
        assert!(record.contains("native_rip=0xfffff80012345678\n"));
        assert!(record.contains("native_stack_bytes=16384\n"));
        assert!(record.contains("native_stack_offset=208\n"));
        assert!(record.contains("native_frame_complete=true\n"));
        assert!(save_native_frame(&trace_path, &mut trace, 0, 7, 0, layout, &[]).is_err());
        assert_eq!(std::fs::read(&frame_path).unwrap(), bytes);
        assert_eq!(std::fs::read_to_string(&trace_path).unwrap(), record);
    }
}

mod confirmation {
    use crate::commands::confirm_matrix_on;
    use std::io::Cursor;

    #[test]
    fn activation_requires_an_explicit_y_after_the_crash_warning() {
        for answer in ["Y\n", "y\r\n", " Y \n"] {
            let mut output = Vec::new();
            assert!(confirm_matrix_on(&mut Cursor::new(answer), &mut output).unwrap());
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains("can crash running emulators or virtual machines"));
            assert!(text.contains("Close them before continuing."));
            assert!(text.ends_with("Turn MatrixHV ON? [Y/N] (default N): "));
        }
    }

    #[test]
    fn cancellation_and_eof_never_confirm_activation() {
        for answer in ["N\n", "n\r\n", "\n", "", "yes\n", "1\n", "Y N\n"] {
            assert!(!confirm_matrix_on(&mut Cursor::new(answer), &mut Vec::new()).unwrap());
        }
    }

    #[test]
    fn invalid_answers_prompt_again_without_implicitly_confirming() {
        for (answer, confirmed) in [("yes\nY\n", true), ("invalid\nN\n", false)] {
            let mut output = Vec::new();
            assert_eq!(
                confirm_matrix_on(&mut Cursor::new(answer), &mut output).unwrap(),
                confirmed
            );
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains("Enter Y or N."));
            assert_eq!(text.matches("Turn MatrixHV ON?").count(), 2);
        }
    }
}

#[cfg(target_os = "windows")]
mod elevation {
    use crate::matrix::{
        Command,
        windows::{
            ShellExecuteInfo, elevated_arguments, get_current_process, receive_elevated_result,
        },
    };
    use crate::server::protocol::{RequestKind, Response, write_response};
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::time::Duration;

    #[test]
    fn elevated_arguments_preserve_the_requested_operation_and_cpu() {
        for (command, expected) in [
            (Command::On, "--runtime-elevated matrix on"),
            (Command::Off, "--runtime-elevated matrix off"),
            (Command::Status, "--runtime-elevated matrix status"),
            (
                Command::OffProcessor(0),
                "--runtime-elevated matrix off --cpu 0",
            ),
            (
                Command::OffProcessor(63),
                "--runtime-elevated matrix off --cpu 63",
            ),
        ] {
            assert_eq!(
                elevated_arguments(command, 1234, 5678),
                expected.replacen("--runtime-elevated", "--runtime-elevated 1234 5678", 1)
            );
        }
    }

    #[test]
    fn shell_execute_layout_matches_the_windows_x64_abi() {
        assert_eq!(std::mem::size_of::<ShellExecuteInfo>(), 112);
        assert_eq!(std::mem::offset_of!(ShellExecuteInfo, parameters), 32);
        assert_eq!(std::mem::offset_of!(ShellExecuteInfo, process), 104);
    }

    #[test]
    fn result_channel_rejects_wrong_nonce_and_waits_for_delayed_response() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let expected = Response::success(RequestKind::Status, "bridge=present\n");
        let sent = expected.clone();
        let child = std::thread::spawn(move || {
            let mut invalid = TcpStream::connect(address).unwrap();
            invalid.write_all(&[0; 16]).unwrap();
            drop(invalid);
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&[1; 16]).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            write_response(&mut stream, 0, &sent).unwrap();
        });
        let received =
            receive_elevated_result(&listener, unsafe { get_current_process() }, [1; 16]).unwrap();
        child.join().unwrap();
        assert_eq!(received, expected);
    }

    #[test]
    fn result_channel_preserves_failure_details() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let expected = Response::failure(RequestKind::Status, "firmware privilege unavailable");
        let sent = expected.clone();
        let child = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&[2; 16]).unwrap();
            write_response(&mut stream, 0, &sent).unwrap();
        });
        let received =
            receive_elevated_result(&listener, unsafe { get_current_process() }, [2; 16]).unwrap();
        child.join().unwrap();
        assert_eq!(received, expected);
    }
}

mod repl {
    use std::io::Write;
    use std::process::{Command, Output, Stdio};

    fn shell(arguments: &[&str], input: &str) -> Output {
        let mut child = Command::new(
            std::env::var_os("NEO_TEST_BINARY")
                .expect("run_alltests.py must build the Neo binary before running REPL tests"),
        )
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    fn explicit_shell_keeps_running_after_command_errors() {
        let result = shell(&["shell"], "help\nunknown_command\nping\nquit\n");
        assert!(result.status.success());
        let text = String::from_utf8(result.stdout).unwrap();
        assert!(text.contains("Matrix Road Interface"));
        assert!(text.contains("UEFI MatrixHV Core"));
        assert!(text.contains("Available Interactive Commands:"));
        assert!(text.contains("pong"));
        assert!(text.contains("Exiting Matrix."));
        assert!(
            String::from_utf8(result.stderr)
                .unwrap()
                .contains("unknown command")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn no_arguments_open_the_shell_without_installing_startup() {
        let result = shell(&[], "exit\n");
        assert!(result.status.success());
        let text = String::from_utf8(result.stdout).unwrap();
        assert!(text.contains("neo> "));
        assert!(!text.contains("startup installed"));
    }

    #[test]
    fn eof_exits_the_shell_without_spinning() {
        let result = shell(&["shell"], "");
        assert!(result.status.success());
        assert_eq!(
            String::from_utf8(result.stdout)
                .unwrap()
                .matches("neo> ")
                .count(),
            1
        );
    }

    #[test]
    fn matrix_on_confirmation_consumes_only_its_answer_and_returns_to_the_shell() {
        let result = shell(&["shell"], "matrix on\nN\non\n\nping\nexit\n");
        assert!(result.status.success());
        let text = String::from_utf8(result.stdout).unwrap();
        assert_eq!(text.matches("MatrixHV activation cancelled.").count(), 2);
        assert_eq!(text.matches("Turn MatrixHV ON? [Y/N]").count(), 2);
        assert!(text.contains("pong"));
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn quoted_paths_and_recursive_shell_commands_do_not_break_the_session() {
        let result = shell(
            &["shell"],
            "shell\n--binary \"D:\\folder with spaces\\neo.exe\" --update\nping\nq\n",
        );
        assert!(result.status.success());
        let errors = String::from_utf8(result.stderr).unwrap();
        assert!(errors.contains("already open"));
        assert!(errors.contains("requires --remote"));
        assert!(String::from_utf8(result.stdout).unwrap().contains("pong"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn elevated_helper_rejects_commands_outside_the_local_runtime_bridge() {
        for arguments in [
            vec!["--runtime-elevated", "ping"],
            vec!["--runtime-elevated", "shell"],
            vec!["--runtime-elevated", "install"],
            vec!["--runtime-elevated", "--remote", "127.0.0.1:1", "status"],
            vec!["--runtime-elevated", "matrix", "off", "--cpu", "64"],
            vec![
                "--runtime-elevated",
                "--cleanup",
                "unused",
                "matrix",
                "status",
            ],
        ] {
            let mut helper_arguments = vec!["--runtime-elevated", "1234", "5678"];
            helper_arguments.extend_from_slice(&arguments[1..]);
            let result = shell(&helper_arguments, "");
            assert!(!result.status.success());
            assert!(!result.stderr.is_empty());
        }
    }
}
