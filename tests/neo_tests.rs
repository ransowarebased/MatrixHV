mod transport {
    use crate::server::protocol::{
        MAX_FRAME_SIZE, ProtocolError, Request, RequestKind, Response, read_request, read_response,
        write_request, write_response,
    };
    use crate::server::{
        capture_stream, execute, handle_connection, valid_elf_update, validate_update_binary,
    };
    use std::io::{self, Read, Write};

    #[test]
    fn request_writer_rejects_argument_counts_the_reader_cannot_accept() {
        for count in [0, 4097] {
            let mut frame = Vec::new();
            assert!(matches!(
                write_request(
                    &mut frame,
                    42,
                    &Request::Exec {
                        arguments: vec![String::new(); count]
                    }
                ),
                Err(ProtocolError::InvalidPayload(_))
            ));
            assert!(frame.is_empty());
        }
        let request = Request::Exec {
            arguments: vec!["argument".into(); 4096],
        };
        let mut frame = Vec::new();
        write_request(&mut frame, 42, &request).unwrap();
        assert_eq!(read_request(&mut frame.as_slice()).unwrap(), (42, request));
    }

    #[test]
    fn oversized_payloads_are_rejected_before_writing_any_frame() {
        let mut frame = Vec::new();
        let request = Request::Update {
            binary: vec![0; MAX_FRAME_SIZE - 3],
        };
        assert!(matches!(
            write_request(&mut frame, 1, &request),
            Err(ProtocolError::FrameTooLarge(_))
        ));
        assert!(frame.is_empty());
        drop(request);
        let mut response = Response::success(RequestKind::Exec, "");
        response.stdout = vec![0; MAX_FRAME_SIZE - 19];
        assert!(matches!(
            write_response(&mut frame, 1, &response),
            Err(ProtocolError::FrameTooLarge(_))
        ));
        assert!(frame.is_empty());
    }

    #[test]
    fn response_status_only_accepts_the_published_boolean_encoding() {
        for (status, success) in [(0u32, true), (1, false), (2, false), (u32::MAX, false)] {
            let mut frame = Vec::new();
            let response = Response::success(RequestKind::Status, "ready");
            write_response(&mut frame, 42, &response).unwrap();
            frame[20..24].copy_from_slice(&status.to_le_bytes());
            let result = read_response(&mut frame.as_slice());
            if status <= 1 {
                assert_eq!(result.unwrap().1.success, success);
            } else {
                assert!(matches!(result, Err(ProtocolError::InvalidPayload(_))));
            }
        }
    }

    fn header(kind: u16, payload_size: u32) -> Vec<u8> {
        let mut frame = b"ROAD".to_vec();
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.extend_from_slice(&kind.to_le_bytes());
        frame.extend_from_slice(&payload_size.to_le_bytes());
        frame.extend_from_slice(&42u64.to_le_bytes());
        frame
    }

    #[test]
    fn invalid_request_headers_are_rejected_without_reading_the_payload() {
        for (kind, size) in [(1, 1), (2, MAX_FRAME_SIZE as u32), (3, 7), (4, 3), (5, 9)] {
            assert!(matches!(
                read_request(&mut header(kind, size).as_slice()),
                Err(ProtocolError::InvalidPayload(_))
            ));
        }
        for kind in [0, 6, 0x8001, u16::MAX] {
            assert!(matches!(
                read_request(&mut header(kind, MAX_FRAME_SIZE as u32).as_slice()),
                Err(ProtocolError::InvalidKind(value)) if value == kind
            ));
        }
    }

    #[test]
    fn invalid_response_headers_are_rejected_without_reading_the_payload() {
        assert!(matches!(
            read_response(&mut header(1, MAX_FRAME_SIZE as u32).as_slice()),
            Err(ProtocolError::InvalidResponseKind(1))
        ));
        assert!(matches!(
            read_response(&mut header(0x8006, MAX_FRAME_SIZE as u32).as_slice()),
            Err(ProtocolError::InvalidKind(6))
        ));
        assert!(matches!(
            read_response(&mut header(0x8001, 19).as_slice()),
            Err(ProtocolError::TruncatedPayload)
        ));
    }

    #[test]
    fn update_requires_a_complete_executable_for_the_current_platform() {
        for binary in [
            &b""[..],
            &b"MZ"[..],
            &b"\x7fELF"[..],
            &b"MZinvalid executable"[..],
        ] {
            assert!(validate_update_binary(binary).is_err());
        }
        let binary = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(validate_update_binary(&binary).is_ok());
        for length in [64, 128, binary.len() / 2] {
            assert!(validate_update_binary(&binary[..length]).is_err());
        }
        let mut invalid = binary;
        #[cfg(target_os = "windows")]
        {
            let pe_offset = u32::from_le_bytes(invalid[60..64].try_into().unwrap()) as usize;
            invalid[pe_offset + 4..pe_offset + 6].copy_from_slice(&0x14cu16.to_le_bytes());
        }
        #[cfg(target_os = "linux")]
        {
            invalid[18..20].copy_from_slice(&3u16.to_le_bytes());
        }
        assert!(validate_update_binary(&invalid).is_err());
    }

    #[test]
    fn elf_updates_require_a_file_backed_executable_entry_point() {
        let mut binary = vec![0; 128];
        binary[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        binary[16..18].copy_from_slice(&2u16.to_le_bytes());
        binary[18..20].copy_from_slice(&62u16.to_le_bytes());
        binary[20..24].copy_from_slice(&1u32.to_le_bytes());
        binary[24..32].copy_from_slice(&0x400078u64.to_le_bytes());
        binary[32..40].copy_from_slice(&64u64.to_le_bytes());
        binary[52..54].copy_from_slice(&64u16.to_le_bytes());
        binary[54..56].copy_from_slice(&56u16.to_le_bytes());
        binary[56..58].copy_from_slice(&1u16.to_le_bytes());
        binary[64..68].copy_from_slice(&1u32.to_le_bytes());
        binary[68..72].copy_from_slice(&5u32.to_le_bytes());
        binary[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
        binary[96..104].copy_from_slice(&128u64.to_le_bytes());
        binary[104..112].copy_from_slice(&128u64.to_le_bytes());
        binary[120] = 0xc3;
        assert!(valid_elf_update(&binary));
        for length in 0..binary.len() {
            assert!(!valid_elf_update(&binary[..length]));
        }
        for (offset, bytes) in [
            (32, u64::MAX.to_le_bytes()),
            (72, u64::MAX.to_le_bytes()),
            (80, u64::MAX.to_le_bytes()),
            (96, 129u64.to_le_bytes()),
            (104, 120u64.to_le_bytes()),
        ] {
            let mut invalid = binary.clone();
            invalid[offset..offset + 8].copy_from_slice(&bytes);
            assert!(!valid_elf_update(&invalid));
        }
        for (offset, value) in [(4, 1), (5, 2), (7, 6), (18, 3), (54, 55), (68, 4)] {
            let mut invalid = binary.clone();
            invalid[offset] = value;
            assert!(!valid_elf_update(&invalid));
        }
        if let Some(path) = std::env::var_os("NEO_TEST_LINUX_BINARY") {
            assert!(valid_elf_update(&std::fs::read(path).unwrap()));
        }
    }

    #[test]
    fn staged_update_commits_when_the_response_connection_is_lost() {
        struct LostConnection(io::Cursor<Vec<u8>>);
        impl Read for LostConnection {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.0.read(buffer)
            }
        }
        impl Write for LostConnection {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut frame = Vec::new();
        write_request(
            &mut frame,
            42,
            &Request::Update {
                binary: std::fs::read(std::env::current_exe().unwrap()).unwrap(),
            },
        )
        .unwrap();
        let mut prepared = false;
        let result = handle_connection(
            &mut LostConnection(io::Cursor::new(frame)),
            &mut |_| {
                prepared = true;
                Ok(())
            },
            &mut |_, _| unreachable!(),
        )
        .unwrap();
        assert!(result);
        assert!(prepared);
    }

    #[test]
    fn capture_drains_excess_bytes_and_retries_interrupted_reads() {
        struct OutputStream {
            remaining: usize,
            interrupted: bool,
        }
        impl Read for OutputStream {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                assert!(buffer.len() <= 16 * 1024);
                let count = self.remaining.min(buffer.len());
                buffer[..count].fill(0x5a);
                self.remaining -= count;
                Ok(count)
            }
        }
        let mut stream = OutputStream {
            remaining: 32 * 1024 * 1024 + 17,
            interrupted: false,
        };
        let bytes = capture_stream(&mut stream).unwrap();
        assert_eq!(bytes.len(), 16 * 1024 * 1024);
        assert!(bytes.iter().all(|byte| *byte == 0x5a));
        assert_eq!(stream.remaining, 0);
    }

    #[test]
    fn capture_preserves_read_errors() {
        struct FailedStream;
        impl Read for FailedStream {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        assert_eq!(
            capture_stream(&mut FailedStream).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn execution_preserves_both_streams_and_the_process_exit_code() {
        #[cfg(target_os = "windows")]
        let arguments = [
            "cmd.exe",
            "/d",
            "/c",
            "echo output & echo error 1>&2 & exit /b 7",
        ];
        #[cfg(not(target_os = "windows"))]
        let arguments = ["sh", "-c", "printf output; printf error >&2; exit 7"];
        let response = execute(arguments.into_iter().map(str::to_string).collect());
        assert!(!response.success);
        assert_eq!(response.exit_code, Some(7));
        assert_eq!(String::from_utf8(response.stdout).unwrap().trim(), "output");
        assert_eq!(String::from_utf8(response.stderr).unwrap().trim(), "error");
    }
}

mod server_concurrency {
    use crate::server::protocol::{Request, Response, read_response, write_request};
    use crate::server::{ServerExit, serve};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    fn start_server(
        prepare: impl FnMut(&[u8]) -> Result<(), String> + Send + 'static,
        telemetry: impl FnMut(u32, u32) -> Result<String, String> + Send + 'static,
    ) -> (SocketAddr, JoinHandle<Result<ServerExit, String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let server = thread::spawn(move || serve(&address.to_string(), prepare, telemetry));
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_err() {
            assert!(Instant::now() < deadline, "server did not bind");
            thread::sleep(Duration::from_millis(10));
        }
        (address, server)
    }

    fn connect(address: SocketAddr) -> TcpStream {
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
    }

    fn transact(address: SocketAddr, request: Request) -> Response {
        let mut stream = connect(address);
        write_request(&mut stream, 42, &request).unwrap();
        let (request_id, response) = read_response(&mut stream).unwrap();
        assert_eq!(request_id, 42);
        response
    }

    fn update() -> Request {
        let binary = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        Request::Update { binary }
    }

    #[test]
    fn idle_connection_does_not_block_ping_or_status() {
        let (address, server) = start_server(|_| Ok(()), |_, _| Ok("telemetry".into()));
        let idle = connect(address);
        assert!(transact(address, Request::Ping).success);
        assert!(transact(address, Request::Status).success);
        drop(idle);
        assert!(transact(address, update()).success);
        assert!(matches!(
            server.join().unwrap().unwrap(),
            ServerExit::Update
        ));
    }

    #[test]
    fn slow_telemetry_does_not_block_ping() {
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (address, server) = start_server(
            |_| Ok(()),
            move |_, _| {
                entered_sender.send(()).unwrap();
                release_receiver
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                Ok("telemetry".into())
            },
        );
        let telemetry = thread::spawn(move || {
            transact(
                address,
                Request::Telemetry {
                    mode: 0,
                    control: 0,
                },
            )
        });
        entered_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert!(transact(address, Request::Ping).success);
        release_sender.send(()).unwrap();
        assert!(telemetry.join().unwrap().success);
        assert!(transact(address, update()).success);
        assert!(matches!(
            server.join().unwrap().unwrap(),
            ServerExit::Update
        ));
    }

    #[test]
    fn concurrent_updates_cannot_overwrite_a_committed_binary() {
        let count = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&count);
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (address, server) = start_server(
            move |_| {
                calls.fetch_add(1, Ordering::Relaxed);
                entered_sender.send(()).unwrap();
                release_receiver
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                Ok(())
            },
            |_, _| Ok("telemetry".into()),
        );
        let first = thread::spawn(move || transact(address, update()));
        entered_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let second = transact(address, update());
        assert!(!second.success);
        assert!(second.message.contains("already pending"));
        assert_eq!(count.load(Ordering::Relaxed), 1);
        release_sender.send(()).unwrap();
        assert!(first.join().unwrap().success);
        assert!(matches!(
            server.join().unwrap().unwrap(),
            ServerExit::Update
        ));
    }

    #[test]
    fn failed_update_releases_the_pending_gate_for_a_retry() {
        let mut calls = 0;
        let (address, server) = start_server(
            move |_| {
                calls += 1;
                if calls == 1 {
                    Err("staging failed".into())
                } else {
                    Ok(())
                }
            },
            |_, _| Ok("telemetry".into()),
        );
        let failure = transact(address, update());
        assert!(!failure.success);
        assert_eq!(failure.message, "staging failed");
        assert!(transact(address, Request::Ping).success);
        assert!(transact(address, update()).success);
        assert!(matches!(
            server.join().unwrap().unwrap(),
            ServerExit::Update
        ));
    }
}

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
        for (chunk, value) in bytes[..layout.stack_offset]
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(fields)
        {
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

#[test]
fn ept_diagnostic_output_keeps_attempts_results_failure_context_and_pending_cpu_mask() {
    use crate::protocol::memory::{EPT_DIAGNOSTIC_SUBLEAF, INTERCEPT_DIAGNOSTIC_WORDS, EPT_SYNC_DIAGNOSTIC_WORDS};
    let mut words = [0u64; INTERCEPT_DIAGNOSTIC_WORDS + EPT_SYNC_DIAGNOSTIC_WORDS + 8];
    words[3..6].copy_from_slice(&[7, 5, 2]);
    words[18..21].copy_from_slice(&[2, 2, 0]);
    words[21..24].copy_from_slice(&[2, 0xffff800040123456, 0x800008]);
    words[24..32].copy_from_slice(&[9, 5, 1, 1, 1, 1, 5, 1 << 63]);
    words[32..].copy_from_slice(&[5, 0x1000, 7, 1 << 63, 0x401234, 0x800082, 2, 100]);
    let mut queried = Vec::new();
    let mut output = String::new();
    crate::telemetry::append_ept_diagnostics(&mut output, "cpu.63", |subleaf| {
        queried.push(subleaf);
        let index = (subleaf - EPT_DIAGNOSTIC_SUBLEAF) as usize * 2;
        (words[index], words[index + 1])
    });
    assert_eq!(queried, (0x400..0x414).collect::<Vec<_>>());
    for line in [
        "cpu.63.interception.apply.attempts=7",
        "cpu.63.interception.apply.successes=5",
        "cpu.63.interception.apply.failures=2",
        "cpu.63.interception.recovery.successes=2",
        "cpu.63.interception.failure_phase_name=apply",
        "cpu.63.interception.failure_rip=0xffff800040123456",
        "cpu.63.interception.failure_gpa=0x0000000000800008",
        "cpu.63.ept_sync.failure_phase_name=parked-peer-release",
        "cpu.63.ept_sync.pending_cpu_mask=0x8000000000000000",
        "cpu.63.ept_sync.stall.owner=0x0000000000001000",
        "cpu.63.ept_sync.stall.epoch=0x0000000000000007",
        "cpu.63.ept_sync.stall.write_step=0x0000000000000002",
    ] {
        assert!(output.lines().any(|actual| actual == line), "missing diagnostic: {line}");
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
    fn elevated_update_quotes_spaces_embedded_quotes_and_trailing_backslashes() {
        let path = std::path::PathBuf::from("C:\\Matrix Updates\\quoted\" name\\");
        let expected = r#"--runtime-elevated 1234 5678 matrix update --binary "C:\Matrix Updates\quoted\" name\\""#;
        assert_eq!(elevated_arguments(Command::Update(path), 1234, 5678), expected);
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

mod exit_benchmark {
    use crate::telemetry::{Mode, append_exit_benchmark};

    #[test]
    fn calibration_preserves_raw_tails_and_uses_nearest_rank_percentiles() {
        let mut output = String::new();
        append_exit_benchmark(
            &mut output,
            "cpu.3",
            vec![30, 20, 0, u64::MAX],
            (1..=100)
                .map(|value| value * 100)
                .chain([0, u64::MAX])
                .collect(),
            2_000_000_000,
        )
        .unwrap();
        for line in [
            "cpu.3.baseline_samples=2",
            "cpu.3.baseline_rejected=2",
            "cpu.3.samples=100",
            "cpu.3.rejected=2",
            "cpu.3.bracket_overhead_tsc_ticks=20",
            "cpu.3.round_trip_tsc_ticks.min=100",
            "cpu.3.round_trip_tsc_ticks.p50=5000",
            "cpu.3.round_trip_tsc_ticks.p95=9500",
            "cpu.3.round_trip_tsc_ticks.p99=9900",
            "cpu.3.round_trip_tsc_ticks.max=10000",
            "cpu.3.round_trip_tsc_ticks.mean=5050",
            "cpu.3.calibrated_round_trip_tsc_ticks.mean=5030",
            "cpu.3.calibrated_round_trip_ns.p99=4940",
        ] {
            assert!(
                output.lines().any(|actual| actual == line),
                "missing {line}"
            );
        }
    }

    #[test]
    fn saturated_calibration_averages_each_sample_and_unknown_frequency_stays_unavailable() {
        let mut output = String::new();
        append_exit_benchmark(&mut output, "cpu.0", vec![20], vec![10, 30], 0).unwrap();
        assert!(output.contains("cpu.0.calibrated_round_trip_tsc_ticks.min=0\n"));
        assert!(output.contains("cpu.0.calibrated_round_trip_tsc_ticks.mean=5\n"));
        assert!(output.contains("cpu.0.round_trip_ns=unavailable\n"));
        assert!(!output.contains("round_trip_ns.mean="));
    }

    #[test]
    fn large_tsc_samples_do_not_overflow_means_or_time_conversion() {
        let mut output = String::new();
        let ticks = i64::MAX as u64;
        append_exit_benchmark(&mut output, "cpu.0", vec![1], vec![ticks; 4], 1).unwrap();
        assert!(output.contains(&format!("round_trip_tsc_ticks.mean={ticks}\n")));
        assert!(output.contains(&format!(
            "round_trip_ns.mean={}\n",
            u128::from(ticks) * 1_000_000_000
        )));
    }

    #[test]
    fn empty_or_invalid_samples_cannot_report_success() {
        for (baseline, samples) in [
            (vec![], vec![10]),
            (vec![10], vec![]),
            (vec![0, u64::MAX], vec![10]),
            (vec![10], vec![0, u64::MAX]),
        ] {
            assert!(
                append_exit_benchmark(&mut String::new(), "cpu.0", baseline, samples, 1).is_err()
            );
        }
        assert_eq!(Mode::from_u32(3).unwrap(), Mode::Benchmark);
        assert!(Mode::from_u32(4).is_err());
    }

    #[test]
    fn benchmark_flag_sends_only_a_query_and_normal_telemetry_keeps_its_mode() {
        use crate::server::protocol::{
            Request, RequestKind, Response, read_request, write_response,
        };
        use std::net::TcpListener;
        for (flag, mode) in [(Some("--benchmark"), 3), (None, 0)] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let (request_id, request) = read_request(&mut stream).unwrap();
                assert_eq!(request, Request::Telemetry { mode, control: 0 });
                write_response(
                    &mut stream,
                    request_id,
                    &Response::success(RequestKind::Telemetry, "benchmark-test\n"),
                )
                .unwrap();
            });
            let mut arguments = vec!["--remote".into(), address.to_string(), "telemetry".into()];
            arguments.extend(flag.map(str::to_string));
            assert_eq!(crate::commands::run(arguments).unwrap(), 0);
            server.join().unwrap();
        }
    }

    #[test]
    fn benchmark_flag_rejects_controls_other_modes_and_unrelated_commands() {
        for arguments in [
            vec!["telemetry", "watchdog", "--benchmark"],
            vec!["telemetry", "eptdiag", "--benchmark"],
            vec!["telemetry", "enable", "--benchmark"],
            vec!["telemetry", "disable", "--benchmark"],
            vec!["telemetry", "--benchmark", "--benchmark"],
            vec!["status", "--benchmark"],
            vec!["--benchmark"],
        ] {
            let error = crate::commands::run(arguments.into_iter().map(str::to_string).collect())
                .unwrap_err();
            assert!(error.contains("--benchmark"), "{error}");
        }
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
