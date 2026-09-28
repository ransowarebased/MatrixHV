use super::{Command, ShellExecuteInfo, elevated_arguments};
use super::{RequestKind, Response, get_current_process, receive_elevated_result, write_response};
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
