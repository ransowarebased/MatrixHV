use std::io::Write;
use std::process::{Command, Output, Stdio};

fn shell(arguments: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_neo"))
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
