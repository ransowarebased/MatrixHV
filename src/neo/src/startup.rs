use crate::commands;
use colored::Colorize;
use std::io::{self, Write};
use std::path::Path;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::path::PathBuf;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::process::Command;
use std::thread;
use std::time::Duration;

#[cfg(target_os = "windows")]
const WINDOWS_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(target_os = "windows")]
const WINDOWS_VALUE_NAME: &str = "MatrixHVNeo";
#[cfg(target_os = "linux")]
const LINUX_UNIT_NAME: &str = "matrixhv-neo.service";

pub fn run_shell() -> Result<i32, String> {
    print_banner();
    println!(
        "{}\n",
        "Entering Matrix Interactive REPL. Type 'help' or 'exit'.".bright_cyan()
    );
    loop {
        print!("{}", "neo> ".bright_green().bold());
        io::stdout()
            .flush()
            .map_err(|error| format!("failed to flush shell prompt: {error}"))?;
        let mut input = String::new();
        if io::stdin()
            .read_line(&mut input)
            .map_err(|error| format!("failed to read shell command: {error}"))?
            == 0
        {
            println!();
            return Ok(0);
        }
        let mut arguments = match parse_arguments(input.trim()) {
            Ok(arguments) => arguments,
            Err(error) => {
                print_error(&error);
                continue;
            }
        };
        let argument_count = arguments.len();
        let Some(command) = arguments.first_mut() else {
            continue;
        };
        *command = command.to_ascii_lowercase();
        match command.as_str() {
            "exit" | "quit" | "q" if argument_count == 1 => {
                println!("{}", "Exiting Matrix.".bright_green());
                return Ok(0);
            }
            "help" | "?" if argument_count == 1 => {
                print_help();
                continue;
            }
            "cls" | "clear" if argument_count == 1 => {
                print!("\x1b[2J\x1b[1;1H");
                print_banner();
                continue;
            }
            "shell" => {
                print_error("the interactive shell is already open");
                continue;
            }
            "on" | "off" => arguments.insert(0, "matrix".to_string()),
            _ => {}
        }
        if let Err(error) = commands::run(arguments) {
            print_error(&error);
        }
    }
}

fn print_banner() {
    for line in [
        "==================================================================",
        "  _   _ _____ ___     - Matrix Road Interface -",
        " | \\ | | ____/ _ \\    \"The Matrix is everywhere. It is all around us.\"",
        " |  \\| |  _|| | | |   Bare-Metal Ring -1 CPUID Hypercall (Rust CLI)",
        " | |\\  | |__| |_| |",
        " |_| \\_|_____\\___/    v0.1.0 (UEFI MatrixHV Core)",
        "==================================================================",
    ] {
        println!("{}", line.bright_green().bold());
    }
}

fn print_help() {
    println!(
        "{}",
        "\nAvailable Interactive Commands:".bright_cyan().bold()
    );
    for line in [
        "  ping                              - Test the Neo agent",
        "  status                            - Query hypervisor state and diagnostics",
        "  read PID|NAME CR3|auto [ADDRESS SIZE ...] - Read a memory batch or resolve a process",
        "  write PID|NAME CR3|auto ADDRESS HEX [...] - Write a memory batch",
        "  hook install CR3 ADDRESS HEX [...] [--alternate-cr3 CR3] [--vmfunc] [--concurrent-writes] [--persistent-data] [--lease-ms MS | --no-lease] [--tsc-offset] - Install split views",
        "  hook add TOKEN ADDRESS HEX [...] | hook remove TOKEN [ID] | hook list TOKEN - Change individual patches",
        "  hook context-add TOKEN CR3 [...] | hook context-remove TOKEN CR3 [...] | hook context-list TOKEN - Manage validated CR3 aliases",
        "  hook renew TOKEN [--lease-ms MS] | hook watch TOKEN [--lease-ms MS] | hook release TOKEN | hook status - Manage the lease",
        "  debug-registers set CR3 ADDRESS RIP [...] [--alternate-cr3 CR3] - Set 1..4 redirects",
        "  debug-registers clear TOKEN | debug-registers status - Clear redirects or query interception",
        "  matrix status                     - Query the Windows runtime bridge",
        "  matrix on | on                    - Enable MatrixHV after Y/N confirmation",
        "  matrix off | off [--cpu INDEX]     - Disable MatrixHV",
        "  telemetry [watchdog | eptdiag]     - Capture diagnostic telemetry",
        "  telemetry enable | disable        - Control diagnostic collection",
        "  telemetry control --cpu INDEX --output FILE - Trace runtime transitions",
        "  install | uninstall               - Manage automatic agent startup",
        "  --help                            - Show all CLI commands and options",
        "  cls | clear                       - Clear screen",
        "  exit | quit | q                    - Exit interactive shell",
    ] {
        println!("{line}");
    }
    println!();
}

fn print_error(error: &str) {
    eprintln!("{} {error}", "[-]".bright_red().bold());
}

#[cfg(target_os = "windows")]
fn parse_arguments(input: &str) -> Result<Vec<String>, String> {
    use std::ffi::c_void;

    #[link(name = "shell32")]
    unsafe extern "system" {
        #[link_name = "CommandLineToArgvW"]
        fn command_line_to_argv(command_line: *const u16, count: *mut i32) -> *mut *mut u16;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "LocalFree"]
        fn local_free(memory: *mut c_void) -> *mut c_void;
    }

    if input.contains('\0') {
        return Err("shell commands cannot contain NUL characters".to_string());
    }
    let command_line: Vec<u16> = format!("neo {input}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut count = 0;
    let pointers = unsafe { command_line_to_argv(command_line.as_ptr(), &mut count) };
    if pointers.is_null() {
        return Err(format!(
            "failed to parse shell command: {}",
            io::Error::last_os_error()
        ));
    }
    let mut arguments = Vec::new();
    for index in 1..count {
        let pointer = unsafe { *pointers.add(index as usize) };
        let mut length = 0;
        while unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        arguments.push(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(pointer, length)
        }));
    }
    unsafe { local_free(pointers.cast()) };
    Ok(arguments)
}

#[cfg(not(target_os = "windows"))]
fn parse_arguments(input: &str) -> Result<Vec<String>, String> {
    shlex::split(input).ok_or_else(|| "invalid quoting in shell command".to_string())
}

pub fn install(listen_address: &str) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve the neo executable: {error}"))?;
    install_platform(&executable, listen_address)?;
    println!("neo user-mode startup installed for {listen_address}");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    uninstall_platform()?;
    println!("neo user-mode startup removed");
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_platform(executable: &Path, listen_address: &str) -> Result<(), String> {
    let local_app_data =
        std::env::var_os("LOCALAPPDATA").ok_or_else(|| "LOCALAPPDATA is not set".to_string())?;
    let install_directory = Path::new(&local_app_data).join("MatrixHV");
    std::fs::create_dir_all(&install_directory)
        .map_err(|error| format!("failed to create {}: {error}", install_directory.display()))?;
    let installed_executable = install_directory.join("neo.exe");
    copy_for_install(executable, &installed_executable)?;
    let command_line = format!(
        "\"{}\" serve --listen {}",
        installed_executable.display(),
        listen_address
    );
    let status = Command::new("reg.exe")
        .args([
            "add",
            WINDOWS_RUN_KEY,
            "/v",
            WINDOWS_VALUE_NAME,
            "/t",
            "REG_SZ",
            "/d",
            &command_line,
            "/f",
        ])
        .status()
        .map_err(|error| format!("failed to run reg.exe: {error}"))?;
    if !status.success() {
        return Err(format!("reg.exe failed with {status}"));
    }
    spawn_detached(&installed_executable, listen_address)
}

#[cfg(target_os = "windows")]
fn uninstall_platform() -> Result<(), String> {
    let status = Command::new("reg.exe")
        .args(["delete", WINDOWS_RUN_KEY, "/v", WINDOWS_VALUE_NAME, "/f"])
        .status()
        .map_err(|error| format!("failed to run reg.exe: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("reg.exe failed with {status}"))
    }
}

#[cfg(target_os = "windows")]
fn spawn_detached(executable: &Path, listen_address: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new(executable)
        .args(["serve", "--listen", listen_address])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| format!("failed to start neo: {error}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_platform(executable: &Path, listen_address: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    let install_directory = Path::new(&home).join(".local/bin");
    std::fs::create_dir_all(&install_directory)
        .map_err(|error| format!("failed to create {}: {error}", install_directory.display()))?;
    let installed_executable = install_directory.join("neo");
    copy_for_install(executable, &installed_executable)?;
    std::fs::set_permissions(
        &installed_executable,
        std::fs::Permissions::from_mode(0o755),
    )
    .map_err(|error| {
        format!(
            "failed to mark {} executable: {error}",
            installed_executable.display()
        )
    })?;
    let unit_directory = Path::new(&home).join(".config/systemd/user");
    std::fs::create_dir_all(&unit_directory)
        .map_err(|error| format!("failed to create {}: {error}", unit_directory.display()))?;
    let unit_path = unit_directory.join(LINUX_UNIT_NAME);
    let executable_text = systemd_quote(&installed_executable.to_string_lossy());
    let listen_text = systemd_quote(listen_address);
    let contents = format!(
        "[Unit]\nDescription=MatrixHV Neo user-mode agent\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={executable_text} --listen {listen_text}\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n"
    );
    std::fs::write(&unit_path, contents)
        .map_err(|error| format!("failed to write {}: {error}", unit_path.display()))?;
    run_systemctl(["daemon-reload"])?;
    run_systemctl(["enable", "--now", LINUX_UNIT_NAME])
}

#[cfg(target_os = "linux")]
fn uninstall_platform() -> Result<(), String> {
    let _ = run_systemctl(["disable", "--now", LINUX_UNIT_NAME]);
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    let unit_path = Path::new(&home)
        .join(".config/systemd/user")
        .join(LINUX_UNIT_NAME);
    match std::fs::remove_file(&unit_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!("failed to remove {}: {error}", unit_path.display()));
        }
    }
    run_systemctl(["daemon-reload"])
}

#[cfg(target_os = "linux")]
fn run_systemctl<const N: usize>(arguments: [&str; N]) -> Result<(), String> {
    let status = Command::new("systemctl")
        .arg("--user")
        .args(arguments)
        .status()
        .map_err(|error| format!("failed to run systemctl: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl failed with {status}"))
    }
}

#[cfg(target_os = "linux")]
fn systemd_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn copy_for_install(source: &Path, destination: &Path) -> Result<(), String> {
    let same_path =
        destination.exists() && source.canonicalize().ok() == destination.canonicalize().ok();
    if same_path {
        return Ok(());
    }
    if destination.exists()
        && std::fs::read(source).ok().is_some_and(|source_bytes| {
            std::fs::read(destination).ok().as_ref() == Some(&source_bytes)
        })
    {
        return Ok(());
    }
    std::fs::copy(source, destination)
        .map(|_| ())
        .map_err(|error| {
            format!(
                "failed to install {} from {}: {error}",
                destination.display(),
                source.display()
            )
        })
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn install_platform(_executable: &Path, _listen_address: &str) -> Result<(), String> {
    Err("user-mode startup is supported only on Windows and Linux".to_string())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn uninstall_platform() -> Result<(), String> {
    Err("user-mode startup is supported only on Windows and Linux".to_string())
}

pub fn prepare(binary: &[u8]) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve the neo executable: {error}"))?;
    prepare_platform(&executable, binary)
}

#[cfg(target_os = "windows")]
fn prepare_platform(executable: &Path, binary: &[u8]) -> Result<(), String> {
    let updater = update_path(executable, "update.exe")?;
    std::fs::write(&updater, binary)
        .map_err(|error| format!("failed to stage {}: {error}", updater.display()))
}

#[cfg(target_os = "linux")]
fn prepare_platform(executable: &Path, binary: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let updater = update_path(executable, "update")?;
    std::fs::write(&updater, binary)
        .map_err(|error| format!("failed to stage {}: {error}", updater.display()))?;
    std::fs::set_permissions(&updater, std::fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("failed to mark {} executable: {error}", updater.display()))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn prepare_platform(_executable: &Path, _binary: &[u8]) -> Result<(), String> {
    Err("self-update is supported only on Windows and Linux".to_string())
}

pub fn activate(listen_address: &str) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve the neo executable: {error}"))?;
    activate_platform(&executable, listen_address)
}

#[cfg(target_os = "windows")]
fn activate_platform(executable: &Path, listen_address: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let updater = update_path(executable, "update.exe")?;
    Command::new(&updater)
        .args([
            "--apply-update",
            &executable.to_string_lossy(),
            "--listen",
            listen_address,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| format!("failed to start {}: {error}", updater.display()))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn activate_platform(executable: &Path, listen_address: &str) -> Result<(), String> {
    let updater = update_path(executable, "update")?;
    std::fs::rename(&updater, executable)
        .map_err(|error| format!("failed to replace {}: {error}", executable.display()))?;
    if std::env::var_os("INVOCATION_ID").is_none() {
        Command::new(executable)
            .args(["--listen", listen_address])
            .spawn()
            .map_err(|error| format!("failed to restart {}: {error}", executable.display()))?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn activate_platform(_executable: &Path, _listen_address: &str) -> Result<(), String> {
    Err("self-update is supported only on Windows and Linux".to_string())
}

pub fn apply_windows_update(target: &Path, listen_address: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let updater = std::env::current_exe()
            .map_err(|error| format!("failed to resolve the update executable: {error}"))?;
        let mut last_error = None;
        for _ in 0..80 {
            match std::fs::copy(&updater, target) {
                Ok(_) => {
                    Command::new(target)
                        .args([
                            "serve",
                            "--listen",
                            listen_address,
                            "--cleanup",
                            &updater.to_string_lossy(),
                        ])
                        .creation_flags(CREATE_NO_WINDOW)
                        .spawn()
                        .map_err(|error| {
                            format!("failed to restart {}: {error}", target.display())
                        })?;
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "failed to replace {}: {}",
            target.display(),
            last_error.unwrap()
        ))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (target, listen_address);
        Err("--apply-update is internal to the Windows updater".to_string())
    }
}

pub fn remove_stale_updater(path: &Path) {
    for _ in 0..40 {
        match std::fs::remove_file(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn update_path(executable: &Path, suffix: &str) -> Result<PathBuf, String> {
    let file_name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "neo executable has an invalid file name".to_string())?;
    Ok(executable.with_file_name(format!("{file_name}.{suffix}")))
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::copy_for_install;
    use std::os::windows::fs::OpenOptionsExt;

    #[test]
    fn reinstall_preserves_an_identical_running_binary() {
        let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        let directory = project
            .join("builds/road-startup-tests")
            .join(std::process::id().to_string());
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("source.exe");
        let destination = directory.join("installed.exe");
        std::fs::write(&source, b"neo test binary").unwrap();
        copy_for_install(&source, &destination).unwrap();
        let running = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&destination)
            .unwrap();
        copy_for_install(&source, &destination).unwrap();
        std::fs::write(&source, b"different neo binary").unwrap();
        assert!(copy_for_install(&source, &destination).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"neo test binary");
        drop(running);
        std::fs::remove_file(source).unwrap();
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    use std::path::PathBuf;
}
