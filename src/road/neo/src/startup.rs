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
        "\"{}\" --listen {}",
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
        .args(["--listen", listen_address])
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
