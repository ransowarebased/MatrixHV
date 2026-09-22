use std::path::Path;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::path::PathBuf;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::process::Command;
use std::thread;
use std::time::Duration;

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
