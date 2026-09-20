use std::env;
use std::fs;
use std::io;
use std::path::Path;

const CONFIG_HEADER: &str = "MATRIXHV_CONFIG_V1";
const DEFAULT_FILE_TEXT: &str = "MATRIXHV_CONFIG_V1\ncpuidpresence=true\nlogger=true\n";

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is missing");
    let config_dir = Path::new(&manifest_dir).join("config");
    let config_path = config_dir.join("MatrixConfig.bin");
    let example_path = config_dir.join("MatrixConfig.example.bin");

    fs::create_dir_all(&config_dir).expect("failed to create config directory");
    ensure_user_config(&config_path).expect("failed to generate MatrixConfig.bin");
    validate_user_config(&config_path).expect("invalid MatrixConfig.bin");
    write_if_changed(&example_path, DEFAULT_FILE_TEXT.as_bytes())
        .expect("failed to generate MatrixConfig.example.bin");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/boot/config.rs");
    println!("cargo:rerun-if-changed=config/MatrixConfig.bin");
}

fn ensure_user_config(path: &Path) -> io::Result<()> {
    let needs_default = match fs::metadata(path) {
        Ok(metadata) => metadata.len() == 0,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(error),
    };

    if needs_default {
        fs::write(path, DEFAULT_FILE_TEXT)?;
    }
    Ok(())
}

fn validate_user_config(path: &Path) -> io::Result<()> {
    let bytes = fs::read(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line == CONFIG_HEADER {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: invalid line: {line}", path.display()),
            )
        })?;

        let parsed = value.trim();
        if !parsed.eq_ignore_ascii_case("true") && !parsed.eq_ignore_ascii_case("false") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: invalid boolean: {parsed}", path.display()),
            ));
        }

        match key.trim() {
            "cpuidpresence" | "logger" => {}
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: unknown key: {unknown}", path.display()),
                ));
            }
        }
    }

    Ok(())
}

fn write_if_changed(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Ok(existing) = fs::read(path)
        && existing.as_slice() == contents
    {
        return Ok(());
    }
    fs::write(path, contents)
}
