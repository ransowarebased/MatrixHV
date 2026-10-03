use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_FILE_TEXT: &str = "MATRIXHV_CONFIG_V2\ncpuidpresence=false\nlogger=true\nVtNested=true\nVtEvmcs=false\nVmxTest=false\n";

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is missing");
    let build_dir = Path::new(&manifest_dir).join("builds");
    let config_path = build_dir.join("MatrixConfig.bin");

    fs::create_dir_all(&build_dir).expect("failed to create build directory");
    ensure_user_config(&config_path).expect("failed to generate MatrixConfig.bin");
    let output = env::var_os("OUT_DIR").expect("OUT_DIR is missing");
    let public_key = Path::new(&output).join("update-public-key.bin");
    let key_path = env::var_os("MATRIXHV_UPDATE_SIGNING_KEY").unwrap_or_else(|| {
        Path::new(
            &env::var_os("LOCALAPPDATA")
                .or_else(|| env::var_os("HOME"))
                .expect("user data directory is missing"),
        )
        .join("MatrixHV")
        .join("update-signing.key")
        .into_os_string()
    });
    let python = env::var_os("MATRIXHV_PYTHON").unwrap_or_else(|| "python".into());
    let status = Command::new(&python)
        .arg(Path::new(&manifest_dir).join("scripts/build_update.py"))
        .args(["bootstrap", "--key"])
        .arg(&key_path)
        .arg("--public")
        .arg(&public_key)
        .status()
        .expect("failed to prepare runtime update trust key");
    assert!(
        status.success(),
        "runtime update trust key preparation failed"
    );
    println!(
        "cargo:rustc-env=MATRIXHV_UPDATE_PUBLIC_KEY={}",
        public_key.display()
    );
    let version = env::var("SOURCE_DATE_EPOCH")
        .map(|value| {
            value
                .parse::<u64>()
                .expect("SOURCE_DATE_EPOCH must be an unsigned decimal integer")
        })
        .unwrap_or_else(|_| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("invalid system time")
                .as_secs()
        });
    assert!(version != 0, "the resident core version must be positive");
    println!("cargo:rustc-env=MATRIXHV_CORE_VERSION={version}");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=scripts/build_update.py");
    println!("cargo:rerun-if-env-changed=MATRIXHV_UPDATE_SIGNING_KEY");
    println!("cargo:rerun-if-env-changed=MATRIXHV_PYTHON");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-changed=build.rs");
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
