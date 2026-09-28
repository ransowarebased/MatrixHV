use std::env;
use std::fs;
use std::io;
use std::path::Path;

const DEFAULT_FILE_TEXT: &str =
    "MATRIXHV_CONFIG_V2\ncpuidpresence=false\nlogger=true\nVtNested=true\nVmxTest=false\n";

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is missing");
    let build_dir = Path::new(&manifest_dir).join("builds");
    let config_path = build_dir.join("MatrixConfig.bin");

    fs::create_dir_all(&build_dir).expect("failed to create build directory");
    ensure_user_config(&config_path).expect("failed to generate MatrixConfig.bin");
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
