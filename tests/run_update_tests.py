"""Run the production update parser and transaction tests on the host without transport."""

from pathlib import Path
import json
import subprocess

project = Path(__file__).resolve().parents[1]
output = project / "builds/update-host-tests"
output.mkdir(parents=True, exist_ok=True)
(output / "Cargo.toml").write_text('''[package]
name = "resident-update-host-tests"
version = "0.1.0"
edition = "2024"
[workspace]
[lib]
path = "lib.rs"
[dependencies]
ed25519-dalek = { version = "=2.2.0", default-features = false }
sha2 = { version = "=0.10.9", default-features = false }
''', encoding="utf-8")
(output / "lib.rs").write_text(
    f"#[path = {json.dumps(str(project / 'src/update.rs'))}]\npub mod update;\n"
    f"#[cfg(test)]\n#[path = {json.dumps(str(project / 'tests/update_tests.rs'))}]\nmod tests;\n",
    encoding="utf-8",
)
subprocess.run(["cargo", "test", "--offline", "--manifest-path", str(output / "Cargo.toml"),
                "--target-dir", str(output / "target")], cwd=project, check=True)
