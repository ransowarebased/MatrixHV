"""Run the production update parser and transaction tests on the host without transport."""

from pathlib import Path
import subprocess

project = Path(__file__).resolve().parents[1]
subprocess.run(
    ["cargo", "test", "--offline", "--locked", "-p", "matrixhv-sdk", "--features", "update", "--test", "update"],
    cwd=project,
    check=True,
)
