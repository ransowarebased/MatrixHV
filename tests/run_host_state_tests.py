"""Exercise the production resident host GDT selector validation on the host."""

from pathlib import Path
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds/host-state-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/vmx/state.rs").read_text(encoding="utf-8")
selector_function = source[source.index("fn host_selector("):source.index("fn write_segment(")]
constants = source[source.index("const HOST_CODE_SELECTOR:"):source.index("const TSS_LIMIT:")]
selectors = source[source.index("#[derive(Clone, Copy)]\npub(crate) struct ResidentHostSelectors"):
                   source.index("impl ResidentHostTables {")]
definitions = """
mod arch {
    #[derive(Clone, Copy, Default)]
    pub struct SegmentState { pub selector: u16 }
    #[derive(Clone, Copy, Default)]
    pub struct SegmentationState {
        pub es: SegmentState, pub cs: SegmentState, pub ss: SegmentState,
        pub ds: SegmentState, pub fs: SegmentState, pub gs: SegmentState,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostTablesError { InvalidCodeLayout }
""" + selector_function + constants + selectors
(output / "definitions.rs").write_text(definitions, encoding="utf-8")
executable = output / "host-state-tests.exe"
subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "--test",
                str(project / "tests/host_state_tests.rs"), "-o", str(executable)],
               cwd=project, check=True)
subprocess.run([str(executable)], cwd=project, check=True)
