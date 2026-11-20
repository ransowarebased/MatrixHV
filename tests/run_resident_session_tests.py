"""Execute the production read-only diagnostic handler against synthetic L0 state."""
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
output = root / "builds" / "resident-session-tests"
output.mkdir(parents=True, exist_ok=True)
source = (root / "src/asm/diagnostics.S").read_text(encoding="utf-8")
handler = source.split(".Lresident_dispatch_cpuid_resident_session:\n", 1)[1].split(
    ".Lresident_dispatch_cpuid_nested_state:", 1
)[0]
for key, value in {"event_interception_context": 0, "interception_active": 0, "interception_cause": 8}.items():
    handler = handler.replace("{" + key + "}", str(value))
assembly = """
.text
.global test_session_query
test_session_query:
push rbx
mov r9, rcx
mov r11, rdx
""" + handler + """
.Lresident_dispatch_cpuid_diagnostic_store:
mov dword ptr [r11], eax
mov dword ptr [r11 + 4], ebx
mov dword ptr [r11 + 8], ecx
mov dword ptr [r11 + 12], edx
pop rbx
ret
"""
(output / "query.S").write_text(assembly, encoding="utf-8")
test = r'''
use std::arch::global_asm;
global_asm!(include_str!("query.S"));
unsafe extern "C" { fn test_session_query(event: *const u64, output: *mut u32); }
#[test]
fn missing_allocation_is_explicit_and_does_not_dereference_null() {
    let event = 0_u64;
    let mut output = [u32::MAX; 4];
    unsafe { test_session_query(&event, output.as_mut_ptr()); }
    assert_eq!(output, [0; 4]);
}
#[test]
fn observes_resident_state_without_mutating_it() {
    for state in [0_u64, 1, 2, 3] {
        let session = [state, 15, 0xfeedface];
        let original = session;
        let event = session.as_ptr() as u64;
        let mut output = [u32::MAX; 4];
        unsafe { test_session_query(&event, output.as_mut_ptr()); }
        assert_eq!(output, [1, state as u32, 15, 0]);
        assert_eq!(session, original);
        assert_eq!(event, session.as_ptr() as u64);
    }
}
'''
(output / "tests.rs").write_text(test, encoding="utf-8")
subprocess.run(["rustc", "--test", str(output / "tests.rs"), "-o", str(output / "tests.exe")], check=True)
subprocess.run([str(output / "tests.exe")], check=True)
