"""Execute the resident interception flow with modeled privileged instructions."""
from pathlib import Path
import re
import subprocess

project = Path(__file__).resolve().parents[1]
output = project / "builds" / "interception-runtime-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/memory/interception.rs").read_text()


def item(text, declaration):
    start = text.index(declaration)
    cursor = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[cursor] == "{") - (text[cursor] == "}")
        cursor += 1
    return text[start:cursor]


runtime = item(source, 'pub(crate) mod runtime')
for declaration, replacement in [
    ('fn debug_registers()', 'fn debug_registers() -> [u64; 5] { crate::hardware::debug_registers() }'),
    ('fn load_debug(', 'fn load_debug(registers: &[u64; 5]) { crate::hardware::load_debug(registers); }'),
    ('fn invalidate(', 'fn invalidate(ept: u64) -> Result<(), ()> { crate::hardware::invalidate(ept) }'),
    ('fn entry_bits(', 'fn entry_bits(pointer: u64, set: u64, clear: u64) { crate::hardware::entry_bits(pointer, set, clear); }'),
    ('fn shared_entry(', 'fn shared_entry(pointer: u64, target: u64, permissions: u64) { crate::hardware::shared_entry(pointer, target, permissions); }'),
    ('fn page_byte(', 'fn page_byte(address: u64, value: Option<u8>) -> u8 { crate::hardware::page_byte(address, value) }'),
    ('fn clock()', 'fn clock() -> u64 { crate::hardware::clock() }'),
    ('fn syscall_msrs()', 'fn syscall_msrs() -> [u64; 2] { crate::hardware::syscall_msrs() }'),
    ('fn fetch_instruction(', 'fn fetch_instruction(_: &ResidentBootContext, _: &RoadEptProfile, rip: u64, execution: &mut [u8; 15], original: &mut [u8; 15]) -> usize { crate::hardware::fetch_instruction(rip, execution, original) }'),
    ('fn original_value(', 'fn original_value(address: u64, width: usize, value: Option<u64>) -> u64 { crate::hardware::original_value(address, width, value) }'),
]:
    runtime = runtime.replace(item(runtime, declaration), replacement)
start = runtime.index('        if !no_flush &&')
end = runtime.index('        Ok(2)', start)
runtime = runtime[:start] + '''        if !no_flush && read(SECONDARY_VM_EXEC_CONTROL)? & (1 << 5) != 0 {
            crate::hardware::invalidate_vpid(read(VIRTUAL_PROCESSOR_ID)?)?;
        }
''' + runtime[end:]
assert 'core::arch::asm!' not in runtime
engine = source[:source.index('pub(crate) trait InterceptionMemory')]
engine = engine.replace('use crate::memory::access::{PhysicalMemory, page_mapping};', '')
engine = re.sub(r'const OPTIONS: u32 = .*?;', '', engine, flags=re.S)
# Split ownership is tested by the frontend harness. Keep its storage opaque
# here while preserving the complete session layout and resident ABI assertions.
engine = engine.replace(item(source, 'struct BaseSplit'), 'struct BaseSplit { storage: [u64; 6] }')
engine = engine.replace('        self.splits.get_mut().fill(BaseSplit::default());',
                        '        for split in self.splits.get_mut() { split.storage.fill(0); }')
engine += '\n'.join(item(source, declaration) for declaration in ['fn canonical(', 'fn bank_base(', 'fn expired(', 'fn lock_refresh(', 'fn data_root(', 'fn data_leaves(', 'fn root_matches(', 'fn baseline_page(', 'fn merge_byte(', 'fn cpuid_values(']) + '\n' + runtime
abi = (project / 'src/vmx/resident/abi.rs').read_text()
cpu = 'use core::sync::atomic::AtomicU64;\n#[repr(C)]\n#[derive(Default)]\n' + item(abi, 'pub struct InterceptionCpuState')
vmcs = (project / 'src/vmx/vmcs.rs').read_text()
constants = '\n'.join(re.findall(r'pub const \w+: u64 = (?:0x[0-9a-fA-F_]+|\d+);', vmcs))
definitions = '''pub mod protocol { include!("../../src/protocol.rs"); }
pub mod arch {
    pub struct Leaf { pub eax: u32 }
    pub fn leaf(_: u32) -> Leaf { Leaf { eax: 48 } }
}
pub mod memory { pub mod interception {
''' + engine + '''
} }
pub mod vmx {
    pub mod vmcs {
''' + constants + '''
        pub fn vmread(field: u64) -> Result<u64, ()> { crate::hardware::read(field) }
        pub fn vmwrite(field: u64, value: u64) -> Result<(), ()> { crate::hardware::write(field, value) }
    }
    pub mod resident { pub mod abi {
''' + cpu + '''
        #[derive(Default)]
        pub struct NestedState { pub active: u64, pub l2_active: u64, pub host_misc: u64 }
        #[derive(Default)]
        pub struct ResidentBootContext {
            pub event_context: u64,
            pub cache_ept_pointer: u64,
            pub eptp_switches: u64,
            pub telemetry_active: u64,
            pub mtf_exits: u64,
            pub last_qualification: u64,
            pub last_reason: u64,
            pub diagnostic_interval_tsc: u64,
            pub diagnostic_expired: u64,
            pub processor_number: u64,
            pub nested: NestedState,
            pub interception: InterceptionCpuState,
        }
        pub struct ResidentEventContext { pub interception_context_physical: u64 }
    } }
}
'''
(output / 'definitions.rs').write_text(definitions)
binary = output / 'runtime.exe'
host = next(line.removeprefix('host: ') for line in subprocess.check_output(['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
(output / 'Cargo.toml').write_text('''[package]
name = "interception-runtime-dependencies"
version = "0.1.0"
edition = "2024"
[lib]
path = "dependencies.rs"
[dependencies]
yaxpeax-x86 = { version = "2.2.0", default-features = false }
yaxpeax-arch = { version = "0.3.2", default-features = false }
''')
(output / 'dependencies.rs').write_text('pub use yaxpeax_x86; pub use yaxpeax_arch;')
subprocess.run(['cargo', 'build', '--manifest-path', str(output / 'Cargo.toml'), '--target', host,
                '--target-dir', str(output / 'target')], cwd=project, check=True)
deps = output / 'target' / host / 'debug' / 'deps'
externs = []
for name in ['yaxpeax_x86', 'yaxpeax_arch']:
    externs += ['--extern', f'{name}={next(deps.glob("lib" + name + "-*.rlib"))}']
subprocess.run(['rustc', '--edition=2024', '-Dwarnings', '--test', str(project / 'tests/interception_runtime_tests.rs'),
                '-L', f'dependency={deps}', *externs, '-o', str(binary)], cwd=project, check=True)
subprocess.run([str(binary)], cwd=project, check=True)
