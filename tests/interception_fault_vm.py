"""Inject and inspect a stranded rendezvous owner in the isolated VMware guest."""
import hashlib
import json
import os
from pathlib import Path
import struct
import traceback

import ida_dbg
import ida_ida
import ida_idp
import ida_pro
import idc

root = Path(os.environ['MATRIXHV_EVIDENCE_ROOT']).resolve()
project = Path(__file__).resolve().parents[1]
root.relative_to(project / 'builds')
mode = os.environ['MATRIXHV_FAULT_MODE']
assert mode in ('strand', 'inspect', 'release')
baseline = json.loads((root / 'updated-state.json').read_text())
assert len(baseline['cpus']) == 8
package = (root / 'MatrixHV.mxcore').read_bytes()
code_end = struct.unpack_from('<I', package, 260)[0]
image_offset = struct.unpack_from('<I', package, 20)[0]
bank = {cpu['bank'] for cpu in baseline['update']['cpu_states']}
assert len(bank) == 1 and None not in bank
base = baseline['update']['banks'][bank.pop()]
# EPT cache state precedes the rendezvous state in the package's writable region.
state = base + code_end + 16 + 4192
owner = next(c['address'] for c in baseline['contexts'] if c['values']['processor_number'] == 0)
result = {'mode': mode, 'base': base, 'state': state, 'owner_context': owner}
attached = False
exit_code = 1
try:
    assert ida_idp.set_processor_type('metapc', ida_idp.SETPROC_LOADER)
    ida_ida.inf_set_app_bitness(64)
    assert ida_dbg.load_debugger('gdb', True)
    ida_dbg.set_remote_debugger('127.0.0.1', '', 8864)
    ida_dbg.start_process('', '', '')
    assert ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 10) > 0
    attached = ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK
    assert attached and ida_dbg.get_thread_qty() == 8
    idc.send_dbg_command('phys')
    code = idc.get_bytes(base, code_end, True)
    assert code is not None
    assert hashlib.sha256(code).digest() == hashlib.sha256(package[image_offset:image_offset+code_end]).digest()
    values = struct.unpack('<4Q', idc.get_bytes(state, 32, True))
    result['before'] = dict(zip(('owner', 'epoch', 'failure', 'recovered'), values))
    def store(offset, value):
        data = struct.pack('<Q', value)
        written = ida_dbg.write_dbg_memory(state + offset, data)
        result.setdefault('writes', []).append({'offset': offset, 'written': written})
        ida_dbg.invalidate_dbgmem_contents(state + offset, 8)
        actual = idc.get_bytes(state + offset, 8, True)
        assert actual == data, f'Debugger write failed: written={written}, observed={actual!r}'
    if mode == 'strand':
        assert values[0] == values[2] == values[3] == 0
        store(8, values[1] + 1)
        store(0, owner)
    elif mode == 'release':
        assert values[0] == owner and values[2] == values[1] and values[3] == 0xff
        store(0, 0)
    else:
        assert values[0] == owner and values[2] == values[1] and values[3] == 0xff
        records = idc.get_bytes(state + 32 + 1024, 4096, True)
        result['records'] = [dict(zip(('phase', 'owner', 'epoch', 'pending', 'rip', 'gpa', 'write_step', 'tsc'), struct.unpack_from('<8Q', records, cpu * 64))) for cpu in range(8)]
        assert any(record['phase'] == 5 and record['owner'] == owner for record in result['records'])
    result['passed'] = True
    exit_code = 0
except Exception:
    result['error'] = traceback.format_exc()
finally:
    if attached:
        idc.send_dbg_command('virt')
        ida_dbg.detach_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 10)
    (root / f'fault-{mode}.json').write_text(json.dumps(result, indent=2))
    ida_pro.qexit(exit_code)
