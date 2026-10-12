"""Strand a refresh lock and verify bounded recovery in the current test VM."""
import ast
import json
import os
from pathlib import Path
import re
import struct
import traceback

import ida_dbg
import ida_ida
import ida_idd
import ida_idp
import ida_pro
import idc

project = Path(__file__).resolve().parents[1]
output = Path(os.environ['MATRIXHV_EVIDENCE_ROOT']).resolve()
output.relative_to(project / 'builds')
baseline = json.loads(Path(os.environ['MATRIXHV_REFRESH_BASELINE']).read_text())
mode = os.environ['MATRIXHV_REFRESH_FAULT_MODE']
assert mode in ('strand', 'release')
assert len(baseline['cpus']) == len(baseline['contexts']) == 8
session = baseline['interception']['session']

layout_path = project / 'tests/collect_boot_state.py'
layout_tree = ast.parse(layout_path.read_text())
layout_nodes = [node for node in layout_tree.body if isinstance(node, ast.FunctionDef)
                and node.name in ('structure', 'plain_layout')]
layout_scope = {'re': re}
exec(compile(ast.Module(body=layout_nodes, type_ignores=[]), str(layout_path), 'exec'), layout_scope)
source = (project / 'src/memory/interception.rs').read_text() + (project / 'src/protocol.rs').read_text()
fields, _, _ = layout_scope['plain_layout'](source, 'Session', stop='refresh_lock')
profile, _, _ = layout_scope['plain_layout'](source, 'RoadEptProfile')
lock_address = session + fields['refresh_lock']
result = {'mode': mode, 'session': session, 'refresh_lock': lock_address, 'cpus': []}
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
    names = [descriptor[0].upper() for descriptor in ida_idd.dbg_get_registers()]
    for index in range(8):
        thread = ida_dbg.getn_thread(index)
        ida_dbg.select_thread(thread)
        registers = dict(zip(names, (value.ival for value in ida_dbg.get_reg_vals(thread))))
        result['cpus'].append({'thread': thread, 'registers': registers,
            'cr3': idc.send_dbg_command('r cr3'),
            'rip_bytes': idc.get_bytes(registers['RIP'], 16, True).hex()})
    idc.send_dbg_command('phys')

    def quad(address):
        return struct.unpack('<Q', idc.get_bytes(address, 8, True))[0]

    active = quad(session)
    cause = quad(session + fields['cause'])
    lock = quad(lock_address)
    configuration = session + fields['configuration']
    options = struct.unpack('<I', idc.get_bytes(configuration + profile['options'], 4, True))[0]
    assert quad(configuration + profile['cpu_mask']) == 0xff
    assert quad(configuration + profile['hook_count']) == 1
    assert options & 20 == 20
    assert quad(session + fields['lock']) == 0
    result['before'] = {'active': active, 'cause': cause, 'lock': lock, 'options': options}
    if mode == 'strand':
        assert active == 1 and cause == lock == 0
        value = 1
    else:
        assert active == 2 and cause == 7 and lock == 1
        value = 0
    data = struct.pack('<Q', value)
    ida_dbg.write_dbg_memory(lock_address, data)
    ida_dbg.invalidate_dbgmem_contents(lock_address, 8)
    assert idc.get_bytes(lock_address, 8, True) == data
    result['after_lock'] = value
    result['passed'] = True
    exit_code = 0
except Exception:
    result['error'] = traceback.format_exc()
finally:
    if attached:
        idc.send_dbg_command('virt')
        ida_dbg.detach_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 10)
    (output / f'refresh-fault-{mode}.json').write_text(json.dumps(result, indent=2))
    ida_pro.qexit(exit_code)
