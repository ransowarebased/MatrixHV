"""Capture every VMware CPU through a headless IDA GDB session."""
import json
import os
from pathlib import Path
import traceback

import ida_bytes
import ida_dbg
import ida_ida
import ida_idd
import ida_idp
import ida_pro
import ida_segment
import ida_ua
import idc

output = Path(os.environ['MATRIXHV_EVIDENCE_ROOT']).resolve()
output.relative_to(Path(__file__).resolve().parents[1] / 'builds')
sample = os.environ['MATRIXHV_EVIDENCE_SAMPLE']
result = {'cpus': [], 'status': 'RUNNING'}
attached = False
exit_code = 1
try:
    if not ida_idp.set_processor_type('metapc', ida_idp.SETPROC_LOADER):
        raise RuntimeError('Intel x64 processor module unavailable')
    ida_ida.inf_set_app_bitness(64)
    if not ida_dbg.load_debugger('gdb', True):
        raise RuntimeError('GDB debugger unavailable')
    ida_dbg.set_remote_debugger('127.0.0.1', '', 8864)
    ida_dbg.start_process('', '', '')
    event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 10)
    attached = ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK
    if event <= 0 or ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        raise RuntimeError('VM did not suspend')
    names = [descriptor[0].upper() for descriptor in ida_idd.dbg_get_registers()]
    for index in range(ida_dbg.get_thread_qty()):
        thread = ida_dbg.getn_thread(index)
        ida_dbg.select_thread(thread)
        registers = dict(zip(names, (value.ival for value in ida_dbg.get_reg_vals(thread))))
        code = idc.get_bytes(registers['RIP'], 32, True)
        if code is None:
            raise RuntimeError('Cannot read CPU instruction bytes')
        result['cpus'].append({'thread': thread, 'registers': registers,
            'cr3': idc.send_dbg_command('r cr3'), 'cr4': idc.send_dbg_command('r cr4'),
            'bytes': code.hex()})
    if not result['cpus']:
        raise RuntimeError('No CPUs returned')
    result['status'] = 'PASS'
    exit_code = 0
except Exception:
    result['error'] = traceback.format_exc()
finally:
    if attached:
        ida_dbg.detach_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 10)
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK:
            result['status'] = 'FAIL'
            result['error'] = 'Debugger remained attached'
            exit_code = 1
    if exit_code == 0:
        for cpu in result['cpus']:
            rip = cpu['registers']['RIP']
            code = bytes.fromhex(cpu['bytes'])
            if not ida_segment.get_segment_info(None, rip):
                ida_segment.add_segm(0, rip & ~4095, (rip + 4095 + len(code)) & ~4095, 'VM_SNAPSHOT', 'CODE')
            ida_segment.set_segment_addressing(rip, 2)
            ida_bytes.put_bytes(rip, code)
            instruction = ida_ua.insn_t()
            cpu['disassembly'] = []
            cursor = rip
            for _ in range(6):
                size = ida_ua.decode_insn(instruction, cursor)
                if size == 0 or cursor + size > rip + len(code):
                    break
                idc.create_insn(cursor)
                cpu['disassembly'].append(idc.generate_disasm_line(cursor, 0))
                cursor += size
    (output / (sample + '-cpus.json')).write_text(json.dumps(result, indent=2))
    ida_pro.qexit(exit_code)
