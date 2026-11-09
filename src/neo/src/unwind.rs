use crate::protocol::memory::{CONTEXT_RECORD_BYTES, STACK_MAX_FRAMES};
use crate::user::{MemoryReader, Module, read_exact, symbolize, u16_at, u32_at, u64_at};
use std::collections::{HashMap, HashSet};
use yaxpeax_arch::LengthedInstruction;
use yaxpeax_x86::long_mode::{InstDecoder, Opcode, Operand, RegSpec, register_class};

#[derive(Clone, Debug)]
pub struct UnwindContext {
    pub rip: u64,
    pub rsp: u64,
    pub registers: [u64; 16],
}

impl UnwindContext {
    pub fn from_record(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < CONTEXT_RECORD_BYTES || u64_at(bytes, 200)? != 3 {
            return Err("native user-mode unwind requires a CPL=3 context record".into());
        }
        let rsp = u64_at(bytes, 32)?;
        let mut registers = [0; 16];
        for (index, slot) in [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            .into_iter()
            .enumerate()
        {
            registers[slot] = u64_at(bytes, 72 + index * 8)?;
        }
        registers[4] = rsp;
        Ok(Self {
            rip: u64_at(bytes, 24)?,
            rsp,
            registers,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StackFrame {
    pub rip: u64,
    pub rsp: u64,
    pub symbol: String,
    pub method: String,
}

pub struct UnwindResult {
    pub frames: Vec<StackFrame>,
    pub stop: String,
    pub complete: bool,
}

#[derive(Clone, Copy)]
struct RuntimeFunction {
    begin: u32,
    end: u32,
    unwind: u32,
}

fn runtime_function(
    bytes: &[u8],
    offset: usize,
    module: &Module,
) -> Result<RuntimeFunction, String> {
    let function = RuntimeFunction {
        begin: u32_at(bytes, offset)?,
        end: u32_at(bytes, offset + 4)?,
        unwind: u32_at(bytes, offset + 8)?,
    };
    if function.begin >= function.end || function.end > module.size || function.unwind & 3 != 0 {
        return Err("invalid or unsupported RUNTIME_FUNCTION".into());
    }
    module.address(function.unwind, 4)?;
    Ok(function)
}

fn function_table(
    reader: &mut impl MemoryReader,
    module: &Module,
) -> Result<Vec<RuntimeFunction>, String> {
    let size = module.exception_size as usize;
    if size == 0 {
        return Ok(Vec::new());
    }
    if size > 12 * 262_144 || !size.is_multiple_of(12) {
        return Err("invalid or oversized PE exception directory".into());
    }
    let bytes = read_exact(reader, module.address(module.exception_rva, size)?, size)?;
    let mut table: Vec<RuntimeFunction> = Vec::with_capacity(size / 12);
    for offset in (0..size).step_by(12) {
        let function = runtime_function(&bytes, offset, module)?;
        if table
            .last()
            .is_some_and(|previous| previous.end > function.begin)
        {
            return Err("unsorted or overlapping RUNTIME_FUNCTION table".into());
        }
        table.push(function);
    }
    Ok(table)
}

fn stack_word(
    reader: &mut impl MemoryReader,
    address: u64,
    lower: u64,
    upper: u64,
) -> Result<u64, String> {
    if address < lower || address & 7 != 0 || address.checked_add(8).is_none_or(|end| end > upper) {
        return Err("stack read exceeds the bounded user stack window".into());
    }
    u64_at(&read_exact(reader, address, 8)?, 0)
}

fn add_rsp(context: &mut UnwindContext, amount: u64) -> Result<(), String> {
    context.rsp = context
        .rsp
        .checked_add(amount)
        .ok_or("unwind stack pointer overflow")?;
    context.registers[4] = context.rsp;
    Ok(())
}

fn nonvolatile(register: usize) -> bool {
    matches!(register, 3 | 5 | 6 | 7 | 12..=15)
}

fn epilog(
    reader: &mut impl MemoryReader,
    module: &Module,
    function: RuntimeFunction,
    context: &UnwindContext,
    lower: u64,
    upper: u64,
) -> Result<Option<UnwindContext>, String> {
    let available = (module.base + u64::from(function.end))
        .saturating_sub(context.rip)
        .min(128) as usize;
    if available == 0 {
        return Ok(None);
    }
    let bytes = reader.read(context.rip, available)?;
    if bytes.is_empty() || bytes.len() > available {
        return Err("instruction bytes are unavailable for epilog recognition".into());
    }
    let mut offset = 0;
    let mut candidate = context.clone();
    while offset < bytes.len() {
        let Ok(instruction) = InstDecoder::default().decode_slice(&bytes[offset..]) else {
            if bytes.len() < available {
                return Err("captured instruction bytes end during epilog recognition".into());
            }
            return Ok(None);
        };
        let length = instruction.len().to_const() as usize;
        if length == 0 || offset + length > bytes.len() {
            return Ok(None);
        }
        match instruction.opcode() {
            Opcode::ADD
                if offset == 0
                    && instruction.operand(0)
                        == (Operand::Register {
                            reg: RegSpec::rsp(),
                        }) =>
            {
                let amount = match instruction.operand(1) {
                    Operand::ImmediateI8 { imm } if imm >= 0 => imm as u64,
                    Operand::ImmediateI32 { imm } if imm >= 0 => imm as u64,
                    _ => return Ok(None),
                };
                add_rsp(&mut candidate, amount)?;
            }
            Opcode::LEA
                if offset == 0
                    && instruction.operand(0)
                        == (Operand::Register {
                            reg: RegSpec::rsp(),
                        }) =>
            {
                let (base, displacement) = match instruction.operand(1) {
                    Operand::Disp { base, disp } => (base, i64::from(disp)),
                    Operand::MemDeref { base } => (base, 0),
                    _ => return Ok(None),
                };
                if base.class() != register_class::Q || !nonvolatile(base.num() as usize) {
                    return Ok(None);
                }
                candidate.rsp = candidate.registers[base.num() as usize]
                    .checked_add_signed(displacement)
                    .ok_or("epilog stack overflow")?;
                candidate.registers[4] = candidate.rsp;
            }
            Opcode::POP => {
                let Operand::Register { reg } = instruction.operand(0) else {
                    return Ok(None);
                };
                if reg.class() != register_class::Q || !nonvolatile(reg.num() as usize) {
                    return Ok(None);
                }
                // Defer stack reads until the entire byte sequence is known to
                // be an epilog, so body POP instructions cannot cause false errors.
            }
            Opcode::RETURN | Opcode::JMP => {
                if instruction.opcode() == Opcode::JMP {
                    let displacement = match instruction.operand(0) {
                        Operand::ImmediateI8 { imm } => Some(i64::from(imm)),
                        Operand::ImmediateI32 { imm } => Some(i64::from(imm)),
                        _ => None,
                    };
                    let direct_tail = displacement.is_some_and(|displacement| {
                        let target = context
                            .rip
                            .wrapping_add((offset + length) as u64)
                            .wrapping_add_signed(displacement);
                        target < module.base + u64::from(function.begin)
                            || target >= module.base + u64::from(function.end)
                    });
                    let opcode_offset = offset + usize::from(bytes[offset] & 0xf0 == 0x40);
                    let indirect_tail = bytes.get(opcode_offset) == Some(&0xff)
                        && bytes
                            .get(opcode_offset + 1)
                            .is_some_and(|modrm| modrm & 0xf8 == 0x20);
                    if !direct_tail && !indirect_tail {
                        return Ok(None);
                    }
                }
                let mut replay = context.clone();
                let mut cursor = 0;
                while cursor < offset {
                    let operation = InstDecoder::default()
                        .decode_slice(&bytes[cursor..])
                        .map_err(|_| "invalid epilog")?;
                    match operation.opcode() {
                        Opcode::ADD => {
                            let amount = match operation.operand(1) {
                                Operand::ImmediateI8 { imm } => imm as u64,
                                Operand::ImmediateI32 { imm } => imm as u64,
                                _ => return Err("invalid epilog adjustment".into()),
                            };
                            add_rsp(&mut replay, amount)?;
                        }
                        Opcode::LEA => {
                            replay.rsp = candidate.rsp;
                            replay.registers[4] = replay.rsp;
                        }
                        Opcode::POP => {
                            let Operand::Register { reg } = operation.operand(0) else {
                                return Err("invalid epilog pop".into());
                            };
                            replay.registers[reg.num() as usize] =
                                stack_word(reader, replay.rsp, lower, upper)?;
                            add_rsp(&mut replay, 8)?;
                        }
                        _ => return Err("invalid epilog sequence".into()),
                    }
                    cursor += operation.len().to_const() as usize;
                }
                replay.rip = stack_word(reader, replay.rsp, lower, upper)?;
                add_rsp(&mut replay, 8)?;
                if instruction.opcode() == Opcode::RETURN && instruction.operand_count() != 0 {
                    let Operand::ImmediateU16 { imm } = instruction.operand(0) else {
                        return Err("unsupported epilog return".into());
                    };
                    add_rsp(&mut replay, u64::from(imm))?;
                }
                return Ok(Some(replay));
            }
            _ => return Ok(None),
        }
        offset += length;
    }
    if bytes.len() < available {
        return Err("captured instruction bytes end before the possible epilog terminator".into());
    }
    Ok(None)
}

fn unwind_codes(
    reader: &mut impl MemoryReader,
    module: &Module,
    mut function: RuntimeFunction,
    context: &mut UnwindContext,
    control_pc: u64,
    lower: u64,
    upper: u64,
) -> Result<bool, String> {
    let mut visited = HashSet::new();
    let mut machine_frame = false;
    for _ in 0..16 {
        if !visited.insert(function.unwind) {
            return Err("cyclic chained unwind metadata".into());
        }
        let header = read_exact(reader, module.address(function.unwind, 4)?, 4)?;
        if header[0] & 7 != 1 {
            return Err(format!(
                "unsupported unwind metadata version {}",
                header[0] & 7
            ));
        }
        let flags = header[0] >> 3;
        let count = header[2] as usize;
        let frame_register = (header[3] & 15) as usize;
        let frame_offset = u64::from(header[3] >> 4) * 16;
        if flags & !7 != 0
            || flags & 4 != 0 && flags & 3 != 0
            || frame_register != 0 && !nonvolatile(frame_register)
        {
            return Err("invalid unwind flags or frame register".into());
        }
        let size = 4
            + (count * 2).div_ceil(4) * 4
            + if flags & 4 != 0 {
                12
            } else if flags & 3 != 0 {
                4
            } else {
                0
            };
        let bytes = read_exact(reader, module.address(function.unwind, size)?, size)?;
        let position = control_pc.saturating_sub(module.base + u64::from(function.begin));
        let in_prolog = position < u64::from(header[1]);
        let mut frame_base = context.rsp;
        if frame_register != 0 {
            let mut code_slot = 0;
            while code_slot < count {
                let offset = 4 + code_slot * 2;
                let operation = bytes[offset + 1] & 15;
                let info = bytes[offset + 1] >> 4;
                if operation == 3 && (!in_prolog || u64::from(bytes[offset]) <= position) {
                    frame_base = context.registers[frame_register]
                        .checked_sub(frame_offset)
                        .ok_or("frame base underflow")?;
                    break;
                }
                code_slot += match operation {
                    0 | 2 | 3 | 10 => 1,
                    1 if info == 0 => 2,
                    1 if info == 1 => 3,
                    4 | 8 => 2,
                    5 | 9 => 3,
                    _ => return Err("unsupported unwind operation".into()),
                };
            }
        }
        let mut slot = 0;
        let mut previous_offset = u8::MAX;
        while slot < count {
            let offset = 4 + slot * 2;
            let code_offset = bytes[offset];
            let operation = bytes[offset + 1] & 15;
            let info = (bytes[offset + 1] >> 4) as usize;
            if code_offset > previous_offset || code_offset > header[1] {
                return Err("invalid unwind code ordering".into());
            }
            previous_offset = code_offset;
            let slots = match operation {
                0 | 2 | 3 | 10 => 1,
                1 if info == 0 => 2,
                1 if info == 1 => 3,
                4 | 8 => 2,
                5 | 9 => 3,
                _ => return Err("unsupported unwind operation".into()),
            };
            if slot + slots > count {
                return Err("truncated unwind operation operands".into());
            }
            if !in_prolog || u64::from(code_offset) <= position {
                match operation {
                    0 => {
                        if !nonvolatile(info) {
                            return Err("invalid saved nonvolatile register".into());
                        }
                        context.registers[info] = stack_word(reader, context.rsp, lower, upper)?;
                        add_rsp(context, 8)?;
                    }
                    1 => {
                        let amount = if info == 0 {
                            u64::from(u16_at(&bytes, offset + 2)?) * 8
                        } else {
                            u64::from(u32_at(&bytes, offset + 2)?)
                        };
                        add_rsp(context, amount)?;
                    }
                    2 => add_rsp(context, info as u64 * 8 + 8)?,
                    3 => {
                        if frame_register == 0 || info != 0 {
                            return Err("invalid unwind frame register".into());
                        }
                        context.rsp = context.registers[frame_register]
                            .checked_sub(frame_offset)
                            .ok_or("frame register underflow")?;
                        context.registers[4] = context.rsp;
                    }
                    4 | 5 => {
                        if !nonvolatile(info) {
                            return Err("invalid saved register".into());
                        }
                        let displacement = if operation == 4 {
                            u64::from(u16_at(&bytes, offset + 2)?) * 8
                        } else {
                            u64::from(u32_at(&bytes, offset + 2)?)
                        };
                        let address = frame_base
                            .checked_add(displacement)
                            .ok_or("saved register address overflow")?;
                        context.registers[info] = stack_word(reader, address, lower, upper)?;
                    }
                    // XMM restoration cannot affect the integer frame walk.
                    8 | 9 => {}
                    10 => {
                        if info > 1 || machine_frame {
                            return Err("invalid machine frame unwind".into());
                        }
                        let base = context
                            .rsp
                            .checked_add(if info == 1 { 8 } else { 0 })
                            .ok_or("machine frame overflow")?;
                        if stack_word(
                            reader,
                            base.checked_add(8).ok_or("machine frame overflow")?,
                            lower,
                            upper,
                        )? & 3
                            != 3
                        {
                            return Err("machine frame crosses the user-mode boundary".into());
                        }
                        context.rip = stack_word(reader, base, lower, upper)?;
                        context.rsp = stack_word(
                            reader,
                            base.checked_add(24).ok_or("machine frame overflow")?,
                            lower,
                            upper,
                        )?;
                        context.registers[4] = context.rsp;
                        machine_frame = true;
                    }
                    _ => return Err("unsupported unwind operation".into()),
                }
            }
            slot += slots;
        }
        if flags & 4 == 0 {
            return Ok(machine_frame);
        }
        function = runtime_function(&bytes, 4 + (count * 2).div_ceil(4) * 4, module)?;
    }
    Err("chained unwind metadata exceeds its depth limit".into())
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "cli", derive(serde::Deserialize, serde::Serialize))]
pub struct DynamicTable {
    pub base: u64,
    pub start: u64,
    pub end: u64,
    pub address: u64,
    pub count: u32,
    pub kind: u32,
}

const USER_END: u64 = 0x8000_0000_0000;
const TABLE_LIMIT: u32 = 262_144;

fn user_range(address: u64, size: u64) -> bool {
    address != 0 && address.checked_add(size).is_some_and(|end| end <= USER_END)
}

impl DynamicTable {
    pub fn validate(&self) -> Result<(), String> {
        if !user_range(self.base, 1)
            || self.start < self.base
            || self.end <= self.start
            || self.end > USER_END
            || self.end - self.base > u64::from(u32::MAX)
            || self.count > TABLE_LIMIT
            || self.kind > 3
            || self.kind != 2
                && self.count != 0
                && (self.address & 3 != 0 || !user_range(self.address, u64::from(self.count) * 12))
        {
            return Err("invalid dynamic function table descriptor".into());
        }
        Ok(())
    }

    fn image(&self) -> Module {
        Module {
            base: self.base,
            size: (USER_END - self.base).min(u64::from(u32::MAX)) as u32,
            entry_point: 0,
            name: "dynamic".into(),
            path: String::new(),
            sections: Vec::new(),
            exports: Vec::new(),
            export_error: None,
            exception_rva: 0,
            exception_size: 0,
        }
    }
}

pub fn dynamic_list_head(
    reader: &mut impl MemoryReader,
    modules: &[Module],
) -> Result<u64, String> {
    let entry = crate::user::resolve_address(modules, "ntdll!RtlGetFunctionTableListHead")?;
    let module = modules
        .iter()
        .find(|module| module.contains(entry))
        .ok_or("invalid list getter")?;
    let bytes = read_exact(reader, entry, 12)?;
    let prefix = if bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) {
        4
    } else {
        0
    };
    let code = &bytes[prefix..];
    if !code.starts_with(&[0x48, 0x8d, 0x05]) || code[7] != 0xc3 {
        return Err(
            "unsupported RtlGetFunctionTableListHead implementation; supply --dynamic-list HEAD"
                .into(),
        );
    }
    let displacement = i32::from_le_bytes(code[3..7].try_into().unwrap());
    let head = (entry + prefix as u64 + 7).wrapping_add_signed(i64::from(displacement));
    if !module.contains(head) || !module.contains(head + 15) {
        return Err("dynamic function table head is outside ntdll".into());
    }
    Ok(head)
}

pub fn dynamic_tables(
    reader: &mut impl MemoryReader,
    head: u64,
) -> Result<Vec<DynamicTable>, String> {
    if head & 7 != 0 || !user_range(head, 16) {
        return Err("invalid dynamic function list head".into());
    }
    let links = read_exact(reader, head, 16)?;
    let mut next = u64_at(&links, 0)?;
    let mut previous = head;
    let mut seen = HashSet::new();
    let mut tables = Vec::new();
    while next != head {
        if next & 7 != 0 || !user_range(next, 88) || seen.len() >= 256 || !seen.insert(next) {
            return Err("invalid or oversized dynamic function table list".into());
        }
        let bytes = read_exact(reader, next, 88)?;
        if u64_at(&bytes, 8)? != previous {
            return Err("inconsistent dynamic function table links".into());
        }
        let table = DynamicTable {
            address: u64_at(&bytes, 16)?,
            start: u64_at(&bytes, 32)?,
            end: u64_at(&bytes, 40)?,
            base: u64_at(&bytes, 48)?,
            kind: u32_at(&bytes, 80)?,
            count: u32_at(&bytes, 84)?,
        };
        table.validate()?;
        tables.push(table);
        previous = next;
        next = u64_at(&bytes, 0)?;
    }
    if u64_at(&links, 8)? != previous || read_exact(reader, head, 16)? != links {
        return Err("dynamic function table list changed during collection".into());
    }
    Ok(tables)
}

fn lookup_sparse(
    reader: &mut impl MemoryReader,
    image: &Module,
    address: u64,
    count: u32,
    pc: u64,
) -> Result<Option<RuntimeFunction>, String> {
    let rva = pc - image.base;
    let mut low = 0;
    let mut high = count;
    while low < high {
        let middle = low + (high - low) / 2;
        let bytes = read_exact(reader, address + u64::from(middle) * 12, 12)?;
        let function = runtime_function(&bytes, 0, image)?;
        if rva < u64::from(function.begin) {
            high = middle;
        } else if rva >= u64::from(function.end) {
            low = middle + 1;
        } else {
            return Ok(Some(function));
        }
    }
    Ok(None)
}

fn lookup_dynamic(
    reader: &mut impl MemoryReader,
    table: &DynamicTable,
    image: &Module,
    pc: u64,
) -> Result<Option<RuntimeFunction>, String> {
    table.validate()?;
    if table.kind == 2 {
        return Err("dynamic function table requires a callback provider".into());
    }
    if table.kind != 1 {
        return lookup_sparse(reader, image, table.address, table.count, pc);
    }
    let bytes = read_exact(reader, table.address, table.count as usize * 12)?;
    let mut found = None;
    for offset in (0..bytes.len()).step_by(12) {
        let function = runtime_function(&bytes, offset, image)?;
        if (u64::from(function.begin)..u64::from(function.end)).contains(&(pc - table.base))
            && found.replace(function).is_some()
        {
            return Err("overlapping dynamic runtime functions".into());
        }
    }
    Ok(found)
}

pub fn unwind(
    reader: &mut impl MemoryReader,
    modules: &[Module],
    context: UnwindContext,
    maximum: usize,
) -> UnwindResult {
    unwind_with_tables(reader, modules, &[], context, maximum, false)
}

pub fn unwind_with_tables(
    reader: &mut impl MemoryReader,
    modules: &[Module],
    dynamic: &[DynamicTable],
    mut context: UnwindContext,
    maximum: usize,
    captured: bool,
) -> UnwindResult {
    let mut result = UnwindResult {
        frames: Vec::new(),
        stop: String::new(),
        complete: false,
    };
    if maximum == 0
        || maximum > STACK_MAX_FRAMES
        || context.rsp & 7 != 0
        || context.rsp >= 0x8000_0000_0000
    {
        result.stop = "invalid user unwind context or frame limit".into();
        return result;
    }
    let lower = context.rsp;
    let upper = lower.saturating_add(1024 * 1024).min(0x8000_0000_0000);
    let mut tables = HashMap::new();
    let mut visited = HashSet::new();
    for index in 0..maximum {
        if context.rip == 0 {
            result.complete = true;
            result.stop = "end_of_stack".into();
            return result;
        }
        if context.rip >= 0x8000_0000_0000 || !visited.insert((context.rip, context.rsp)) {
            result.stop = "invalid or cyclic user stack".into();
            return result;
        }
        result.frames.push(StackFrame {
            rip: context.rip,
            rsp: context.rsp,
            symbol: symbolize(modules, context.rip),
            method: String::new(),
        });
        let step = (|| -> Result<&str, String> {
            let control_pc = context.rip.saturating_sub(u64::from(index != 0));
            let static_image = modules.iter().find(|module| module.contains(control_pc));
            let mut function = None;
            if let Some(module) = static_image {
                let size = module.exception_size;
                if captured && size != 0 {
                    if size / 12 > TABLE_LIMIT || !size.is_multiple_of(12) {
                        return Err("invalid or oversized PE exception directory".into());
                    }
                    function = lookup_sparse(
                        reader,
                        module,
                        module.address(module.exception_rva, size as usize)?,
                        size / 12,
                        control_pc,
                    )?;
                } else if !captured {
                    if let std::collections::hash_map::Entry::Vacant(entry) =
                        tables.entry(module.base)
                    {
                        entry.insert(function_table(reader, module)?);
                    }
                    let table = &tables[&module.base];
                    let rva = control_pc - module.base;
                    let position =
                        table.partition_point(|function| u64::from(function.begin) <= rva);
                    function = position
                        .checked_sub(1)
                        .and_then(|position| table.get(position))
                        .filter(|function| rva < u64::from(function.end))
                        .copied();
                }
            }
            let mut dynamic_image = None;
            if function.is_none() {
                for table in dynamic
                    .iter()
                    .filter(|table| (table.start..table.end).contains(&control_pc))
                {
                    let image = table.image();
                    if let Some(entry) = lookup_dynamic(reader, table, &image, control_pc)? {
                        if function.replace(entry).is_some() {
                            return Err("multiple dynamic function tables cover this frame".into());
                        }
                        dynamic_image = Some(image);
                    }
                }
            }
            let module = dynamic_image.as_ref().or(static_image).ok_or(
                "frame is outside loaded modules and has no available dynamic function entry",
            )?;
            let previous_rsp = context.rsp;
            let method = if let Some(function) = function {
                if let Some(caller) = epilog(reader, module, function, &context, lower, upper)? {
                    context = caller;
                    "epilog"
                } else {
                    if !unwind_codes(
                        reader,
                        module,
                        function,
                        &mut context,
                        control_pc,
                        lower,
                        upper,
                    )? {
                        context.rip = stack_word(reader, context.rsp, lower, upper)?;
                        add_rsp(&mut context, 8)?;
                    }
                    if dynamic_image.is_some() {
                        "dynamic_pdata"
                    } else {
                        "pdata"
                    }
                }
            } else {
                if !module.sections.iter().any(|section| {
                    section.characteristics & 0x2000_0000 != 0
                        && control_pc >= section.start
                        && control_pc - section.start < u64::from(section.size)
                }) {
                    return Err("leaf frame is outside an executable PE section".into());
                }
                context.rip = stack_word(reader, context.rsp, lower, upper)?;
                add_rsp(&mut context, 8)?;
                "leaf"
            };
            if context.rsp <= previous_rsp || context.rsp > upper || context.rsp & 7 != 0 {
                return Err("unwind stack pointer did not advance within the stack window".into());
            }
            Ok(method)
        })();
        match step {
            Ok(method) => {
                if let Some(frame) = result.frames.last_mut() {
                    frame.method = method.into();
                }
            }
            Err(error) => {
                result.stop = error;
                return result;
            }
        }
    }
    result.complete = context.rip == 0;
    result.stop = if result.complete {
        "end_of_stack"
    } else {
        "frame_limit"
    }
    .into();
    result
}
