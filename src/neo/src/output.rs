use serde_json::{Map, Value, json};
use std::cell::Cell;
use std::io::{self, Write};

thread_local! {
    static JSON: Cell<bool> = const { Cell::new(false) };
    static EMITTED: Cell<bool> = const { Cell::new(false) };
    static ERROR_CODE: Cell<Option<(&'static str, bool)>> = const { Cell::new(None) };
}

pub fn begin(arguments: &mut Vec<String>) {
    let mut enabled = false;
    let mut index = 0;
    let mut command_seen = false;
    while index < arguments.len() {
        if arguments[index] == "exec" && !command_seen {
            break;
        }
        if arguments[index] == "--json" {
            arguments.remove(index);
            enabled = true;
        } else if matches!(
            arguments[index].as_str(),
            "--remote"
                | "--timeout"
                | "--exec-timeout-ms"
                | "--listen"
                | "--cleanup"
                | "--apply-update"
                | "--binary"
                | "--seconds"
                | "--interval-ms"
                | "--output"
                | "--cpu"
                | "--kernel-cr3"
                | "--kernel-image"
                | "--symbols"
                | "--pid"
                | "--cr3"
                | "--gva"
                | "--pages"
                | "--alternate-cr3"
                | "--lease-ms"
                | "--process"
                | "--pattern"
                | "--start"
                | "--end"
                | "--max-hits"
                | "--token"
                | "--dr3"
                | "--dr7-mask"
                | "--dr7-value"
                | "--thread-teb"
        ) {
            index += 2;
        } else {
            if !arguments[index].starts_with('-') {
                command_seen = true;
            }
            index += 1;
        }
    }
    JSON.set(enabled);
    EMITTED.set(false);
    ERROR_CODE.set(None);
}

pub fn is_json() -> bool {
    JSON.get()
}

pub fn mark_emitted() {
    EMITTED.set(true);
}

pub fn hex(value: u64) -> String {
    format!("0x{value:016x}")
}

pub fn fields(text: &str) -> Value {
    let mut fields = Map::new();
    for line in text.lines() {
        let Some((key, text)) = line.split_once('=') else {
            continue;
        };
        let value = match text {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            "0" | "1" if key.ends_with("telemetry_enabled") => json!(text == "1"),
            _ if key == "binary_fingerprint" => u64::from_str_radix(text, 16)
                .map(|value| json!(hex(value)))
                .unwrap_or_else(|_| json!(text)),
            _ if text.starts_with("0x") => u64::from_str_radix(&text[2..], 16)
                .map(|value| json!(hex(value)))
                .unwrap_or_else(|_| json!(text)),
            _ => match text.parse::<u64>() {
                Ok(value)
                    if matches!(
                        key,
                        "process_id"
                            | "matrixhv_protocol"
                            | "road_protocol"
                            | "logical_processor_count"
                    ) =>
                {
                    json!(value)
                }
                Ok(value) => json!(hex(value)),
                Err(_) => json!(text),
            },
        };
        fields.insert(key.to_string(), value);
    }
    Value::Object(fields)
}

pub fn write(value: &Value) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)
        .map_err(|error| format!("failed to serialize JSON: {error}"))?;
    writeln!(stdout)
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("failed to write JSON: {error}"))?;
    EMITTED.set(true);
    Ok(())
}

pub fn success(data: Value) -> Result<(), String> {
    write(&json!({"ok": true, "data": data}))
}

pub fn text(text: &str) -> Result<(), String> {
    if is_json() {
        let data = fields(text);
        if data.as_object().is_some_and(|fields| !fields.is_empty()) {
            success(data)
        } else {
            success(json!({"message": text.trim_end()}))
        }
    } else {
        print!("{text}");
        Ok(())
    }
}

pub fn set_error(code: &'static str, retryable: bool) {
    ERROR_CODE.set(Some((code, retryable)));
}

pub fn clear_error() {
    ERROR_CODE.set(None);
}

pub fn classify(message: &str) -> (&'static str, bool) {
    if let Some(error) = ERROR_CODE.get() {
        return error;
    }
    for status in 1..=15 {
        if message.ends_with(neo::memory::status_text(status)) {
            return memory_status(status);
        }
    }
    let lower = message.to_ascii_lowercase();
    if lower.starts_with("process timed out") {
        ("EXEC_TIMEOUT", false)
    } else if lower.contains("timed out") || lower.contains("timeout expired") {
        ("CONNECTION_TIMEOUT", false)
    } else if lower.contains("memory transport is unavailable")
        || lower.contains("matrixhv is not present")
    {
        ("HYPERVISOR_INACTIVE", false)
    } else if lower.starts_with("process ") && lower.contains("was not found") {
        ("PROCESS_NOT_FOUND", false)
    } else if lower.contains("lease") && lower.contains("expired") {
        ("LEASE_EXPIRED", false)
    } else if lower.contains("session is no longer active") {
        ("SESSION_INACTIVE", false)
    } else if lower.contains("unsupported")
        || lower.contains("requires windows")
        || lower.contains("requires x86")
        || lower.contains("unavailable on this cpu")
    {
        ("UNSUPPORTED_FEATURE", false)
    } else if lower.starts_with("failed to connect")
        || lower.contains("connection reset")
        || lower.contains("connection refused")
    {
        ("CONNECTION_FAILED", true)
    } else if lower.starts_with("failed to start") {
        ("PROCESS_START_FAILED", false)
    } else if lower.starts_with("usage:")
        || lower.contains("requires")
        || lower.starts_with("invalid ")
        || lower.starts_with("unknown ")
        || lower.contains("must ")
        || lower.contains("cannot be combined")
    {
        ("INVALID_ARGUMENT", false)
    } else {
        ("COMMAND_FAILED", false)
    }
}

pub fn memory_status(status: u32) -> (&'static str, bool) {
    match status {
        1 => ("INVALID_PACKET", false),
        2 => ("INVALID_RANGE", false),
        3 => ("PAGE_NOT_RESIDENT", false),
        4 => ("ACCESS_DENIED", false),
        5 => ("UNSUPPORTED_FEATURE", false),
        6 => ("PROTOTYPE_UNRESOLVED", false),
        7 => ("PAGEFILE_BACKED", false),
        8 => ("COPY_ON_WRITE", false),
        9 => ("DEMAND_ZERO_WRITE", false),
        10 => ("SESSION_BUSY", true),
        11 => ("INVALID_SESSION", false),
        12 => ("CAPACITY_EXHAUSTED", false),
        13 => ("MAPPING_CHANGED", false),
        14 => ("WRITE_COMMITTED_MERGE_CONFLICT", false),
        15 => ("WRITE_COMMITTED_REFRESH_FAILED", false),
        _ => ("COMMAND_FAILED", false),
    }
}

pub fn failure(message: &str) -> Result<(), String> {
    let (code, retryable) = classify(message);
    write(
        &json!({"ok": false, "error": {"code": code, "message": message, "retryable": retryable}}),
    )
}

pub fn partial(data: Value, code: &str, message: &str) -> Result<(), String> {
    write(
        &json!({"ok": false, "data": data, "error": {"code": code, "message": message, "retryable": false}}),
    )
}

pub fn finish(exit_code: i32) -> Result<(), String> {
    if is_json() && !EMITTED.get() {
        if exit_code == 0 {
            success(json!({"exit_code": 0}))
        } else {
            failure("command failed")
        }
    } else {
        Ok(())
    }
}
