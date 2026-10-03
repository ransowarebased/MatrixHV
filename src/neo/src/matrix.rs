#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    On,
    Off,
    OffProcessor(u32),
    Status,
    Update(std::path::PathBuf),
}

#[cfg(target_os = "windows")]
pub(crate) mod windows {
    use super::Command;
    use crate::protocol::{
        CONTROL_MAGIC, CONTROL_PROBE_OPERATION, CONTROL_VERSION, ControlProbeSnapshot,
        ControlRequest, ControlStatus,
    };
    use crate::server::protocol::{RequestKind, Response, read_response, write_response};
    use crate::update::{self, Abi, Package, Phase};
    use std::ffi::c_void;
    use std::io::{Read, Write};
    use std::mem::size_of;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::os::windows::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    const VARIABLE_ATTRIBUTES: u32 = 0x07;
    const TOKEN_ADJUST_PRIVILEGES: u32 = 0x20;
    const TOKEN_QUERY: u32 = 0x08;
    const SE_PRIVILEGE_ENABLED: u32 = 0x02;
    const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
    const ERROR_CANCELLED: u32 = 1223;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_ABANDONED: u32 = 0x80;
    const CONTROL_LOCK_WAIT_MS: u32 = 30_000;
    const VARIABLE_NAME: &str = "MatrixHVControl";
    const VARIABLE_GUID: &str = "{a830e824-19a4-42c4-9178-81ee63c135cc}";
    const CONTROL_MUTEX_NAME: &str = "Global\\MatrixHVRuntimeControl";

    impl ControlProbeSnapshot {
        fn checksum(self) -> u64 {
            [
                self.sequence,
                self.guest_rip,
                self.guest_rsp,
                self.guest_rflags,
                self.guest_cr0,
                self.guest_cr3,
                self.guest_cr4,
                self.guest_efer,
                self.guest_pat,
                self.guest_gdtr_base,
                self.guest_gdtr_limit,
                self.guest_idtr_base,
                self.guest_idtr_limit,
                self.guest_cs_selector,
                self.guest_ss_selector,
                self.guest_tr_selector,
                self.guest_tr_access,
                self.guest_fs_base,
                self.guest_gs_base,
                self.guest_interruptibility,
                self.idt_vectoring,
                self.vm_entry_intr_info,
                self.runtime_get_variable,
                self.runtime_set_variable,
                self.runtime_context,
                self.guest_es_selector,
                self.guest_ds_selector,
                self.guest_fs_selector,
                self.guest_gs_selector,
                self.guest_ldtr_selector,
                self.guest_dr7,
                self.guest_cr4_read_shadow,
                self.guest_tr_base,
                self.guest_tr_limit,
            ]
            .into_iter()
            .fold(0xcbf2_9ce4_8422_2325_u64, |value, word| {
                value.wrapping_mul(0x100_0000_01b3) ^ word
            })
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct GroupAffinity {
        mask: usize,
        group: u16,
        reserved: [u16; 3],
    }

    #[derive(Clone, Copy)]
    struct ProcessorRoute {
        group: u16,
        number: u32,
        index: usize,
        apic_id: u32,
    }

    struct ControlMutex(*mut c_void);

    impl ControlMutex {
        fn acquire() -> Result<Self, String> {
            let name = wide(CONTROL_MUTEX_NAME);
            let handle = unsafe { create_mutex_w(std::ptr::null_mut(), 0, name.as_ptr()) };
            if handle.is_null() {
                return Err(win32_error("CreateMutexW"));
            }
            let wait_result = unsafe { wait_for_single_object(handle, CONTROL_LOCK_WAIT_MS) };
            if wait_result != WAIT_OBJECT_0 && wait_result != WAIT_ABANDONED {
                unsafe { close_handle(handle) };
                return Err(format!(
                    "MatrixHV runtime control mutex wait failed with result {wait_result:#x}"
                ));
            }
            Ok(Self(handle))
        }
    }

    impl Drop for ControlMutex {
        fn drop(&mut self) {
            unsafe {
                release_mutex(self.0);
                close_handle(self.0);
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Luid {
        low_part: u32,
        high_part: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct LuidAndAttributes {
        luid: Luid,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenPrivileges {
        privilege_count: u32,
        privileges: [LuidAndAttributes; 1],
    }

    #[repr(C)]
    pub(crate) struct ShellExecuteInfo {
        size: u32,
        mask: u32,
        window: *mut c_void,
        verb: *const u16,
        file: *const u16,
        pub(crate) parameters: *const u16,
        directory: *const u16,
        show: i32,
        instance: *mut c_void,
        id_list: *mut c_void,
        class: *const u16,
        class_key: *mut c_void,
        hot_key: u32,
        icon_or_monitor: *mut c_void,
        pub(crate) process: *mut c_void,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetCurrentProcess"]
        pub(crate) fn get_current_process() -> *mut c_void;
        #[link_name = "GetCurrentThread"]
        fn get_current_thread() -> *mut c_void;
        #[link_name = "GetActiveProcessorGroupCount"]
        fn get_active_processor_group_count() -> u16;
        #[link_name = "GetActiveProcessorCount"]
        fn get_active_processor_count(group: u16) -> u32;
        #[link_name = "SetThreadGroupAffinity"]
        fn set_thread_group_affinity(
            thread: *mut c_void,
            group_affinity: *const GroupAffinity,
            previous_group_affinity: *mut GroupAffinity,
        ) -> i32;
        #[link_name = "CloseHandle"]
        fn close_handle(handle: *mut c_void) -> i32;
        #[link_name = "GetLastError"]
        fn get_last_error() -> u32;
        #[link_name = "GetExitCodeProcess"]
        fn get_exit_code_process(process: *mut c_void, exit_code: *mut u32) -> i32;
        #[link_name = "CreateMutexW"]
        fn create_mutex_w(
            attributes: *mut c_void,
            initial_owner: i32,
            name: *const u16,
        ) -> *mut c_void;
        #[link_name = "WaitForSingleObject"]
        fn wait_for_single_object(handle: *mut c_void, milliseconds: u32) -> u32;
        #[link_name = "ReleaseMutex"]
        fn release_mutex(handle: *mut c_void) -> i32;
        #[link_name = "GetFirmwareEnvironmentVariableExW"]
        fn get_firmware_environment_variable_ex_w(
            name: *const u16,
            guid: *const u16,
            value: *mut c_void,
            size: u32,
            attributes: *mut u32,
        ) -> u32;
        #[link_name = "SetFirmwareEnvironmentVariableExW"]
        fn set_firmware_environment_variable_ex_w(
            name: *const u16,
            guid: *const u16,
            value: *const c_void,
            size: u32,
            attributes: u32,
        ) -> i32;
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        #[link_name = "ShellExecuteExW"]
        fn shell_execute_ex_w(info: *mut ShellExecuteInfo) -> i32;
    }

    #[link(name = "ole32")]
    unsafe extern "system" {
        #[link_name = "CoInitializeEx"]
        fn co_initialize_ex(reserved: *mut c_void, flags: u32) -> i32;
        #[link_name = "CoUninitialize"]
        fn co_uninitialize();
    }

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        #[link_name = "BCryptGenRandom"]
        fn bcrypt_gen_random(
            algorithm: *mut c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        #[link_name = "OpenProcessToken"]
        fn open_process_token(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        #[link_name = "LookupPrivilegeValueW"]
        fn lookup_privilege_value_w(system: *const u16, name: *const u16, luid: *mut Luid) -> i32;
        #[link_name = "AdjustTokenPrivileges"]
        fn adjust_token_privileges(
            token: *mut c_void,
            disable_all: i32,
            new_state: *const TokenPrivileges,
            buffer_length: u32,
            previous_state: *mut c_void,
            return_length: *mut u32,
        ) -> i32;
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn win32_error(operation: &str) -> String {
        format!("{operation} failed with Win32 error {}", unsafe {
            get_last_error()
        })
    }

    fn enable_firmware_privilege() -> Result<bool, String> {
        let mut token = std::ptr::null_mut();
        if unsafe {
            open_process_token(
                get_current_process(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        } == 0
        {
            return Err(win32_error("OpenProcessToken"));
        }
        let result = (|| {
            let mut luid = Luid::default();
            let name = wide("SeSystemEnvironmentPrivilege");
            if unsafe { lookup_privilege_value_w(std::ptr::null(), name.as_ptr(), &mut luid) } == 0
            {
                return Err(win32_error("LookupPrivilegeValueW"));
            }
            let privileges = TokenPrivileges {
                privilege_count: 1,
                privileges: [LuidAndAttributes {
                    luid,
                    attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            if unsafe {
                adjust_token_privileges(
                    token,
                    0,
                    &privileges,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(win32_error("AdjustTokenPrivileges"));
            }
            if unsafe { get_last_error() } == ERROR_NOT_ALL_ASSIGNED {
                return Ok(false);
            }
            Ok(true)
        })();
        unsafe { close_handle(token) };
        result
    }

    pub(crate) fn elevated_arguments(command: Command, port: u16, nonce: u128) -> String {
        let command = match command {
            Command::On => "on".to_string(),
            Command::Off => "off".to_string(),
            Command::OffProcessor(index) => format!("off --cpu {index}"),
            Command::Status => "status".to_string(),
            Command::Update(path) => format!(
                "update --binary {}",
                quote_argument(&path.to_string_lossy())
            ),
        };
        format!("--runtime-elevated {port} {nonce} matrix {command}")
    }

    pub(crate) fn receive_elevated_result(
        listener: &TcpListener,
        process: *mut c_void,
        nonce: [u8; 16],
    ) -> Result<Response, String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if Instant::now() >= deadline {
                return Err("timed out waiting for the elevated helper to connect".into());
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|error| error.to_string())?;
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .map_err(|error| error.to_string())?;
                    let mut received_nonce = [0_u8; 16];
                    if stream.read_exact(&mut received_nonce).is_err() || received_nonce != nonce {
                        continue;
                    }
                    stream
                        .set_read_timeout(Some(Duration::from_secs(300)))
                        .map_err(|error| error.to_string())?;
                    loop {
                        let (request_id, response) = read_response(&mut stream)
                            .map_err(|error| format!("failed to read the UAC result: {error}"))?;
                        if request_id != 0 {
                            return Err("invalid UAC result frame".into());
                        }
                        if response.request_kind == RequestKind::Status {
                            return Ok(response);
                        }
                        if response.request_kind != RequestKind::Exec || !response.success {
                            return Err("invalid UAC progress frame".into());
                        }
                        println!("{}", response.message);
                        let _ = std::io::stdout().flush();
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("failed to accept the UAC result: {error}")),
            }
            if unsafe { wait_for_single_object(process, 0) } == WAIT_OBJECT_0 {
                return Err("the elevated helper exited without returning a result".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn quote_argument(value: &str) -> String {
        let mut quoted = String::from("\"");
        let mut slashes = 0;
        for character in value.chars() {
            if character == '\\' {
                slashes += 1;
                continue;
            }
            quoted.extend(std::iter::repeat_n(
                '\\',
                if character == '"' {
                    slashes * 2 + 1
                } else {
                    slashes
                },
            ));
            quoted.push(character);
            slashes = 0;
        }
        quoted.extend(std::iter::repeat_n('\\', slashes * 2));
        quoted.push('"');
        quoted
    }

    fn run_elevated(command: Command) -> Result<String, String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| format!("failed to bind the UAC result channel: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let mut nonce_bytes = [0_u8; 16];
        let random_status =
            unsafe { bcrypt_gen_random(std::ptr::null_mut(), nonce_bytes.as_mut_ptr(), 16, 0x02) };
        if random_status < 0 {
            return Err(format!(
                "BCryptGenRandom failed with NTSTATUS {random_status:#x}"
            ));
        }
        let nonce = u128::from_le_bytes(nonce_bytes);
        let executable = std::env::current_exe()
            .map_err(|error| format!("failed to resolve the neo executable: {error}"))?;
        let file: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let parameters = wide(&elevated_arguments(command, port, nonce));
        let verb = wide("runas");
        let mut info: ShellExecuteInfo = unsafe { std::mem::zeroed() };
        info.size = size_of::<ShellExecuteInfo>() as u32;
        // The hidden helper returns its result over a one-shot loopback channel.
        // It never accepts commands over this channel.
        info.mask = 0x40 | 0x100 | 0x400 | 0x8000;
        info.verb = verb.as_ptr();
        info.file = file.as_ptr();
        info.parameters = parameters.as_ptr();
        info.show = 0;
        let initialized = unsafe { co_initialize_ex(std::ptr::null_mut(), 0x02 | 0x04) };
        let launched = unsafe { shell_execute_ex_w(&mut info) };
        let launch_error = unsafe { get_last_error() };
        if initialized >= 0 {
            unsafe { co_uninitialize() };
        }
        if launched == 0 {
            return Err(if launch_error == ERROR_CANCELLED {
                "UAC elevation cancelled; MatrixHV command was not executed".into()
            } else {
                format!("ShellExecuteExW elevation failed with Win32 error {launch_error}")
            });
        }
        if info.process.is_null() {
            return Err("UAC elevation did not return a process handle".into());
        }
        let result = (|| {
            let response = receive_elevated_result(&listener, info.process, nonce_bytes)?;
            if unsafe { wait_for_single_object(info.process, u32::MAX) } != WAIT_OBJECT_0 {
                return Err(win32_error("WaitForSingleObject"));
            }
            let mut exit_code = 0;
            if unsafe { get_exit_code_process(info.process, &mut exit_code) } == 0 {
                return Err(win32_error("GetExitCodeProcess"));
            }
            if !response.success {
                return Err(response.message);
            }
            if exit_code != 0 {
                return Err(format!(
                    "elevated MatrixHV command failed with exit code {exit_code}"
                ));
            }
            Ok(response.message)
        })();
        unsafe { close_handle(info.process) };
        result
    }

    pub(super) fn execute_helper(command: Command, port: u16, nonce: u128) -> Result<i32, String> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .map_err(|error| format!("failed to connect the UAC result channel: {error}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(300)))
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&nonce.to_le_bytes())
            .map_err(|error| error.to_string())?;
        let (response, exit_code) = match execute(command, false, &mut |message| {
            let _ = write_response(
                &mut stream,
                0,
                &Response::success(RequestKind::Exec, message),
            );
        }) {
            Ok(text) => (Response::success(RequestKind::Status, text), 0),
            Err(error) => (Response::failure(RequestKind::Status, error), 1),
        };
        write_response(&mut stream, 0, &response)
            .map_err(|error| format!("failed to return the UAC result: {error}"))?;
        Ok(exit_code)
    }

    fn read_status() -> Result<ControlStatus, String> {
        let name = wide(VARIABLE_NAME);
        let guid = wide(VARIABLE_GUID);
        let mut status = ControlStatus::default();
        let mut attributes = 0;
        let received = unsafe {
            get_firmware_environment_variable_ex_w(
                name.as_ptr(),
                guid.as_ptr(),
                (&mut status as *mut ControlStatus).cast(),
                size_of::<ControlStatus>() as u32,
                &mut attributes,
            )
        };
        if received == 0 {
            return Err(win32_error("GetFirmwareEnvironmentVariableExW"));
        }
        if received as usize != size_of::<ControlStatus>()
            || status.magic != CONTROL_MAGIC
            || status.version != CONTROL_VERSION
            || attributes != VARIABLE_ATTRIBUTES
        {
            return Err("MatrixHV runtime bridge returned an incompatible status".into());
        }
        if status.virtual_address_error != 0 {
            return Err(format!(
                "MatrixHV runtime address conversion failed with EFI status {:#x}",
                status.virtual_address_error
            ));
        }
        Ok(status)
    }

    fn with_processor_affinity<T>(
        group: u16,
        number: u32,
        callback: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let affinity = GroupAffinity {
            mask: 1_usize
                .checked_shl(number)
                .ok_or_else(|| format!("processor number {number} exceeds the affinity mask"))?,
            group,
            reserved: [0; 3],
        };
        let mut previous = GroupAffinity::default();
        let thread = unsafe { get_current_thread() };
        if unsafe { set_thread_group_affinity(thread, &affinity, &mut previous) } == 0 {
            return Err(win32_error("SetThreadGroupAffinity"));
        }
        let result = callback();
        let restored =
            unsafe { set_thread_group_affinity(thread, &previous, std::ptr::null_mut()) } != 0;
        match (result, restored) {
            (Ok(value), true) => Ok(value),
            (Err(error), true) => Err(error),
            (Ok(_), false) => Err(win32_error("restoring thread affinity")),
            (Err(error), false) => Err(format!(
                "{error}; {}",
                win32_error("restoring thread affinity")
            )),
        }
    }

    fn read_status_on_processor(
        group: u16,
        number: u32,
    ) -> Result<(ControlStatus, Option<Result<(), String>>), String> {
        with_processor_affinity(group, number, || {
            let mut status = read_status()?;
            let active_processor = status.apic_ids.iter().enumerate().any(|(index, apic_id)| {
                status.active_mask & (1_u64 << index) != 0 && *apic_id == status.current_apic_id
            });
            let apic_id = status.current_apic_id;
            let probe = active_processor.then(|| match probe_processor(apic_id) {
                Ok(sequence) => match read_status() {
                    Ok(updated)
                        if updated.current_apic_id == apic_id
                            && updated.probe_snapshot.sequence == sequence =>
                    {
                        status = updated;
                        Ok(())
                    }
                    Ok(updated) => Err(format!(
                        "runtime probe snapshot mismatch: apic_id={} expected_apic_id={apic_id} sequence={:#x} expected_sequence={sequence:#x} rip={:#x} cr3={:#x} runtime_get={:#x} runtime_set={:#x} runtime_context={:#x}",
                        updated.current_apic_id,
                        updated.probe_snapshot.sequence,
                        updated.probe_snapshot.guest_rip,
                        updated.probe_snapshot.guest_cr3,
                        updated.probe_snapshot.runtime_get_variable,
                        updated.probe_snapshot.runtime_set_variable,
                        updated.probe_snapshot.runtime_context,
                    )),
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            });
            Ok((status, probe))
        })
    }

    fn probe_processor(expected_apic_id: u32) -> Result<u64, String> {
        let sequence = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("system clock error: {error}"))?
            .as_nanos() as u64;
        send_request(
            CONTROL_PROBE_OPERATION,
            sequence,
            expected_apic_id,
            "runtime VM exit probe",
        )?;
        Ok(sequence)
    }

    fn send_request(
        operation: u32,
        sequence: u64,
        expected_apic_id: u32,
        description: &str,
    ) -> Result<(), String> {
        let request = ControlRequest {
            magic: CONTROL_MAGIC,
            version: CONTROL_VERSION,
            operation,
            sequence,
            expected_apic_id,
            reserved: 0,
        };
        let name = wide(VARIABLE_NAME);
        let guid = wide(VARIABLE_GUID);
        if unsafe {
            set_firmware_environment_variable_ex_w(
                name.as_ptr(),
                guid.as_ptr(),
                (&request as *const ControlRequest).cast(),
                size_of::<ControlRequest>() as u32,
                VARIABLE_ATTRIBUTES,
            )
        } == 0
        {
            return Err(win32_error(description));
        }
        Ok(())
    }

    fn observe_processors(
        reference: &ControlStatus,
    ) -> Result<(u64, String, u64, String, String), String> {
        let group_count = unsafe { get_active_processor_group_count() };
        let mut observed_mask = 0_u64;
        let mut probe_mask = 0_u64;
        let mut samples = Vec::new();
        let mut probe_errors = Vec::new();
        let mut probe_snapshots = Vec::new();
        for group in 0..group_count {
            let count = unsafe { get_active_processor_count(group) };
            for number in 0..count {
                let (status, probe) = read_status_on_processor(group, number)?;
                if status.expected_mask != reference.expected_mask
                    || status.apic_ids != reference.apic_ids
                {
                    return Err("MatrixHV runtime bridge changed during CPU discovery".into());
                }
                let processor = status
                    .apic_ids
                    .iter()
                    .enumerate()
                    .find(|(index, apic_id)| {
                        reference.expected_mask & (1_u64 << index) != 0
                            && **apic_id == status.current_apic_id
                    })
                    .map(|(index, _)| index);
                if let Some(processor) = processor {
                    observed_mask |= 1_u64 << processor;
                    if matches!(probe, Some(Ok(()))) {
                        probe_mask |= 1_u64 << processor;
                        let snapshot = status.probe_snapshot;
                        probe_snapshots.push(format!(
                            "{processor}:{:#x}:{:#x}:{:#x}:{:#x}:{:#x}:{:#x}:{:#x}:{:#x}:{:#x}:{:#x}:{:#x}",
                            snapshot.guest_cr3,
                            snapshot.guest_rsp,
                            snapshot.runtime_get_variable,
                            snapshot.runtime_set_variable,
                            snapshot.runtime_context,
                            snapshot.guest_fs_selector,
                            snapshot.guest_gs_selector,
                            snapshot.guest_ldtr_selector,
                            snapshot.guest_cr4_read_shadow,
                            snapshot.guest_tr_limit,
                            snapshot.checksum(),
                        ));
                    }
                }
                if let Some(Err(error)) = probe {
                    probe_errors.push(format!("{group}:{number}:{error}"));
                }
                samples.push(format!(
                    "{group}:{number}:{}",
                    processor
                        .map(|processor| processor.to_string())
                        .unwrap_or_else(|| format!("unknown-apic-{}", status.current_apic_id))
                ));
            }
        }
        Ok((
            observed_mask,
            samples.join(","),
            probe_mask,
            if probe_errors.is_empty() {
                "none".into()
            } else {
                probe_errors.join(",")
            },
            probe_snapshots.join(","),
        ))
    }

    fn discover_routes(reference: &ControlStatus) -> Result<Vec<ProcessorRoute>, String> {
        if reference.expected_mask == 0
            || reference.processor_count != reference.expected_mask.count_ones()
        {
            return Err("MatrixHV runtime bridge reported an invalid CPU topology".into());
        }
        let mut routes = Vec::with_capacity(reference.processor_count as usize);
        let mut observed_mask = 0_u64;
        for group in 0..unsafe { get_active_processor_group_count() } {
            for number in 0..unsafe { get_active_processor_count(group) } {
                let status = with_processor_affinity(group, number, read_status)?;
                if status.expected_mask != reference.expected_mask
                    || status.apic_ids != reference.apic_ids
                {
                    return Err("MatrixHV runtime bridge changed during CPU discovery".into());
                }
                let index = reference
                    .apic_ids
                    .iter()
                    .enumerate()
                    .filter(|(index, apic_id)| {
                        reference.expected_mask & (1_u64 << index) != 0
                            && **apic_id == status.current_apic_id
                    })
                    .map(|(index, _)| index)
                    .next()
                    .ok_or_else(|| {
                        format!(
                            "Windows processor {group}:{number} has unknown APIC ID {}",
                            status.current_apic_id
                        )
                    })?;
                let bit = 1_u64 << index;
                if observed_mask & bit != 0 {
                    return Err(format!(
                        "multiple Windows processors map to MatrixHV APIC ID {}",
                        status.current_apic_id
                    ));
                }
                observed_mask |= bit;
                routes.push(ProcessorRoute {
                    group,
                    number,
                    index,
                    apic_id: status.current_apic_id,
                });
            }
        }
        if observed_mask != reference.expected_mask {
            return Err(format!(
                "MatrixHV CPU routes incomplete: expected={:#x} observed={observed_mask:#x}",
                reference.expected_mask
            ));
        }
        Ok(routes)
    }

    fn run_on_route(
        route: ProcessorRoute,
        reference: &ControlStatus,
        operation: u32,
        sequence: u64,
    ) -> Result<bool, String> {
        with_processor_affinity(route.group, route.number, || {
            let before = read_status()?;
            let bit = 1_u64 << route.index;
            if before.expected_mask != reference.expected_mask
                || before.apic_ids != reference.apic_ids
                || before.current_apic_id != route.apic_id
            {
                return Err(format!(
                    "CPU route changed for {}:{}",
                    route.group, route.number
                ));
            }
            if before.failed_mask & bit != 0 {
                return Err(format!("CPU {} is marked failed", route.index));
            }
            let (source_mask, target_mask) = if operation == 1 {
                (before.stopped_mask, before.active_mask)
            } else {
                (before.active_mask, before.stopped_mask)
            };
            if target_mask & bit != 0 {
                return Ok(false);
            }
            if source_mask & bit == 0 {
                return Err(format!("CPU {} is neither active nor stopped", route.index));
            }
            send_request(
                operation,
                sequence,
                route.apic_id,
                "MatrixHV runtime transition",
            )?;
            let after = read_status()?;
            if after.current_apic_id != route.apic_id
                || after.expected_mask != reference.expected_mask
                || after.apic_ids != reference.apic_ids
            {
                return Err(format!(
                    "CPU route changed after transitioning CPU {}",
                    route.index
                ));
            }
            let (source_mask, target_mask) = if operation == 1 {
                (after.stopped_mask, after.active_mask)
            } else {
                (after.active_mask, after.stopped_mask)
            };
            if after.completion_sequence != sequence
                || target_mask & bit == 0
                || source_mask & bit != 0
                || after.failed_mask & bit != 0
            {
                return Err(format!(
                    "CPU {} did not confirm transition: sequence={:#x} expected={sequence:#x} active={:#x} stopped={:#x} failed={:#x}",
                    route.index,
                    after.completion_sequence,
                    after.active_mask,
                    after.stopped_mask,
                    after.failed_mask
                ));
            }
            Ok(true)
        })
    }

    fn update_status(status: &ControlStatus) -> update::Status {
        unsafe { (status.update_status.as_ptr() as *const update::Status).read_unaligned() }
    }

    fn identity_text(identity: &[u8; 32]) -> String {
        identity.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn update_summary(status: &ControlStatus) -> String {
        let update = update_status(status);
        let cpu_errors = update
            .cpu_errors
            .iter()
            .enumerate()
            .filter(|(_, error)| **error != 0)
            .map(|(cpu, error)| format!("{cpu}:{}", update::Error::description(*error)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "update transaction={:#x} phase={} error={} previous_version={} next_version={} uploaded={}/{} checked={:#x} verified={:#x} retained_banks={:#x} previous_identity={} next_identity={} cpu_errors=[{cpu_errors}]",
            update.transaction,
            update.phase,
            update::Error::description(update.error),
            update.previous_version,
            update.next_version,
            update.received_bytes,
            update.total_bytes,
            update.checked_mask,
            update.verified_mask,
            update.retained_banks,
            identity_text(&update.previous_identity),
            identity_text(&update.next_identity)
        )
    }

    fn update_request(
        route: ProcessorRoute,
        reference: &ControlStatus,
        operation: u32,
        transaction: u64,
        offset: usize,
        total_bytes: usize,
        payload: &[u8],
    ) -> Result<ControlStatus, String> {
        if payload.len() > update::CHUNK_BYTES {
            return Err("runtime upload block exceeds its bound".into());
        }
        with_processor_affinity(route.group, route.number, || {
            let before = read_status()?;
            if before.current_apic_id != route.apic_id
                || before.expected_mask != reference.expected_mask
                || before.apic_ids != reference.apic_ids
            {
                return Err("runtime update CPU route changed".into());
            }
            let mut request = vec![0_u8; update::REQUEST_BYTES + payload.len()];
            request[..8].copy_from_slice(&update::REQUEST_MAGIC.to_le_bytes());
            request[8..12].copy_from_slice(&update::PACKAGE_VERSION.to_le_bytes());
            request[12..16].copy_from_slice(&operation.to_le_bytes());
            request[16..24].copy_from_slice(&transaction.to_le_bytes());
            request[24..28].copy_from_slice(&route.apic_id.to_le_bytes());
            request[32..36].copy_from_slice(&(offset as u32).to_le_bytes());
            request[36..40].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            request[40..44].copy_from_slice(&(total_bytes as u32).to_le_bytes());
            request[update::REQUEST_BYTES..].copy_from_slice(payload);
            let accepted = unsafe {
                set_firmware_environment_variable_ex_w(
                    wide(VARIABLE_NAME).as_ptr(),
                    wide(VARIABLE_GUID).as_ptr(),
                    request.as_ptr().cast(),
                    request.len() as u32,
                    VARIABLE_ATTRIBUTES,
                )
            };
            let call_error = if accepted == 0 {
                Some(win32_error("MatrixHV runtime update"))
            } else {
                None
            };
            let after = read_status()?;
            let state = update_status(&after);
            if let Some(error) = call_error {
                return Err(format!(
                    "{error}; operation={operation} cpu={} {}; {}",
                    route.index,
                    update::Error::description(state.error),
                    update_summary(&after)
                ));
            }
            if state.transaction != transaction
                || state.error != 0
                || after.current_apic_id != route.apic_id
            {
                return Err(format!(
                    "runtime update acknowledgement mismatch; {}",
                    update_summary(&after)
                ));
            }
            Ok(after)
        })
    }

    fn recover_update(
        routes: &[ProcessorRoute],
        reference: &ControlStatus,
        transaction: u64,
        progress: &mut dyn FnMut(&str),
    ) -> Result<String, String> {
        let status = read_status()?;
        let phase = update_status(&status).phase;
        let route = *routes.first().ok_or("runtime update has no CPU route")?;
        if matches!(phase, 1 | 2) {
            let cancelled =
                update_request(route, reference, update::CANCEL, transaction, 0, 0, &[])?;
            return Ok(format!(
                "cancelled before deactivation; {}",
                update_summary(&cancelled)
            ));
        }
        if phase == Phase::Complete as u32 {
            return Err("new core completed; no rollback is needed".into());
        }
        if status.failed_mask != 0 {
            return Err(format!(
                "host CPU failure prevents recovery; both banks remain reserved; {}",
                update_summary(&status)
            ));
        }
        progress("Recovering the previous resident core; retaining both banks.");
        if phase == Phase::Activating as u32 {
            for &cpu in routes {
                run_on_route(cpu, reference, 2, transaction)?;
            }
        }
        update_request(route, reference, update::RECOVER, transaction, 0, 0, &[])?;
        for &cpu in routes {
            run_on_route(cpu, reference, 1, transaction)?;
            update_request(cpu, reference, update::PROBE_CPU, transaction, 0, 0, &[])?;
            with_processor_affinity(cpu.group, cpu.number, || {
                probe_processor(cpu.apic_id).map(|_| ())
            })?;
            progress(&format!(
                "CPU {}: previous core restored and probed.",
                cpu.index
            ));
        }
        let restored = update_request(route, reference, update::RECOVERED, transaction, 0, 0, &[])?;
        if update_status(&restored).phase != Phase::Recovered as u32 {
            return Err("runtime recovery was not confirmed".into());
        }
        Ok(format!(
            "previous resident core recovered; {}",
            update_summary(&restored)
        ))
    }

    fn run_update(
        path: &std::path::Path,
        reference: &ControlStatus,
        progress: &mut dyn FnMut(&str),
    ) -> Result<String, String> {
        if reference.capabilities & 4 == 0
            || reference.active_mask != reference.expected_mask
            || reference.stopped_mask != 0
            || reference.failed_mask != 0
            || reference.exit_boot_services_seen != 1
            || reference.virtual_address_change_seen != 1
        {
            return Err(
                "runtime update requires a ready bridge and all registered CPUs active".into(),
            );
        }
        let file = std::fs::File::open(path)
            .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
        let mut bytes = Vec::new();
        file.take((update::MAX_PACKAGE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read the resident package: {error}"))?;
        let abi = Abi {
            bridge: reference.update_abi[0],
            boot_bytes: reference.update_abi[1],
            event_bytes: reference.update_abi[2],
            nested_bytes: reference.update_abi[3],
            cpu_bytes: reference.update_abi[4],
        };
        if reference.update_abi[5] != update::STATE_ABI {
            return Err("unsupported resident state ABI".into());
        }
        let package =
            Package::parse(&bytes, abi, &reference.update_public_key).map_err(|error| {
                format!(
                    "resident package rejected before off: {}",
                    update::Error::description(error as u32)
                )
            })?;
        let previous = update_status(reference);
        let current_version = if previous.phase == Phase::Complete as u32 {
            previous.next_version
        } else {
            previous.previous_version
        };
        if package.version <= current_version {
            return Err(format!(
                "resident package version {} must exceed {current_version}",
                package.version
            ));
        }
        let routes = discover_routes(reference)?;
        let route = *routes.first().ok_or("runtime update has no CPU route")?;
        let mut random = [0_u8; 8];
        let random_status =
            unsafe { bcrypt_gen_random(std::ptr::null_mut(), random.as_mut_ptr(), 8, 2) };
        let transaction = u64::from_le_bytes(random);
        if random_status < 0 || transaction == 0 {
            return Err(format!(
                "runtime transaction generation failed: NTSTATUS {random_status:#x}"
            ));
        }
        progress(&format!(
            "Preparing resident update: {current_version} -> {} transaction={transaction:#x} identity={}",
            package.version,
            identity_text(&package.identity)
        ));
        update_request(
            route,
            reference,
            update::PREPARE,
            transaction,
            0,
            bytes.len(),
            &[],
        )?;
        let result: Result<String, String> = (|| {
            for (chunk_index, chunk) in bytes.chunks(update::CHUNK_BYTES).enumerate() {
                update_request(
                    route,
                    reference,
                    update::UPLOAD,
                    transaction,
                    chunk_index * update::CHUNK_BYTES,
                    0,
                    chunk,
                )?;
                if chunk_index % 32 == 0 || (chunk_index + 1) * update::CHUNK_BYTES >= bytes.len() {
                    progress(&format!(
                        "Uploading resident package: {}/{} bytes",
                        ((chunk_index + 1) * update::CHUNK_BYTES).min(bytes.len()),
                        bytes.len()
                    ));
                }
            }
            update_request(route, reference, update::VALIDATE, transaction, 0, 0, &[])?;
            for &cpu in &routes {
                update_request(cpu, reference, update::CHECK_CPU, transaction, 0, 0, &[])?;
                progress(&format!("CPU {}: update preflight passed.", cpu.index));
            }
            update_request(route, reference, update::BEGIN_OFF, transaction, 0, 0, &[])?;
            for &cpu in &routes {
                run_on_route(cpu, reference, 2, transaction)?;
                progress(&format!("CPU {}: stopped and confirmed.", cpu.index));
            }
            update_request(route, reference, update::COMMIT, transaction, 0, 0, &[])?;
            progress("All CPUs stopped; resident entries and IDTs switched to the new bank.");
            for &cpu in &routes {
                run_on_route(cpu, reference, 1, transaction)?;
                update_request(cpu, reference, update::PROBE_CPU, transaction, 0, 0, &[])?;
                with_processor_affinity(cpu.group, cpu.number, || {
                    probe_processor(cpu.apic_id).map(|_| ())
                })?;
                progress(&format!(
                    "CPU {}: new core identity and VM exit probe confirmed.",
                    cpu.index
                ));
            }
            update_request(route, reference, update::FINISH, transaction, 0, 0, &[])?;
            let final_status =
                update_request(route, reference, update::QUERY, transaction, 0, 0, &[])?;
            if update_status(&final_status).phase != Phase::Complete as u32 {
                return Err("runtime update did not complete".into());
            }
            Ok(format!(
                "MatrixHV resident update complete: version={} processors={} active={:#x}\n{}\n",
                package.version,
                reference.processor_count,
                final_status.active_mask,
                update_summary(&final_status)
            ))
        })();
        match result {
            Ok(summary) => Ok(summary),
            Err(error) => match recover_update(&routes, reference, transaction, progress) {
                Ok(recovery) => Err(format!("{error}\n{recovery}")),
                Err(recovery) => Err(format!("{error}\nRecovery incomplete: {recovery}")),
            },
        }
    }

    pub(super) fn execute(
        command: Command,
        allow_elevation: bool,
        progress: &mut dyn FnMut(&str),
    ) -> Result<String, String> {
        if !enable_firmware_privilege()? {
            if allow_elevation {
                return run_elevated(command);
            }
            return Err("The elevated token does not have SeSystemEnvironmentPrivilege for UEFI runtime variables".into());
        }
        let _control_mutex = ControlMutex::acquire()?;
        let status = read_status()?;
        if let Command::Update(path) = &command {
            return run_update(path, &status, progress);
        }
        if command == Command::Status {
            let (observed_mask, routes, probe_mask, probe_errors, probe_snapshots) =
                observe_processors(&status)?;
            let cpu_map = status
                .apic_ids
                .iter()
                .enumerate()
                .filter(|(index, _)| status.expected_mask & (1_u64 << index) != 0)
                .map(|(index, apic_id)| format!("{index}:{apic_id}"))
                .collect::<Vec<_>>()
                .join(",");
            return Ok(format!(
                "bridge=present capabilities={:#x} apic_id={} processors={} expected={:#x} observed={:#x} vmexit_probe={:#x} active={:#x} stopped={:#x} failed={:#x} exit_boot_services={} virtual_address_change={} cpu_map={} routes={} probe_errors={} probe_snapshots={}\n{}\n",
                status.capabilities,
                status.current_apic_id,
                status.processor_count,
                status.expected_mask,
                observed_mask,
                probe_mask,
                status.active_mask,
                status.stopped_mask,
                status.failed_mask,
                status.exit_boot_services_seen,
                status.virtual_address_change_seen,
                cpu_map,
                routes,
                probe_errors,
                probe_snapshots,
                update_summary(&status),
            ));
        }
        let operation = match command {
            Command::On => 1,
            Command::Off | Command::OffProcessor(_) => 2,
            Command::Status => unreachable!(),
            Command::Update(_) => unreachable!(),
        };
        if status.capabilities & operation == 0 {
            return Err("MatrixHV runtime bridge does not support this operation".into());
        }
        if status.active_mask & status.stopped_mask != 0
            || (status.active_mask | status.stopped_mask | status.failed_mask)
                & status.expected_mask
                != status.expected_mask
            || status.failed_mask & status.expected_mask != 0
        {
            return Err(format!(
                "MatrixHV CPU state is inconsistent: expected={:#x} active={:#x} stopped={:#x} failed={:#x}",
                status.expected_mask, status.active_mask, status.stopped_mask, status.failed_mask
            ));
        }
        let target_mask = match command {
            Command::OffProcessor(index) => {
                let bit = 1_u64
                    .checked_shl(index)
                    .ok_or_else(|| format!("processor index {index} exceeds the control mask"))?;
                if status.expected_mask & bit == 0 {
                    return Err(format!("processor index {index} is not registered"));
                }
                bit
            }
            _ => status.expected_mask,
        };
        if operation == 2 {
            let (observed_mask, _, probe_mask, probe_errors, _) = observe_processors(&status)?;
            if observed_mask != status.expected_mask || probe_mask != status.active_mask {
                return Err(format!(
                    "MatrixHV off preflight failed: expected={:#x} observed={observed_mask:#x} active={:#x} vmexit_probe={probe_mask:#x} probe_errors={probe_errors}",
                    status.expected_mask, status.active_mask
                ));
            }
        }
        let routes = discover_routes(&status)?;
        let sequence = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("system clock error: {error}"))?
            .as_nanos() as u64;
        if sequence == 0 {
            return Err("MatrixHV runtime sequence cannot be zero".into());
        }
        let mut transitioned = 0_u64;
        let mut transition_error = None;
        for route in routes
            .into_iter()
            .filter(|route| target_mask & (1_u64 << route.index) != 0)
        {
            match run_on_route(route, &status, operation, sequence) {
                Ok(true) => transitioned |= 1_u64 << route.index,
                Ok(false) => {}
                Err(error) => {
                    transition_error = Some(error);
                    break;
                }
            }
        }
        let final_status = read_status()?;
        let completed_mask = if operation == 1 {
            final_status.active_mask
        } else {
            final_status.stopped_mask
        };
        if transition_error.is_some()
            || completed_mask & target_mask != target_mask
            || final_status.failed_mask & status.expected_mask != 0
        {
            return Err(format!(
                "MatrixHV {} incomplete: target={target_mask:#x} expected={:#x} active={:#x} stopped={:#x} failed={:#x} transitioned={transitioned:#x} error={}",
                if operation == 1 { "on" } else { "off" },
                status.expected_mask,
                final_status.active_mask,
                final_status.stopped_mask,
                final_status.failed_mask,
                transition_error.unwrap_or_else(|| "none".into())
            ));
        }
        Ok(format!(
            "MatrixHV {} complete: processors={} target={target_mask:#x} active={:#x} stopped={:#x} sequence={sequence:#x}\n",
            if operation == 1 { "on" } else { "off" },
            target_mask.count_ones(),
            final_status.active_mask,
            final_status.stopped_mask
        ))
    }
}

pub fn execute(command: Command) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        windows::execute(command, true, &mut |message| {
            println!("{message}");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = command;
        Err("MatrixHV runtime control requires Windows".into())
    }
}

#[cfg(target_os = "windows")]
pub fn execute_elevated(command: Command, port: u16, nonce: u128) -> Result<i32, String> {
    windows::execute_helper(command, port, nonce)
}
