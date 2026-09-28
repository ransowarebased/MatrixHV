#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    On,
    Off,
    OffProcessor(u32),
    Status,
}

#[cfg(target_os = "windows")]
mod windows {
    use super::Command;
    use crate::server::protocol::{RequestKind, Response, read_response, write_response};
    use std::ffi::c_void;
    use std::io::{Read, Write};
    use std::mem::size_of;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::os::windows::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    const CONTROL_MAGIC: u64 = 0x4d41_5452_4958_4354;
    const CONTROL_VERSION: u32 = 3;
    const CONTROL_PROBE_OPERATION: u32 = 3;
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

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ControlStatus {
        magic: u64,
        version: u32,
        capabilities: u32,
        current_apic_id: u32,
        processor_count: u32,
        expected_mask: u64,
        active_mask: u64,
        stopped_mask: u64,
        failed_mask: u64,
        exit_boot_services_seen: u64,
        virtual_address_change_seen: u64,
        virtual_address_error: u64,
        completion_sequence: u64,
        apic_ids: [u32; 64],
        probe_snapshot: ControlProbeSnapshot,
    }

    impl Default for ControlStatus {
        fn default() -> Self {
            Self {
                magic: 0,
                version: 0,
                capabilities: 0,
                current_apic_id: 0,
                processor_count: 0,
                expected_mask: 0,
                active_mask: 0,
                stopped_mask: 0,
                failed_mask: 0,
                exit_boot_services_seen: 0,
                virtual_address_change_seen: 0,
                virtual_address_error: 0,
                completion_sequence: 0,
                apic_ids: [0; 64],
                probe_snapshot: ControlProbeSnapshot::default(),
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ControlProbeSnapshot {
        sequence: u64,
        guest_rip: u64,
        guest_rsp: u64,
        guest_rflags: u64,
        guest_cr0: u64,
        guest_cr3: u64,
        guest_cr4: u64,
        guest_efer: u64,
        guest_pat: u64,
        guest_gdtr_base: u64,
        guest_gdtr_limit: u64,
        guest_idtr_base: u64,
        guest_idtr_limit: u64,
        guest_cs_selector: u64,
        guest_ss_selector: u64,
        guest_tr_selector: u64,
        guest_tr_access: u64,
        guest_fs_base: u64,
        guest_gs_base: u64,
        guest_interruptibility: u64,
        idt_vectoring: u64,
        vm_entry_intr_info: u64,
        runtime_get_variable: u64,
        runtime_set_variable: u64,
        runtime_context: u64,
        guest_es_selector: u64,
        guest_ds_selector: u64,
        guest_fs_selector: u64,
        guest_gs_selector: u64,
        guest_ldtr_selector: u64,
        guest_dr7: u64,
        guest_cr4_read_shadow: u64,
        guest_tr_base: u64,
        guest_tr_limit: u64,
    }

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
    struct ShellExecuteInfo {
        size: u32,
        mask: u32,
        window: *mut c_void,
        verb: *const u16,
        file: *const u16,
        parameters: *const u16,
        directory: *const u16,
        show: i32,
        instance: *mut c_void,
        id_list: *mut c_void,
        class: *const u16,
        class_key: *mut c_void,
        hot_key: u32,
        icon_or_monitor: *mut c_void,
        process: *mut c_void,
    }

    #[repr(C)]
    struct ControlRequest {
        magic: u64,
        version: u32,
        operation: u32,
        sequence: u64,
        expected_apic_id: u32,
        reserved: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetCurrentProcess"]
        fn get_current_process() -> *mut c_void;
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

    fn elevated_arguments(command: Command, port: u16, nonce: u128) -> String {
        let command = match command {
            Command::On => "on".to_string(),
            Command::Off => "off".to_string(),
            Command::OffProcessor(index) => format!("off --cpu {index}"),
            Command::Status => "status".to_string(),
        };
        format!("--runtime-elevated {port} {nonce} matrix {command}")
    }

    fn receive_elevated_result(
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
                    let (request_id, response) = read_response(&mut stream)
                        .map_err(|error| format!("failed to read the UAC result: {error}"))?;
                    if request_id != 0 || response.request_kind != RequestKind::Status {
                        return Err("invalid UAC result frame".into());
                    }
                    return Ok(response);
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
        let (response, exit_code) = match execute(command, false) {
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

    pub(super) fn execute(command: Command, allow_elevation: bool) -> Result<String, String> {
        if !enable_firmware_privilege()? {
            if allow_elevation {
                return run_elevated(command);
            }
            return Err("The elevated token does not have SeSystemEnvironmentPrivilege for UEFI runtime variables".into());
        }
        let _control_mutex = ControlMutex::acquire()?;
        let status = read_status()?;
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
                "bridge=present capabilities={:#x} apic_id={} processors={} expected={:#x} observed={:#x} vmexit_probe={:#x} active={:#x} stopped={:#x} failed={:#x} exit_boot_services={} virtual_address_change={} cpu_map={} routes={} probe_errors={} probe_snapshots={}\n",
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
            ));
        }
        let operation = match command {
            Command::On => 1,
            Command::Off | Command::OffProcessor(_) => 2,
            Command::Status => unreachable!(),
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

    #[cfg(test)]
    mod elevation_tests {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/neo_elevation.rs"
        ));
    }
}

pub fn execute(command: Command) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        windows::execute(command, true)
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
