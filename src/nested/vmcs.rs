pub const VMCS12_LAUNCH_STATE_CLEAR: u64 = 0;
pub const VMCS12_LAUNCH_STATE_LAUNCHED: u64 = 1;
pub const VMCS12_LAUNCH_STATE_UNINITIALIZED: u64 = u64::MAX;

pub const VMCLEAR_EXIT_REASON: u64 = 19;
pub const VMLAUNCH_EXIT_REASON: u64 = 20;
pub const VMPTRLD_EXIT_REASON: u64 = 21;
pub const VMPTRST_EXIT_REASON: u64 = 22;
pub const VMREAD_EXIT_REASON: u64 = 23;
pub const VMRESUME_EXIT_REASON: u64 = 24;
pub const VMWRITE_EXIT_REASON: u64 = 25;
pub const VMXOFF_EXIT_REASON: u64 = 26;
pub const VMXON_EXIT_REASON: u64 = 27;
pub const INVEPT_EXIT_REASON: u64 = 50;
pub const INVVPID_EXIT_REASON: u64 = 53;

pub const VMCLEAR_INVALID_PHYSICAL_ADDRESS_ERROR: u32 = 2;
pub const VMCLEAR_VMXON_POINTER_ERROR: u32 = 3;
pub const VMLAUNCH_NON_CLEAR_VMCS_ERROR: u32 = 4;
pub const VMRESUME_NON_LAUNCHED_VMCS_ERROR: u32 = 5;
pub const VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR: u32 = 7;
pub const VM_ENTRY_INVALID_HOST_STATE_FIELD_ERROR: u32 = 8;
pub const VM_ENTRY_BLOCKED_BY_MOV_SS_ERROR: u32 = 26;
pub const INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR: u32 = 28;
pub const VMPTRLD_INVALID_PHYSICAL_ADDRESS_ERROR: u32 = 9;
pub const VMPTRLD_VMXON_POINTER_ERROR: u32 = 10;
pub const VMPTRLD_INCORRECT_REVISION_ERROR: u32 = 11;
pub const VMCS_UNSUPPORTED_COMPONENT_ERROR: u32 = 12;
pub const VMWRITE_READ_ONLY_COMPONENT_ERROR: u32 = 13;
pub const VMXON_IN_VMX_ROOT_ERROR: u32 = 15;

pub const VMX_STATUS_FLAGS: u32 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
pub const VMX_STATUS_FLAGS_CLEAR_MASK: i32 = !(VMX_STATUS_FLAGS as i32);
pub const VMFAIL_INVALID_STATUS: u32 = 1 << 0;
pub const VMFAIL_VALID_STATUS: u32 = 1 << 6;

pub const VMCS_FIELD_VPID: u64 = 0x0000;
pub const VMCS_FIELD_GUEST_ES_SELECTOR: u64 = 0x0800;
pub const VMCS_FIELD_GUEST_CS_SELECTOR: u64 = 0x0802;
pub const VMCS_FIELD_GUEST_SS_SELECTOR: u64 = 0x0804;
pub const VMCS_FIELD_GUEST_DS_SELECTOR: u64 = 0x0806;
pub const VMCS_FIELD_GUEST_FS_SELECTOR: u64 = 0x0808;
pub const VMCS_FIELD_GUEST_GS_SELECTOR: u64 = 0x080a;
pub const VMCS_FIELD_GUEST_LDTR_SELECTOR: u64 = 0x080c;
pub const VMCS_FIELD_GUEST_TR_SELECTOR: u64 = 0x080e;
pub const VMCS_FIELD_HOST_ES_SELECTOR: u64 = 0x0c00;
pub const VMCS_FIELD_HOST_CS_SELECTOR: u64 = 0x0c02;
pub const VMCS_FIELD_HOST_SS_SELECTOR: u64 = 0x0c04;
pub const VMCS_FIELD_HOST_DS_SELECTOR: u64 = 0x0c06;
pub const VMCS_FIELD_HOST_FS_SELECTOR: u64 = 0x0c08;
pub const VMCS_FIELD_HOST_GS_SELECTOR: u64 = 0x0c0a;
pub const VMCS_FIELD_HOST_TR_SELECTOR: u64 = 0x0c0c;
pub const VMCS_FIELD_IO_BITMAP_A: u64 = 0x2000;
pub const VMCS_FIELD_IO_BITMAP_B: u64 = 0x2002;
pub const VMCS_FIELD_MSR_BITMAP: u64 = 0x2004;
pub const VMCS_FIELD_VM_EXIT_MSR_STORE_ADDR: u64 = 0x2006;
pub const VMCS_FIELD_VM_EXIT_MSR_LOAD_ADDR: u64 = 0x2008;
pub const VMCS_FIELD_VM_ENTRY_MSR_LOAD_ADDR: u64 = 0x200a;
pub const VMCS_FIELD_TSC_OFFSET: u64 = 0x2010;
pub const VMCS_FIELD_VIRTUAL_APIC_PAGE_ADDR: u64 = 0x2012;
pub const VMCS_FIELD_APIC_ACCESS_ADDR: u64 = 0x2014;
pub const VMCS_FIELD_EPT_POINTER: u64 = 0x201a;
pub const VMCS_FIELD_XSS_EXITING_BITMAP: u64 = 0x202c;
pub const VMCS_FIELD_VMCS_LINK_POINTER: u64 = 0x2800;
pub const VMCS_FIELD_GUEST_PHYSICAL_ADDRESS: u64 = 0x2400;
pub const VMCS_FIELD_GUEST_IA32_DEBUGCTL: u64 = 0x2802;
pub const VMCS_FIELD_GUEST_IA32_PAT: u64 = 0x2804;
pub const VMCS_FIELD_GUEST_IA32_EFER: u64 = 0x2806;
pub const VMCS_FIELD_HOST_IA32_PAT: u64 = 0x2c00;
pub const VMCS_FIELD_HOST_IA32_EFER: u64 = 0x2c02;
pub const VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL: u64 = 0x4000;
pub const VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL: u64 = 0x4002;
pub const VMCS_FIELD_EXCEPTION_BITMAP: u64 = 0x4004;
pub const VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MASK: u64 = 0x4006;
pub const VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MATCH: u64 = 0x4008;
pub const VMCS_FIELD_CR3_TARGET_COUNT: u64 = 0x400a;
pub const VMCS_FIELD_VM_EXIT_CONTROLS: u64 = 0x400c;
pub const VMCS_FIELD_VM_EXIT_MSR_STORE_COUNT: u64 = 0x400e;
pub const VMCS_FIELD_VM_EXIT_MSR_LOAD_COUNT: u64 = 0x4010;
pub const VMCS_FIELD_VM_ENTRY_CONTROLS: u64 = 0x4012;
pub const VMCS_FIELD_VM_ENTRY_MSR_LOAD_COUNT: u64 = 0x4014;
pub const VMCS_FIELD_VM_ENTRY_INTR_INFO_FIELD: u64 = 0x4016;
pub const VMCS_FIELD_VM_ENTRY_EXCEPTION_ERROR_CODE: u64 = 0x4018;
pub const VMCS_FIELD_VM_ENTRY_INSTRUCTION_LEN: u64 = 0x401a;
pub const VMCS_FIELD_TPR_THRESHOLD: u64 = 0x401c;
pub const VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL: u64 = 0x401e;
pub const VMCS_FIELD_VM_INSTRUCTION_ERROR: u64 = 0x4400;
pub const VMCS_FIELD_VM_EXIT_REASON: u64 = 0x4402;
pub const VMCS_FIELD_VM_EXIT_INTR_INFO: u64 = 0x4404;
pub const VMCS_FIELD_VM_EXIT_INTR_ERROR_CODE: u64 = 0x4406;
pub const VMCS_FIELD_IDT_VECTORING_INFO_FIELD: u64 = 0x4408;
pub const VMCS_FIELD_IDT_VECTORING_ERROR_CODE: u64 = 0x440a;
pub const VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN: u64 = 0x440c;
pub const VMCS_FIELD_GUEST_ES_LIMIT: u64 = 0x4800;
pub const VMCS_FIELD_GUEST_CS_LIMIT: u64 = 0x4802;
pub const VMCS_FIELD_GUEST_SS_LIMIT: u64 = 0x4804;
pub const VMCS_FIELD_GUEST_DS_LIMIT: u64 = 0x4806;
pub const VMCS_FIELD_GUEST_FS_LIMIT: u64 = 0x4808;
pub const VMCS_FIELD_GUEST_GS_LIMIT: u64 = 0x480a;
pub const VMCS_FIELD_GUEST_LDTR_LIMIT: u64 = 0x480c;
pub const VMCS_FIELD_GUEST_TR_LIMIT: u64 = 0x480e;
pub const VMCS_FIELD_GUEST_GDTR_LIMIT: u64 = 0x4810;
pub const VMCS_FIELD_GUEST_IDTR_LIMIT: u64 = 0x4812;
pub const VMCS_FIELD_GUEST_ES_AR_BYTES: u64 = 0x4814;
pub const VMCS_FIELD_GUEST_CS_AR_BYTES: u64 = 0x4816;
pub const VMCS_FIELD_GUEST_SS_AR_BYTES: u64 = 0x4818;
pub const VMCS_FIELD_GUEST_DS_AR_BYTES: u64 = 0x481a;
pub const VMCS_FIELD_GUEST_FS_AR_BYTES: u64 = 0x481c;
pub const VMCS_FIELD_GUEST_GS_AR_BYTES: u64 = 0x481e;
pub const VMCS_FIELD_GUEST_LDTR_AR_BYTES: u64 = 0x4820;
pub const VMCS_FIELD_GUEST_TR_AR_BYTES: u64 = 0x4822;
pub const VMCS_FIELD_GUEST_INTERRUPTIBILITY_INFO: u64 = 0x4824;
pub const VMCS_FIELD_GUEST_ACTIVITY_STATE: u64 = 0x4826;
pub const VMCS_FIELD_GUEST_SYSENTER_CS: u64 = 0x482a;
pub const VMCS_FIELD_HOST_SYSENTER_CS: u64 = 0x4c00;
pub const VMCS_FIELD_CR0_GUEST_HOST_MASK: u64 = 0x6000;
pub const VMCS_FIELD_CR4_GUEST_HOST_MASK: u64 = 0x6002;
pub const VMCS_FIELD_CR0_READ_SHADOW: u64 = 0x6004;
pub const VMCS_FIELD_CR4_READ_SHADOW: u64 = 0x6006;
pub const VMCS_FIELD_CR3_TARGET_VALUE0: u64 = 0x6008;
pub const VMCS_FIELD_CR3_TARGET_VALUE1: u64 = 0x600a;
pub const VMCS_FIELD_CR3_TARGET_VALUE2: u64 = 0x600c;
pub const VMCS_FIELD_CR3_TARGET_VALUE3: u64 = 0x600e;
pub const VMCS_FIELD_EXIT_QUALIFICATION: u64 = 0x6400;
pub const VMCS_FIELD_GUEST_CR0: u64 = 0x6800;
pub const VMCS_FIELD_GUEST_CR3: u64 = 0x6802;
pub const VMCS_FIELD_GUEST_CR4: u64 = 0x6804;
pub const VMCS_FIELD_GUEST_ES_BASE: u64 = 0x6806;
pub const VMCS_FIELD_GUEST_CS_BASE: u64 = 0x6808;
pub const VMCS_FIELD_GUEST_SS_BASE: u64 = 0x680a;
pub const VMCS_FIELD_GUEST_DS_BASE: u64 = 0x680c;
pub const VMCS_FIELD_GUEST_FS_BASE: u64 = 0x680e;
pub const VMCS_FIELD_GUEST_GS_BASE: u64 = 0x6810;
pub const VMCS_FIELD_GUEST_LDTR_BASE: u64 = 0x6812;
pub const VMCS_FIELD_GUEST_TR_BASE: u64 = 0x6814;
pub const VMCS_FIELD_GUEST_GDTR_BASE: u64 = 0x6816;
pub const VMCS_FIELD_GUEST_IDTR_BASE: u64 = 0x6818;
pub const VMCS_FIELD_GUEST_DR7: u64 = 0x681a;
pub const VMCS_FIELD_GUEST_RSP: u64 = 0x681c;
pub const VMCS_FIELD_GUEST_RIP: u64 = 0x681e;
pub const VMCS_FIELD_GUEST_RFLAGS: u64 = 0x6820;
pub const VMCS_FIELD_GUEST_PENDING_DBG_EXCEPTIONS: u64 = 0x6822;
pub const VMCS_FIELD_GUEST_SYSENTER_ESP: u64 = 0x6824;
pub const VMCS_FIELD_GUEST_SYSENTER_EIP: u64 = 0x6826;
pub const VMCS_FIELD_HOST_CR0: u64 = 0x6c00;
pub const VMCS_FIELD_HOST_CR3: u64 = 0x6c02;
pub const VMCS_FIELD_HOST_CR4: u64 = 0x6c04;
pub const VMCS_FIELD_HOST_FS_BASE: u64 = 0x6c06;
pub const VMCS_FIELD_HOST_GS_BASE: u64 = 0x6c08;
pub const VMCS_FIELD_HOST_TR_BASE: u64 = 0x6c0a;
pub const VMCS_FIELD_HOST_GDTR_BASE: u64 = 0x6c0c;
pub const VMCS_FIELD_HOST_IDTR_BASE: u64 = 0x6c0e;
pub const VMCS_FIELD_HOST_SYSENTER_ESP: u64 = 0x6c10;
pub const VMCS_FIELD_HOST_SYSENTER_EIP: u64 = 0x6c12;
pub const VMCS_FIELD_HOST_RSP: u64 = 0x6c14;
pub const VMCS_FIELD_HOST_RIP: u64 = 0x6c16;

pub const VMCS12_EXTENDED_FIELD_COUNT: usize = 111;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmcs12ExtendedField {
    pub encoding: u64,
    pub index: usize,
}

pub const VMCS12_EXTENDED_FIELDS: [Vmcs12ExtendedField; VMCS12_EXTENDED_FIELD_COUNT] = [
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VPID,
        index: 0,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL,
        index: 1,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL,
        index: 2,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL,
        index: 3,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_EXCEPTION_BITMAP,
        index: 4,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MASK,
        index: 5,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MATCH,
        index: 6,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_COUNT,
        index: 7,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_CONTROLS,
        index: 8,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_MSR_STORE_COUNT,
        index: 9,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_MSR_LOAD_COUNT,
        index: 10,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_CONTROLS,
        index: 11,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_MSR_LOAD_COUNT,
        index: 12,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_INTR_INFO_FIELD,
        index: 13,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_EXCEPTION_ERROR_CODE,
        index: 14,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_INSTRUCTION_LEN,
        index: 15,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_EPT_POINTER,
        index: 16,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_TSC_OFFSET,
        index: 17,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_MSR_BITMAP,
        index: 18,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR0_GUEST_HOST_MASK,
        index: 19,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR4_GUEST_HOST_MASK,
        index: 20,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR0_READ_SHADOW,
        index: 21,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR4_READ_SHADOW,
        index: 22,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VMCS_LINK_POINTER,
        index: 23,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IA32_DEBUGCTL,
        index: 24,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IA32_PAT,
        index: 25,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IA32_EFER,
        index: 26,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_IA32_PAT,
        index: 27,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_IA32_EFER,
        index: 28,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CR0,
        index: 29,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CR3,
        index: 30,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CR4,
        index: 31,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_CR0,
        index: 32,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_CR3,
        index: 33,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_CR4,
        index: 34,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ES_SELECTOR,
        index: 35,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CS_SELECTOR,
        index: 36,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SS_SELECTOR,
        index: 37,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DS_SELECTOR,
        index: 38,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_FS_SELECTOR,
        index: 39,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GS_SELECTOR,
        index: 40,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_LDTR_SELECTOR,
        index: 41,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_TR_SELECTOR,
        index: 42,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_ES_SELECTOR,
        index: 43,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_CS_SELECTOR,
        index: 44,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_SS_SELECTOR,
        index: 45,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_DS_SELECTOR,
        index: 46,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_FS_SELECTOR,
        index: 47,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_GS_SELECTOR,
        index: 48,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_TR_SELECTOR,
        index: 49,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ES_BASE,
        index: 50,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CS_BASE,
        index: 51,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SS_BASE,
        index: 52,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DS_BASE,
        index: 53,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_FS_BASE,
        index: 54,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GS_BASE,
        index: 55,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_LDTR_BASE,
        index: 56,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_TR_BASE,
        index: 57,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GDTR_BASE,
        index: 58,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IDTR_BASE,
        index: 59,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_FS_BASE,
        index: 60,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_GS_BASE,
        index: 61,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_TR_BASE,
        index: 62,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_GDTR_BASE,
        index: 63,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_IDTR_BASE,
        index: 64,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ES_LIMIT,
        index: 65,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CS_LIMIT,
        index: 66,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SS_LIMIT,
        index: 67,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DS_LIMIT,
        index: 68,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_FS_LIMIT,
        index: 69,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GS_LIMIT,
        index: 70,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_LDTR_LIMIT,
        index: 71,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_TR_LIMIT,
        index: 72,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GDTR_LIMIT,
        index: 73,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_IDTR_LIMIT,
        index: 74,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ES_AR_BYTES,
        index: 75,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_CS_AR_BYTES,
        index: 76,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SS_AR_BYTES,
        index: 77,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DS_AR_BYTES,
        index: 78,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_FS_AR_BYTES,
        index: 79,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_GS_AR_BYTES,
        index: 80,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_LDTR_AR_BYTES,
        index: 81,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_TR_AR_BYTES,
        index: 82,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_INTERRUPTIBILITY_INFO,
        index: 83,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_ACTIVITY_STATE,
        index: 84,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SYSENTER_CS,
        index: 85,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SYSENTER_ESP,
        index: 86,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_SYSENTER_EIP,
        index: 87,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_SYSENTER_CS,
        index: 88,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_SYSENTER_ESP,
        index: 89,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_HOST_SYSENTER_EIP,
        index: 90,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_DR7,
        index: 91,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_PENDING_DBG_EXCEPTIONS,
        index: 92,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_IO_BITMAP_A,
        index: 93,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_IO_BITMAP_B,
        index: 94,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_XSS_EXITING_BITMAP,
        index: 95,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_VALUE0,
        index: 96,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_VALUE1,
        index: 97,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_VALUE2,
        index: 98,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_CR3_TARGET_VALUE3,
        index: 99,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_TPR_THRESHOLD,
        index: 100,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VIRTUAL_APIC_PAGE_ADDR,
        index: 101,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_APIC_ACCESS_ADDR,
        index: 102,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_MSR_STORE_ADDR,
        index: 103,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_MSR_LOAD_ADDR,
        index: 104,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_ENTRY_MSR_LOAD_ADDR,
        index: 105,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_INTR_INFO,
        index: 106,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_VM_EXIT_INTR_ERROR_CODE,
        index: 107,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_IDT_VECTORING_INFO_FIELD,
        index: 108,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_IDT_VECTORING_ERROR_CODE,
        index: 109,
    },
    Vmcs12ExtendedField {
        encoding: VMCS_FIELD_GUEST_PHYSICAL_ADDRESS,
        index: 110,
    },
];

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedVmcs12State {
    pub operand: u64,
    pub region: u64,
    pub vmptrst_destination: u64,
    pub last_stored_pointer: u64,
    pub revision_id: u64,
    pub launch_state: u64,
    pub guest_rip: u64,
    pub vmclear_count: u64,
    pub vmptrld_count: u64,
    pub vmptrst_count: u64,
    pub vmwrite_count: u64,
    pub vmread_count: u64,
    pub probe_complete: u64,
    pub vmlaunch_count: u64,
    pub vmresume_count: u64,
    pub entry_rejection_count: u64,
    pub guest_rsp: u64,
    pub guest_rflags: u64,
    pub host_rsp: u64,
    pub host_rip: u64,
    pub exit_reason: u64,
    pub exit_instruction_len: u64,
    pub exit_qualification: u64,
    pub extended_fields: [u64; VMCS12_EXTENDED_FIELD_COUNT],
    pub control_validation_count: u64,
}

impl NestedVmcs12State {
    pub fn new(revision_id: u32, operand: u64, region: u64, vmptrst_destination: u64) -> Self {
        Self {
            operand,
            region,
            vmptrst_destination,
            last_stored_pointer: 0,
            revision_id: u64::from(revision_id),
            launch_state: VMCS12_LAUNCH_STATE_UNINITIALIZED,
            guest_rip: 0,
            vmclear_count: 0,
            vmptrld_count: 0,
            vmptrst_count: 0,
            vmwrite_count: 0,
            vmread_count: 0,
            probe_complete: 0,
            vmlaunch_count: 0,
            vmresume_count: 0,
            entry_rejection_count: 0,
            guest_rsp: 0,
            guest_rflags: 0,
            host_rsp: 0,
            host_rip: 0,
            exit_reason: 0,
            exit_instruction_len: 0,
            exit_qualification: 0,
            extended_fields: [0; VMCS12_EXTENDED_FIELD_COUNT],
            control_validation_count: 0,
        }
    }
}

pub const VMCS12_BACKING_MAGIC: u64 = 0x4d48_5656_4d43_5331;
pub const VMCS12_BACKING_MAGIC_OFFSET: usize = 0x20;
pub const VMCS12_BACKING_STATE_OFFSET: usize = 0x100;
pub const VMCS12_BACKING_QWORD_COUNT: usize =
    core::mem::size_of::<NestedVmcs12State>() / core::mem::size_of::<u64>();

const _: () = assert!(VMCS12_BACKING_MAGIC_OFFSET + core::mem::size_of::<u64>() <= 0x100);
const _: () = assert!(VMCS12_BACKING_STATE_OFFSET & 7 == 0);
const _: () =
    assert!(VMCS12_BACKING_STATE_OFFSET + core::mem::size_of::<NestedVmcs12State>() <= 4096);
