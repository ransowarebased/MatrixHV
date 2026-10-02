mod arch {
    pub const IA32_DEBUGCTL: u32 = 0x1d9;
    pub const IA32_SYSENTER_CS: u32 = 0x174;
    pub const IA32_SYSENTER_ESP: u32 = 0x175;
    pub const IA32_SYSENTER_EIP: u32 = 0x176;
    pub const IA32_PAT: u32 = 0x277;
    pub const IA32_EFER: u32 = 0xc000_0080;
    pub const IA32_FS_BASE: u32 = 0xc000_0100;
    pub const IA32_GS_BASE: u32 = 0xc000_0101;

    pub struct CpuIdLeaf {
        pub eax: u32,
        pub ebx: u32,
        pub ecx: u32,
        pub edx: u32,
    }

    pub fn leaf(_leaf: u32) -> CpuIdLeaf {
        CpuIdLeaf {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: (1 << 11) | (1 << 20),
        }
    }

    pub fn leaf_with_subleaf(_leaf: u32, _subleaf: u32) -> CpuIdLeaf {
        CpuIdLeaf {
            eax: 1,
            ebx: 2,
            ecx: 3,
            edx: 4,
        }
    }

    pub fn read_cr3() -> u64 {
        0x1000
    }
}

mod runtime {
    pub fn phase(_phase: &str) {}
    pub fn info(_message: core::fmt::Arguments<'_>) {}
    pub fn error(_message: core::fmt::Arguments<'_>) {}
}

mod nested {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NestedVmxState;
}

mod hv_core {
    pub mod vmcs {
        use std::cell::RefCell;
        use std::collections::BTreeMap;

        macro_rules! fields {
            ($($name:ident),+ $(,)?) => {
                fields!(@define 1; $($name),+);
            };
            (@define $value:expr; $name:ident, $($remaining:ident),+) => {
                pub const $name: u64 = $value;
                fields!(@define $value + 1; $($remaining),+);
            };
            (@define $value:expr; $name:ident) => {
                pub const $name: u64 = $value;
            };
        }

        fields!(
            EXIT_QUALIFICATION, GUEST_CR0, GUEST_CR3, GUEST_CR4, GUEST_CS_AR_BYTES,
            GUEST_FS_BASE, GUEST_GS_BASE, GUEST_IA32_DEBUGCTL, GUEST_IA32_EFER,
            GUEST_IA32_PAT, GUEST_INTERRUPTIBILITY_INFO, GUEST_PENDING_DBG_EXCEPTIONS,
            GUEST_RFLAGS, GUEST_RIP, GUEST_SS_AR_BYTES, GUEST_SYSENTER_CS,
            GUEST_SYSENTER_EIP, GUEST_SYSENTER_ESP, VM_ENTRY_EXCEPTION_ERROR_CODE,
            VM_ENTRY_INTR_INFO_FIELD, VM_EXIT_INSTRUCTION_LEN, VM_EXIT_REASON,
        );

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct VmcsError;

        thread_local! {
            static FIELDS: RefCell<BTreeMap<u64, u64>> = RefCell::new(BTreeMap::new());
        }

        pub fn vmread(field: u64) -> Result<u64, VmcsError> {
            FIELDS.with(|fields| fields.borrow().get(&field).copied().ok_or(VmcsError))
        }

        pub fn vmwrite(field: u64, value: u64) -> Result<(), VmcsError> {
            FIELDS.with(|fields| {
                fields.borrow_mut().insert(field, value);
            });
            Ok(())
        }

        pub fn reset() {
            FIELDS.with(|fields| {
                fields.borrow_mut().clear();
            });
            for (field, value) in [
                (GUEST_CR0, 1 << 31 | 1),
                (GUEST_CR4, 0),
                (GUEST_CS_AR_BYTES, 1 << 13),
                (GUEST_SS_AR_BYTES, 0),
                (GUEST_RFLAGS, 2),
                (GUEST_IA32_DEBUGCTL, 0),
                (GUEST_INTERRUPTIBILITY_INFO, 0),
                (GUEST_PENDING_DBG_EXCEPTIONS, 0),
                (GUEST_IA32_PAT, 0x0007_0406_0007_0406),
                (GUEST_IA32_EFER, 0x500),
                (GUEST_RIP, 0x1000),
            ] {
                vmwrite(field, value).unwrap();
            }
        }
    }

    pub mod exits {
        include!("../src/core/exits.rs");

        #[cfg(test)]
        mod regression {
            use super::*;
            use crate::hv_core::vmcs;

            #[test]
            fn probe_contract_reports_known_exit_reasons() {
                let reason_codes = [
                    VMCALL_EXIT_REASON,
                    CPUID_EXIT_REASON,
                    RDMSR_EXIT_REASON,
                    WRMSR_EXIT_REASON,
                    XSETBV_EXIT_REASON,
                    EPT_VIOLATION_EXIT_REASON,
                    EPT_MISCONFIGURATION_EXIT_REASON,
                    VMX_PREEMPTION_TIMER_EXIT_REASON,
                    VM_ENTRY_FAILURE_MSR_LOADING_EXIT_REASON,
                ];
                assert_eq!(reason_codes, [18, 10, 31, 32, 55, 48, 49, 52, 34]);
                assert_eq!(VmRunContext::for_boot_target().exit_limit, 65536);
                assert_eq!(failure_name(DISPATCH_FAILURE_EXIT_LIMIT), "exit_limit_exceeded");
                assert!(core::mem::size_of::<ResidentBootReport>() > 0);
            }

            #[test]
            fn prefixed_cpuid_completes_interrupt_shadow_and_single_step() {
                vmcs::reset();
                vmcs::vmwrite(GUEST_RFLAGS, 0x102).unwrap();
                vmcs::vmwrite(GUEST_INTERRUPTIBILITY_INFO, 1).unwrap();
                let mut registers = GuestRegisters::default();
                let result = dispatch_cpuid(&mut registers, 0x1000, 3, false);
                assert_eq!(result, DispatchAction::Resume as u64);
                assert_eq!(registers.rax, 1);
                assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), 0x1003);
                assert_eq!(vmcs::vmread(GUEST_INTERRUPTIBILITY_INFO).unwrap(), 0);
                assert_eq!(vmcs::vmread(GUEST_PENDING_DBG_EXCEPTIONS).unwrap(), 1 << 14);
            }

            #[test]
            fn branch_step_mode_does_not_create_step_for_cpuid() {
                vmcs::reset();
                vmcs::vmwrite(GUEST_RFLAGS, 0x102).unwrap();
                vmcs::vmwrite(GUEST_IA32_DEBUGCTL, 1 << 1).unwrap();
                vmcs::vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 1 << 12).unwrap();
                advance_guest_rip(0x1000, 2).unwrap();
                assert_eq!(vmcs::vmread(GUEST_PENDING_DBG_EXCEPTIONS).unwrap(), 1 << 12);
            }

            #[test]
            fn cpuid_preserves_eip_above_16_bits_in_legacy_and_compatibility_modes() {
                for efer in [0, 0x500] {
                    for cs_access_rights in [0, 1 << 14] {
                        for (rip, expected) in [(0xfffe, 0x10000), (0x10000, 0x10002)] {
                            vmcs::reset();
                            vmcs::vmwrite(GUEST_CS_AR_BYTES, cs_access_rights).unwrap();
                            vmcs::vmwrite(GUEST_IA32_EFER, efer).unwrap();
                            let mut registers = GuestRegisters::default();
                            assert_eq!(dispatch_cpuid(&mut registers, rip, 2, false), 1);
                            assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), expected);
                        }
                    }
                }
            }

            #[test]
            fn instruction_pointer_uses_64_bits_only_when_lma_and_cs_l_are_set() {
                for (cs_access_rights, efer, rip, expected) in [
                    (0, 0, 0xffff_fffe, 0),
                    (1 << 14, 0, 0xffff_fffe, 0),
                    (0, 0x500, 0xffff_fffe, 0),
                    (1 << 14, 0x500, 0xffff_fffe, 0),
                    (1 << 13, 0, 0xffff_fffe, 0),
                    (1 << 13, 0x500, 0xffff_fffe, 0x1_0000_0000),
                    (1 << 13, 0x500, u64::MAX - 1, 0),
                ] {
                    vmcs::reset();
                    vmcs::vmwrite(GUEST_CS_AR_BYTES, cs_access_rights).unwrap();
                    vmcs::vmwrite(GUEST_IA32_EFER, efer).unwrap();
                    advance_guest_rip(rip, 2).unwrap();
                    assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), expected);
                }
            }

            #[test]
            fn wrmsr_efer_ignores_source_lma_and_preserves_architectural_lma() {
                for (old_efer, cr0, value, expected) in [
                    (0, 1, 0x400, 0),
                    (0, 1, 0xd01, 0x901),
                    (0, (1 << 31) | 1, 0x401, 1),
                    (0x500, (1 << 31) | 1, 0x100, 0x500),
                    (0x500, (1 << 31) | 1, 0x901, 0xd01),
                    (0xd01, (1 << 31) | 1, 0x100, 0x500),
                ] {
                    vmcs::reset();
                    vmcs::vmwrite(GUEST_IA32_EFER, old_efer).unwrap();
                    vmcs::vmwrite(GUEST_CR0, cr0).unwrap();
                    vmcs::vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0).unwrap();
                    let registers = GuestRegisters {
                        rcx: u64::from(arch::IA32_EFER),
                        rax: value,
                        ..GuestRegisters::default()
                    };
                    assert_eq!(dispatch_wrmsr(&registers, 0x1000, 2, false), 1);
                    assert_eq!(vmcs::vmread(GUEST_IA32_EFER).unwrap(), expected);
                    assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), 0x1002);
                    assert_eq!(vmcs::vmread(VM_ENTRY_INTR_INFO_FIELD).unwrap(), 0);
                }
            }

            #[test]
            fn wrmsr_efer_rejects_reserved_bits_and_lme_changes_with_paging() {
                for (old_efer, value) in [
                    (0, 0x100),
                    (0, 0x500),
                    (0x500, 0),
                    (0x500, 0x400),
                    (0x500, 0x102),
                    (0x500, 0x1100),
                    (0x500, (1u64 << 63) | 0x100),
                ] {
                    vmcs::reset();
                    vmcs::vmwrite(GUEST_IA32_EFER, old_efer).unwrap();
                    let registers = GuestRegisters {
                        rcx: u64::from(arch::IA32_EFER),
                        rax: value & u64::from(u32::MAX),
                        rdx: value >> 32,
                        ..GuestRegisters::default()
                    };
                    assert_eq!(dispatch_wrmsr(&registers, 0x1000, 2, false), 1);
                    assert_eq!(vmcs::vmread(GUEST_IA32_EFER).unwrap(), old_efer);
                    assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), 0x1000);
                    assert_eq!(vmcs::vmread(VM_ENTRY_INTR_INFO_FIELD).unwrap(), 0x8000_0b0d);
                }
            }

            #[test]
            fn unsupported_msr_injects_gp_without_executing_a_root_msr() {
                vmcs::reset();
                let mut registers = GuestRegisters {
                    rcx: 0xdead_beef,
                    ..GuestRegisters::default()
                };
                assert_eq!(dispatch_rdmsr(&mut registers, 0x1000, 2, false), 1);
                assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), 0x1000);
                assert_eq!(vmcs::vmread(VM_ENTRY_INTR_INFO_FIELD).unwrap(), 0x8000_0b0d);
            }

            #[test]
            fn invalid_pat_write_preserves_guest_state_and_rip() {
                vmcs::reset();
                let old_pat = vmcs::vmread(GUEST_IA32_PAT).unwrap();
                let registers = GuestRegisters {
                    rcx: u64::from(arch::IA32_PAT),
                    rax: 2,
                    ..GuestRegisters::default()
                };
                assert_eq!(dispatch_wrmsr(&registers, 0x1000, 2, false), 1);
                assert_eq!(vmcs::vmread(GUEST_IA32_PAT).unwrap(), old_pat);
                assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), 0x1000);
                assert_eq!(vmcs::vmread(VM_ENTRY_INTR_INFO_FIELD).unwrap(), 0x8000_0b0d);
            }

            #[test]
            fn prefixed_guest_msr_access_uses_vmcs_state() {
                vmcs::reset();
                let registers = GuestRegisters {
                    rcx: u64::from(arch::IA32_FS_BASE),
                    rax: 0x1000_2000,
                    ..GuestRegisters::default()
                };
                assert_eq!(dispatch_wrmsr(&registers, 0x1000, 4, false), 1);
                assert_eq!(vmcs::vmread(GUEST_FS_BASE).unwrap(), 0x1000_2000);
                assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), 0x1004);
                let mut read_registers = GuestRegisters {
                    rcx: u64::from(arch::IA32_FS_BASE),
                    ..GuestRegisters::default()
                };
                assert_eq!(dispatch_rdmsr(&mut read_registers, 0x1004, 4, false), 1);
                assert_eq!(read_registers.rax, 0x1000_2000);
                assert_eq!(read_registers.rdx, 0);
                assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), 0x1008);
            }

            #[test]
            fn unprivileged_msr_access_faults_without_mutating_guest_msr() {
                vmcs::reset();
                vmcs::vmwrite(GUEST_SS_AR_BYTES, 3 << 5).unwrap();
                let registers = GuestRegisters {
                    rcx: u64::from(arch::IA32_FS_BASE),
                    rax: 0x4000,
                    ..GuestRegisters::default()
                };
                assert_eq!(dispatch_wrmsr(&registers, 0x1000, 2, false), 1);
                assert!(vmcs::vmread(GUEST_FS_BASE).is_err());
                assert_eq!(vmcs::vmread(GUEST_RIP).unwrap(), 0x1000);
                assert_eq!(vmcs::vmread(VM_ENTRY_INTR_INFO_FIELD).unwrap(), 0x8000_0b0d);
            }

            #[test]
            fn real_mode_msr_fault_does_not_request_an_error_code() {
                vmcs::reset();
                vmcs::vmwrite(GUEST_CR0, 0).unwrap();
                let mut registers = GuestRegisters {
                    rcx: 0xdead_beef,
                    ..GuestRegisters::default()
                };
                assert_eq!(dispatch_rdmsr(&mut registers, 0x1000, 2, false), 1);
                assert_eq!(vmcs::vmread(VM_ENTRY_INTR_INFO_FIELD).unwrap(), 0x8000_030d);
            }

            #[test]
            fn exit_over_limit_publishes_the_current_exit_fields() {
                vmcs::reset();
                reset_diagnostics();
                vmcs::vmwrite(VM_EXIT_REASON, 10).unwrap();
                vmcs::vmwrite(VM_EXIT_INSTRUCTION_LEN, 4).unwrap();
                vmcs::vmwrite(EXIT_QUALIFICATION, 0x1234).unwrap();
                vmcs::vmwrite(GUEST_CR3, 0x2000).unwrap();
                let mut registers = GuestRegisters::default();
                let mut context = VmRunContext::default();
                context.exit_limit = 0;
                assert_eq!(matrixhv_vmexit_dispatch(&mut registers, &mut context), 0);
                let report = diagnostics();
                assert_eq!(report.exit_count, 1);
                assert_eq!(report.last_reason, 10);
                assert_eq!(report.last_instruction_length, 4);
                assert_eq!(report.last_qualification, 0x1234);
            }

            #[test]
            fn resident_vmwrite_errors_keep_the_collected_instruction_error() {
                assert_eq!(
                    validate_resident_run_path(3, 0x29),
                    Err(ResidentRunError::HostRspVmwriteVmFailValid(0x29))
                );
                assert_eq!(
                    validate_resident_run_path(4, 0x2a),
                    Err(ResidentRunError::HostRipVmwriteVmFailValid(0x2a))
                );
                assert_eq!(
                    validate_resident_run_path(7, u64::MAX),
                    Err(ResidentRunError::HostRspVmwriteVmFailInvalid)
                );
                assert_eq!(
                    validate_resident_run_path(8, u64::MAX),
                    Err(ResidentRunError::HostRipVmwriteVmFailInvalid)
                );
            }
        }
    }
}
