extern crate self as uefi;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status;

pub mod mem {
    pub mod memory_map {
        #[derive(Clone, Copy, Eq, PartialEq)]
        pub struct MemoryType(u32);

        impl MemoryType {
            pub const RESERVED: Self = Self(0);
            pub const LOADER_CODE: Self = Self(1);
            pub const LOADER_DATA: Self = Self(2);
            pub const BOOT_SERVICES_CODE: Self = Self(3);
            pub const BOOT_SERVICES_DATA: Self = Self(4);
            pub const RUNTIME_SERVICES_CODE: Self = Self(5);
            pub const RUNTIME_SERVICES_DATA: Self = Self(6);
            pub const CONVENTIONAL: Self = Self(7);
            pub const UNUSABLE: Self = Self(8);
            pub const ACPI_RECLAIM: Self = Self(9);
            pub const ACPI_NON_VOLATILE: Self = Self(10);
            pub const MMIO: Self = Self(11);
            pub const MMIO_PORT_SPACE: Self = Self(12);
            pub const PERSISTENT_MEMORY: Self = Self(14);
            pub const UNACCEPTED: Self = Self(15);
        }

        #[derive(Clone, Copy)]
        pub struct MemoryAttribute(u64);

        impl MemoryAttribute {
            pub const NONE: Self = Self(0);
            pub const UNCACHEABLE: Self = Self(1);
            pub const WRITE_COMBINE: Self = Self(2);
            pub const WRITE_THROUGH: Self = Self(4);
            pub const WRITE_BACK: Self = Self(8);
            pub const UNCACHABLE_EXPORTED: Self = Self(16);

            pub fn contains(self, value: Self) -> bool {
                self.0 & value.0 == value.0
            }
        }

        impl core::ops::BitOr for MemoryAttribute {
            type Output = Self;

            fn bitor(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }
        }

        #[derive(Clone, Copy)]
        pub struct MemoryDescriptor {
            pub phys_start: u64,
            pub page_count: u64,
            pub ty: MemoryType,
            pub att: MemoryAttribute,
        }
    }
}

mod arch {
    use std::cell::RefCell;

    std::thread_local! {
        static MSR_OVERRIDES: RefCell<Vec<(u32, u64)>> = const { RefCell::new(Vec::new()) };
    }

    pub fn with_msr_overrides<R>(values: &[(u32, u64)], action: impl FnOnce() -> R) -> R {
        struct Restore(Vec<(u32, u64)>);

        impl Drop for Restore {
            fn drop(&mut self) {
                MSR_OVERRIDES.with(|overrides| overrides.replace(core::mem::take(&mut self.0)));
            }
        }

        let _restore = Restore(MSR_OVERRIDES.with(|overrides| overrides.replace(values.to_vec())));
        action()
    }

    pub const IA32_VMX_EPT_VPID_CAP: u32 = 0x48c;

    pub struct Leaf {
        pub eax: u32,
        pub edx: u32,
    }

    pub fn leaf(_selector: u32) -> Leaf {
        Leaf {
            eax: 48,
            edx: 1 << 12,
        }
    }

    pub unsafe fn read_msr(register: u32) -> u64 {
        if let Some(value) = MSR_OVERRIDES.with(|overrides| {
            overrides
                .borrow()
                .iter()
                .find_map(|&(index, value)| (index == register).then_some(value))
        }) {
            return value;
        }
        match register {
            IA32_VMX_EPT_VPID_CAP => {
                (1 << 6) | (1 << 8) | (1 << 14) | (1 << 16) | (1 << 17) | (1 << 20) | (1 << 25)
            }
            0xfe => 0,
            0x2ff => 0x806,
            _ => panic!("Unexpected MSR read: {register:#x}"),
        }
    }
}

mod memory {
    pub mod host {
        use std::alloc::{Layout, alloc_zeroed, dealloc};
        use std::ptr::NonNull;

        use crate::Status;

        pub const PAGE_SIZE: usize = 4096;

        pub enum AddressConstraint {
            Any,
        }

        pub struct ResidentPages {
            pointer: NonNull<u8>,
            layout: Layout,
        }

        impl ResidentPages {
            pub fn allocate(pages: usize, _constraint: AddressConstraint) -> Result<Self, Status> {
                let bytes = pages.checked_mul(PAGE_SIZE).ok_or(Status)?;
                let layout = Layout::from_size_align(bytes, PAGE_SIZE).map_err(|_| Status)?;
                let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(Status)?;
                Ok(Self { pointer, layout })
            }

            pub fn pages(&self) -> usize {
                self.layout.size() / PAGE_SIZE
            }

            pub fn physical_address(&self) -> u64 {
                self.pointer.as_ptr() as u64
            }

            pub fn pointer(&self) -> NonNull<u8> {
                self.pointer
            }
        }

        impl Drop for ResidentPages {
            fn drop(&mut self) {
                unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
            }
        }
    }
}

mod ept {
    include!("../src/vmx/ept.rs");

    #[test]
    fn reserved_write_back_capability_preserves_cacheable_firmware_ram() {
        let attributes = MemoryAttribute::UNCACHEABLE
            | MemoryAttribute::WRITE_COMBINE
            | MemoryAttribute::WRITE_THROUGH
            | MemoryAttribute::WRITE_BACK;
        let start = 0x9900_0000;
        let mut ept = IdentityEpt::build(
            vec![MemoryDescriptor {
                phys_start: start,
                page_count: 512,
                ty: MemoryType::RESERVED,
                att: attributes,
            }],
            0,
        )
        .unwrap();
        for address in [start, start + 4096, start + EPT_2MB_PAGE_SIZE - 1] {
            let translation = ept.translate(address).unwrap();
            assert_eq!(translation.physical_address, address);
            assert_eq!(translation.permissions, EPT_PERMISSIONS);
            assert_eq!(ept.memory_type_at_gpa(address), Some(6));
            assert!(!translation.ignore_pat);
            assert_eq!(
                ept.leaf_entry_value(address & !0xfff).unwrap() & EPT_FIRMWARE_TYPE_MASK,
                6 << EPT_FIRMWARE_TYPE_SHIFT
            );
        }
    }

    #[test]
    fn reserved_write_back_ram_still_honors_uncacheable_mtrr_ranges() {
        let start = 0x9900_0000;
        let uc_start = start + EPT_2MB_PAGE_SIZE;
        let mask = (((1_u64 << 48) - 1) & !(EPT_2MB_PAGE_SIZE - 1)) | (1 << 11);
        crate::arch::with_msr_overrides(&[(0xfe, 1), (0x200, uc_start), (0x201, mask)], || {
            let mut ept = IdentityEpt::build(
                vec![MemoryDescriptor {
                    phys_start: start,
                    page_count: 1024,
                    ty: MemoryType::RESERVED,
                    att: MemoryAttribute::WRITE_BACK,
                }],
                0,
            )
            .unwrap();
            assert_eq!(ept.memory_type_at_gpa(start), Some(6));
            assert_eq!(ept.memory_type_at_gpa(uc_start - 1), Some(6));
            for address in [uc_start, uc_start + EPT_2MB_PAGE_SIZE - 1] {
                assert_eq!(ept.memory_type_at_gpa(address), Some(0));
                let entry = ept.leaf_entry_value(address & !0xfff).unwrap();
                assert_eq!(entry & EPT_IGNORE_PAT, 0);
                assert_eq!(entry & EPT_FIRMWARE_TYPE_MASK, 6 << EPT_FIRMWARE_TYPE_SHIFT);
            }
        });
    }

    #[test]
    fn device_or_unusable_memory_does_not_become_write_back_from_attributes() {
        for ty in [
            MemoryType::MMIO,
            MemoryType::MMIO_PORT_SPACE,
            MemoryType::UNUSABLE,
            MemoryType::UNACCEPTED,
        ] {
            for attributes in [
                MemoryAttribute::WRITE_BACK,
                MemoryAttribute::WRITE_BACK
                    | MemoryAttribute::UNCACHEABLE
                    | MemoryAttribute::WRITE_THROUGH
                    | MemoryAttribute::WRITE_COMBINE,
            ] {
                let start = 0x9900_0000;
                let mut ept = IdentityEpt::build(
                    vec![MemoryDescriptor {
                        phys_start: start,
                        page_count: 512,
                        ty,
                        att: attributes,
                    }],
                    0,
                )
                .unwrap();
                assert_eq!(ept.memory_type_at_gpa(start), Some(0));
                assert_eq!(ept.memory_type_at_gpa(start + EPT_2MB_PAGE_SIZE - 1), Some(0));
                assert_eq!(ept.leaf_entry_value(start).unwrap() & EPT_IGNORE_PAT, 0);
            }
        }
    }

    #[test]
    fn reserved_memory_without_write_back_capability_remains_uncacheable() {
        for attributes in [
            MemoryAttribute::NONE,
            MemoryAttribute::UNCACHEABLE,
            MemoryAttribute::UNCACHABLE_EXPORTED,
            MemoryAttribute::WRITE_COMBINE,
            MemoryAttribute::WRITE_THROUGH,
        ] {
            let start = 0x9900_0000;
            let mut ept = IdentityEpt::build(
                vec![MemoryDescriptor {
                    phys_start: start,
                    page_count: 512,
                    ty: MemoryType::RESERVED,
                    att: attributes,
                }],
                0,
            )
            .unwrap();
            assert_eq!(ept.memory_type_at_gpa(start), Some(0));
            assert_eq!(ept.leaf_entry_value(start).unwrap() & EPT_IGNORE_PAT, 0);
        }
    }

    #[test]
    fn accessed_dirty_control_requires_the_hardware_capability() {
        assert_eq!(ept_pointer_attributes(0), 0x1e);
        assert_eq!(ept_pointer_attributes(EPT_CAP_ACCESSED_DIRTY), 0x5e);
        assert_eq!(
            ept_pointer_attributes(u64::MAX & !EPT_CAP_ACCESSED_DIRTY),
            0x1e
        );
        assert_eq!(ept_pointer_attributes(u64::MAX), 0x5e);
    }

    fn empty(mapped_end: u64) -> IdentityEpt {
        let mut pages = Vec::new();
        let root = allocate_table(&mut pages).unwrap();
        IdentityEpt {
            pages,
            protection_pool: ProtectionTablePool::allocate(0).unwrap(),
            root,
            ept_pointer: root.physical_address | 0x1e,
            mapped_end,
            large_pages_supported: true,
        }
    }

    fn one_gb_leaf(attributes: u64) -> IdentityEpt {
        let mut ept = empty(EPT_GUEST_PHYSICAL_LIMIT);
        let pdpt = allocate_table(&mut ept.pages).unwrap();
        write_entry(ept.root, 0, table_entry(pdpt.physical_address));
        write_entry(pdpt, 4, 0x2_0000_0000 | EPT_LARGE_PAGE | attributes);
        ept
    }

    #[test]
    fn large_leaf_split_preserves_neighbors_and_all_leaf_attributes() {
        let attributes = EPT_READ
            | EPT_EXECUTE
            | (6 << 3)
            | (6 << 52)
            | (1 << 6)
            | (1 << 8)
            | (1 << 9)
            | (1 << 63);
        let mut ept = one_gb_leaf(attributes);
        let address = 0x1_0040_5000;
        assert_eq!(
            ept.translate(address).unwrap().physical_address,
            address + (1 << 32)
        );
        assert_eq!(
            ept.leaf_entry_value(address).unwrap(),
            0x2_0040_5000 | attributes
        );
        assert_eq!(ept.protection_table_pool().2, 2);
        for neighbor in [address - 4096, address + 4096, 0x1_0000_0000, 0x1_3fff_ffff] {
            let translated = ept.translate(neighbor).unwrap();
            assert_eq!(translated.physical_address, neighbor + (1 << 32));
            assert_eq!(translated.permissions, EPT_READ | EPT_EXECUTE);
        }
        ept.remap_page(address, 0x9000).unwrap();
        assert_eq!(ept.translate(address).unwrap().physical_address, 0x9000);
        assert_eq!(
            ept.leaf_entry_value(address).unwrap() & !EPT_ADDRESS_MASK,
            attributes
        );
        ept.deny_guest_access(address, 1).unwrap();
        assert_eq!(ept.translate(address), Err(EptError::InvalidPageTable));
    }

    #[test]
    fn cloning_includes_split_and_sparse_pool_tables_and_owns_its_copies() {
        let mut original = one_gb_leaf(EPT_PERMISSIONS | (6 << 3) | (6 << 52));
        original.ept_pointer |= EPT_ACCESSED_DIRTY_ENABLED;
        original.remap_page(0x1_0000_1000, 0x7000).unwrap();
        original.deny_guest_access(0x1_0000_2000, 1).unwrap();
        let mut clone = original.clone_identity_tables().unwrap();
        assert_ne!(clone.ept_pointer(), original.ept_pointer());
        assert_ne!(clone.ept_pointer() & EPT_ACCESSED_DIRTY_ENABLED, 0);
        assert_eq!(clone.protection_table_pool().2, 0);
        assert_eq!(clone.pages[0].pages(), original.pages.len() + 2);
        drop(original);
        assert_eq!(
            clone.translate(0x1_0000_1000).unwrap().physical_address,
            0x7000
        );
        assert_eq!(
            clone.translate(0x1_0000_2000),
            Err(EptError::InvalidPageTable)
        );
        clone.remap_page(0x1_0000_1000, 0x8000).unwrap();
        let mut sparse = clone.sparse_shadow().unwrap();
        assert_ne!(sparse.ept_pointer() & EPT_ACCESSED_DIRTY_ENABLED, 0);
        sparse
            .compose_page(&clone, &empty_identity_page(0x8000), 0x1_0000_1000)
            .unwrap();
        let copied_sparse = sparse.clone_identity_tables().unwrap();
        drop(sparse);
        assert_eq!(
            copied_sparse
                .translate(0x1_0000_1000)
                .unwrap()
                .physical_address,
            0x8000
        );
    }

    fn empty_identity_page(address: u64) -> IdentityEpt {
        let mut ept = empty(EPT_GUEST_PHYSICAL_LIMIT);
        let (table, index) = ept.ensure_4k_leaf(address).unwrap();
        write_entry(
            table,
            index,
            leaf_entry(address, EptMemoryType::WriteBack, EptMemoryType::WriteBack),
        );
        ept
    }

    #[test]
    fn translations_intersect_permissions_at_every_level_and_leaf_size() {
        for level in 0..3 {
            let ept = empty_identity_page(0x3000);
            let root = ept.root;
            let pdpt = table_from_entry(read_entry(root, 0)).unwrap();
            let pd = table_from_entry(read_entry(pdpt, 0)).unwrap();
            let restricted = [root, pdpt, pd][level];
            write_entry(
                restricted,
                0,
                (read_entry(restricted, 0) & !EPT_PERMISSIONS) | EPT_READ,
            );
            assert_eq!(ept.translate(0x3000).unwrap().permissions, EPT_READ);
        }
        let mut ept = one_gb_leaf(EPT_PERMISSIONS | (6 << 3));
        let root_entry = read_entry(ept.root, 0);
        write_entry(ept.root, 0, (root_entry & !EPT_PERMISSIONS) | EPT_READ);
        assert_eq!(ept.translate(0x1_0000_3000).unwrap().permissions, EPT_READ);
        ept.ensure_4k_leaf(0x1_0000_3000).unwrap();
        assert_eq!(ept.translate(0x1_0020_3000).unwrap().permissions, EPT_READ);
        let pdpt = table_from_entry(root_entry).unwrap();
        write_entry(
            pdpt,
            4,
            (read_entry(pdpt, 4) & !EPT_PERMISSIONS) | EPT_EXECUTE,
        );
        assert_eq!(
            ept.translate(0x1_0000_3000),
            Err(EptError::InvalidPageTable)
        );
    }

    #[test]
    fn pci_ranges_reject_empty_and_reversed_intervals_before_mutating_tables() {
        let mut ept = empty(EPT_GUEST_PHYSICAL_LIMIT);
        for (start, end) in [(0x1001, 0x1001), (0x1002, 0x1001), (0x3000, 0x1000)] {
            assert_eq!(
                ept.map_pci_bars(&[(start, end)]),
                Err(EptError::InvalidMemoryMap)
            );
            assert_eq!(ept.pages.len(), 1);
            assert_eq!(ept.protection_table_pool().2, 0);
        }
    }

    #[test]
    fn pci_ranges_split_gigabyte_leaves_and_change_only_overlapping_pages() {
        let attributes = EPT_READ | EPT_EXECUTE | (6 << 3) | (6 << 52) | (1 << 6);
        let mut ept = one_gb_leaf(attributes);
        let address = 0x1_0040_5000;
        ept.map_pci_bars(&[(address + 1, address + 4097)]).unwrap();
        for offset in [0, 4096] {
            let value = ept.leaf_entry_value(address + offset).unwrap();
            assert_eq!(value & EPT_ADDRESS_MASK, address + offset + (1 << 32));
            assert_eq!(value & !EPT_ADDRESS_MASK, EPT_READ | EPT_EXECUTE | (1 << 6));
            assert_eq!(ept.memory_type_at_gpa(address + offset), Some(0));
        }
        for neighbor in [address - 4096, address + 8192] {
            assert_eq!(
                ept.leaf_entry_value(neighbor).unwrap() & !EPT_ADDRESS_MASK,
                attributes
            );
            assert_eq!(ept.memory_type_at_gpa(neighbor), Some(6));
        }
        assert_eq!(ept.memory_type_at_gpa(EPT_GUEST_PHYSICAL_LIMIT), None);
    }

    #[test]
    fn protection_range_failures_do_not_partially_change_guest_access() {
        let mut ept = empty_identity_page(0x3000);
        ept.mapped_end = 0x4000;
        for conceal in [false, true] {
            for (start, count) in [(0x3000, 2), (0, usize::MAX), (u64::MAX - 4095, 2)] {
                let result = if conceal {
                    ept.conceal_guest_access(start, count, 0)
                } else {
                    ept.deny_guest_access(start, count)
                };
                assert!(result.is_err());
                assert_eq!(ept.translate(0x3000).unwrap().permissions, EPT_PERMISSIONS);
            }
        }
        let used = ept.protection_table_pool().2;
        assert!(ept.ensure_4k_leaf(EPT_GUEST_PHYSICAL_LIMIT).is_err());
        assert_eq!(ept.protection_table_pool().2, used);
    }

    #[test]
    fn exhausted_protection_pools_preserve_access_for_the_entire_range() {
        let address = EPT_2MB_PAGE_SIZE - PAGE_SIZE as u64;
        for conceal in [false, true] {
            let mut ept = empty_identity_page(address);
            ept.protection_pool.used_pages = EPT_PROTECTION_TABLE_PAGES;
            let result = if conceal {
                ept.conceal_guest_access(address, 2, 0)
            } else {
                ept.deny_guest_access(address, 2)
            };
            assert_eq!(result, Err(EptError::ProtectionTableCapacityExceeded));
            let translated = ept.translate(address).unwrap();
            assert_eq!(translated.permissions, EPT_PERMISSIONS);
            assert_eq!(translated.physical_address, address);
        }
    }

    #[test]
    fn scaled_protection_pool_handles_fragmented_allocations_for_64_cpus() {
        let mut ept = IdentityEpt::build(
            vec![MemoryDescriptor {
                phys_start: 0,
                page_count: 1024,
                ty: MemoryType::CONVENTIONAL,
                att: MemoryAttribute::WRITE_BACK,
            }],
            64,
        )
        .unwrap();
        ept.map_high_address_gaps().unwrap();
        let regions: Vec<_> = (0..64 * 16)
            .map(|index| (0x4_0000_0000 + index * EPT_2MB_PAGE_SIZE, 1))
            .collect();
        ept.conceal_guest_access_to_regions(&regions, 0x1000)
            .unwrap();
        let (_, capacity, used) = ept.protection_table_pool();
        assert_eq!(
            capacity,
            EPT_PROTECTION_TABLE_PAGES + 64 * EPT_PROTECTION_TABLE_PAGES_PER_CPU
        );
        assert!(used >= regions.len());
    }

    #[test]
    fn invalid_region_batches_preserve_preceding_mappings() {
        let address = 0x3000;
        let mut ept = empty_identity_page(address);
        assert_eq!(
            ept.conceal_guest_access_to_regions(&[(address, 1), (0x4001, 1)], 0),
            Err(EptError::InvalidProtectionAddress(0x4001))
        );
        let translated = ept.translate(address).unwrap();
        assert_eq!(translated.permissions, EPT_PERMISSIONS);
        assert_eq!(translated.physical_address, address);
    }

    #[test]
    fn composition_preserves_parent_permissions_and_checks_destination_bounds() {
        let address = 0x3000;
        let ept12 = empty_identity_page(address);
        let ept01 = empty_identity_page(address);
        write_entry(
            ept12.root,
            0,
            (read_entry(ept12.root, 0) & !EPT_PERMISSIONS) | EPT_READ,
        );
        let mut shadow = empty(0x4000);
        assert_eq!(
            shadow
                .compose_page(&ept12, &ept01, address)
                .unwrap()
                .permissions,
            EPT_READ
        );
        assert_eq!(shadow.translate(address).unwrap().permissions, EPT_READ);
        let mut undersized = empty(0x3000);
        assert_eq!(
            undersized.compose_page(&ept12, &ept01, address),
            Err(EptError::InvalidRemapAddress(address))
        );
        assert_eq!(undersized.protection_table_pool().2, 0);
    }

    #[test]
    fn composition_respects_both_cache_types_and_l1_ignore_pat() {
        let address = 0x3000;
        for l1_type in [0, 1, 4, 5, 6] {
            for host_type in [0, 1, 4, 5, 6] {
                for ignore_pat in [0, 1 << 6] {
                    let mut ept12 = empty_identity_page(address);
                    let mut ept01 = empty_identity_page(address);
                    for (ept, memory_type, pat) in [
                        (&mut ept12, l1_type, ignore_pat),
                        (&mut ept01, host_type, 0),
                    ] {
                        let (table, index) = ept.ensure_4k_leaf(address).unwrap();
                        write_entry(
                            table,
                            index,
                            address | EPT_PERMISSIONS | (memory_type << 3) | pat,
                        );
                    }
                    let expected = if l1_type == host_type || host_type == 6 {
                        l1_type
                    } else if l1_type == 6 {
                        host_type
                    } else {
                        0
                    };
                    let mut shadow = empty(EPT_GUEST_PHYSICAL_LIMIT);
                    shadow.compose_page(&ept12, &ept01, address).unwrap();
                    let entry = shadow.leaf_entry_value(address).unwrap();
                    assert_eq!((entry >> 3) & 7, expected);
                    assert_eq!(entry & (1 << 6), ignore_pat);
                }
            }
        }
    }

    #[test]
    fn built_tables_and_high_gap_leaves_support_protection_and_cloning() {
        let mut ept = IdentityEpt::build(
            vec![MemoryDescriptor {
                phys_start: 0,
                page_count: 1024,
                ty: MemoryType::CONVENTIONAL,
                att: MemoryAttribute::WRITE_BACK,
            }],
            0,
        )
        .unwrap();
        assert_eq!(ept.map_high_address_gaps().unwrap(), EPT_512GB_PAGE_SIZE);
        ept.conceal_guest_access_to_regions(&[(0x4_0000_0000, 2)], 0x1000)
            .unwrap();
        assert_eq!(
            ept.translate(0x4_0000_1000).unwrap().physical_address,
            0x1000
        );
        let slot = ept.leaf_entry_physical_address(0x4_0000_1000).unwrap();
        assert_eq!(
            unsafe { (slot as *const u64).read() } & EPT_PERMISSIONS,
            EPT_READ
        );
        let clone = ept.clone_identity_tables().unwrap();
        assert_eq!(
            clone.translate(0x4_0000_1000).unwrap().permissions,
            EPT_READ
        );
        let mut table_protection = empty(EPT_GUEST_PHYSICAL_LIMIT);
        table_protection
            .conceal_guest_access_to_tables(0x1000)
            .unwrap();
        for (address, count) in table_protection.table_regions() {
            for page in 0..count {
                let translated = table_protection
                    .translate(address + (page * PAGE_SIZE) as u64)
                    .unwrap();
                assert_eq!(
                    (translated.physical_address, translated.permissions),
                    (0x1000, EPT_READ)
                );
            }
        }
    }
}
