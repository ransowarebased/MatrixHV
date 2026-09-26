#[derive(Debug, PartialEq)]
enum EptError {
    AddressOverflow,
    InvalidPageTable,
}

#[repr(align(4096))]
struct AlignedTable([u64; EPT_ENTRY_COUNT]);

#[derive(Clone, Copy)]
struct TablePage {
    physical_address: u64,
    entries: NonNull<u64>,
}

struct IdentityEpt {
    pages: Vec<Box<AlignedTable>>,
    root: TablePage,
    mapped_end: u64,
    large_pages_supported: bool,
}

mod cpuid {
    pub struct Leaf {
        pub eax: u32,
    }

    pub fn leaf(_selector: u32) -> Leaf {
        Leaf { eax: 39 }
    }
}

mod msr {
    use std::cell::Cell;

    pub const IA32_VMX_EPT_VPID_CAP: u32 = 0x48c;

    thread_local! {
        static CAPABILITIES: Cell<u64> = const { Cell::new(1 << 17) };
    }

    pub unsafe fn read(_register: u32) -> u64 {
        CAPABILITIES.with(Cell::get)
    }

    pub fn set_capabilities(capabilities: u64) {
        CAPABILITIES.with(|value| value.set(capabilities));
    }
}

fn allocate_table(pages: &mut Vec<Box<AlignedTable>>) -> Result<TablePage, EptError> {
    let mut table = Box::new(AlignedTable([0; EPT_ENTRY_COUNT]));
    let entries = NonNull::new(table.0.as_mut_ptr()).unwrap();
    let physical_address = entries.as_ptr() as u64;
    pages.push(table);
    Ok(TablePage {
        physical_address,
        entries,
    })
}

#[test]
fn relocated_pci_bar_is_uc_without_replacing_ram_or_firmware_bar() {
    assert_eq!(
        [
            EptMemoryType::WriteCombining as u64,
            EptMemoryType::WriteThrough as u64,
            EptMemoryType::WriteProtected as u64,
        ],
        [1, 4, 5]
    );
    let mut pages = Vec::new();
    let root = allocate_table(&mut pages).unwrap();
    let pdpt = allocate_table(&mut pages).unwrap();
    write_entry(root, 0, table_entry(pdpt.physical_address));

    let ram_pd = allocate_table(&mut pages).unwrap();
    let ram_leaf = leaf_entry(
        EPT_MINIMUM_MAPPED_END,
        EptMemoryType::WriteBack,
        EptMemoryType::WriteBack,
    ) | EPT_LARGE_PAGE;
    write_entry(pdpt, 4, table_entry(ram_pd.physical_address));
    write_entry(ram_pd, 0, ram_leaf);

    let pci_pd = allocate_table(&mut pages).unwrap();
    let firmware_bar_address = 0x4000_000000;
    let pci_leaf = leaf_entry(
        firmware_bar_address,
        EptMemoryType::Uncacheable,
        EptMemoryType::Uncacheable,
    ) | EPT_LARGE_PAGE;
    write_entry(pdpt, 256, table_entry(pci_pd.physical_address));
    write_entry(pci_pd, 0, pci_leaf);

    let mut ept = IdentityEpt {
        pages,
        root,
        mapped_end: 0x4000_11c000,
        large_pages_supported: true,
    };
    assert_eq!(ept.map_high_address_gaps().unwrap(), EPT_512GB_PAGE_SIZE);
    let pdpt = table_from_entry(read_entry(ept.root, 0)).unwrap();
    assert_eq!(read_entry(pdpt, 3), 0);
    assert_eq!(read_entry(ram_pd, 0), ram_leaf);
    assert_eq!(read_entry(pci_pd, 0), pci_leaf);
    assert_eq!(
        read_entry(pci_pd, 1) & (EPT_PERMISSIONS | EPT_LARGE_PAGE),
        EPT_PERMISSIONS | EPT_LARGE_PAGE
    );

    let relocated_audio_bar = 0x7fff_efcd08;
    let pdpt_index = (relocated_audio_bar / EPT_1GB_PAGE_SIZE) as usize;
    let entry = read_entry(pdpt, pdpt_index);
    assert_eq!(pdpt_index, 511);
    assert_eq!(
        entry & (EPT_PERMISSIONS | EPT_LARGE_PAGE),
        EPT_PERMISSIONS | EPT_LARGE_PAGE
    );
    assert_eq!(
        (entry >> EPT_MEMORY_TYPE_SHIFT) & 7,
        EptMemoryType::Uncacheable as u64
    );
    assert_eq!(
        entry & EPT_ADDRESS_MASK & !(EPT_1GB_PAGE_SIZE - 1),
        511 * EPT_1GB_PAGE_SIZE
    );
    assert_eq!(ept.mapped_end, EPT_512GB_PAGE_SIZE);
}

#[test]
fn two_megabyte_fallback_covers_high_pci_space() {
    msr::set_capabilities(0);
    let mut pages = Vec::new();
    let root = allocate_table(&mut pages).unwrap();
    let mut ept = IdentityEpt {
        pages,
        root,
        mapped_end: EPT_MINIMUM_MAPPED_END,
        large_pages_supported: true,
    };
    assert_eq!(ept.map_high_address_gaps().unwrap(), EPT_512GB_PAGE_SIZE);
    let pdpt = table_from_entry(read_entry(root, 0)).unwrap();
    let pd = table_from_entry(read_entry(pdpt, 511)).unwrap();
    let entry = read_entry(pd, 511);
    assert_eq!(
        entry & (EPT_PERMISSIONS | EPT_LARGE_PAGE),
        EPT_PERMISSIONS | EPT_LARGE_PAGE
    );
    assert_eq!(
        (entry >> EPT_MEMORY_TYPE_SHIFT) & 7,
        EptMemoryType::Uncacheable as u64
    );
    assert_eq!(
        entry & EPT_ADDRESS_MASK & !(EPT_2MB_PAGE_SIZE - 1),
        EPT_512GB_PAGE_SIZE - EPT_2MB_PAGE_SIZE
    );
}
