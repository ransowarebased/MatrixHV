fn descriptor(start: u64, length: u64, resource_type: u8) -> [u8; PCI_BAR_DESCRIPTOR_SIZE] {
    let mut bytes = [0_u8; PCI_BAR_DESCRIPTOR_SIZE];
    bytes[0] = 0x8a;
    bytes[1..3].copy_from_slice(&0x2b_u16.to_le_bytes());
    bytes[3] = resource_type;
    bytes[14..22].copy_from_slice(&start.to_le_bytes());
    bytes[38..46].copy_from_slice(&length.to_le_bytes());
    bytes
}

#[test]
fn high_usb_controller_bar_covers_observed_fault_address() {
    let bytes = descriptor(0x4000_100000, 0x10000, 0);
    let range = read_pci_bar_range(bytes.as_ptr()).unwrap().unwrap();
    assert_eq!(range, (0x4000_100000, 0x4000_110000));
    assert!(range.0 <= 0x4000_100084 && 0x4000_100084 < range.1);
}

#[test]
fn ignores_io_and_unassigned_bars() {
    let io = descriptor(0x4000_100000, 0x10000, 1);
    assert_eq!(read_pci_bar_range(io.as_ptr()), Ok(None));
    let unassigned = descriptor(0x4000_100000, 0, 0);
    assert_eq!(read_pci_bar_range(unassigned.as_ptr()), Ok(None));
}

#[test]
fn rejects_out_of_range_physical_addresses() {
    let overflow = descriptor(u64::MAX - 15, 32, 0);
    assert_eq!(
        read_pci_bar_range(overflow.as_ptr()),
        Err(EptError::AddressOverflow)
    );
    let too_wide = descriptor(EPT_GUEST_PHYSICAL_LIMIT - 0x1000, 0x2000, 0);
    assert_eq!(
        read_pci_bar_range(too_wide.as_ptr()),
        Err(EptError::GuestPhysicalAddressTooWide(
            EPT_GUEST_PHYSICAL_LIMIT + 0x1000
        ))
    );
}
