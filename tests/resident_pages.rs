use boot::AllocateType;
use core::ptr::NonNull;

const PAGE_SIZE: usize = 4096;
const RESIDENT_MEMORY_TYPE: MemoryType = MemoryType;

pub struct MemoryType;

#[derive(Debug, PartialEq)]
pub struct Status(u8);

impl Status {
    const INVALID_PARAMETER: Self = Self(1);
    const UNSUPPORTED: Self = Self(2);

    fn status(self) -> Self {
        self
    }
}

mod hv_core {
    pub mod vt_resident {
        pub fn boot_services_exited() -> bool {
            false
        }
    }
}

mod boot {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[repr(C, align(4096))]
    struct Page([u8; PAGE_SIZE]);

    thread_local! {
        static PAGES: RefCell<HashMap<usize, Vec<Page>>> = RefCell::new(HashMap::new());
    }

    pub enum AllocateType {
        AnyPages,
        MaxAddress(u64),
    }

    pub fn allocate_pages(
        kind: AllocateType,
        _memory_type: MemoryType,
        count: usize,
    ) -> Result<NonNull<u8>, Status> {
        if let AllocateType::MaxAddress(limit) = kind {
            assert_eq!(limit, u64::MAX);
        }
        let mut pages: Vec<Page> = (0..count).map(|_| Page([0xa5; PAGE_SIZE])).collect();
        let pointer = NonNull::new(pages.as_mut_ptr().cast()).unwrap();
        PAGES.with(|allocations| {
            allocations
                .borrow_mut()
                .insert(pointer.as_ptr() as usize, pages);
        });
        Ok(pointer)
    }

    pub unsafe fn free_pages(pointer: NonNull<u8>, count: usize) -> Result<(), Status> {
        PAGES.with(|allocations| {
            let pages = allocations
                .borrow_mut()
                .remove(&(pointer.as_ptr() as usize))
                .unwrap();
            assert_eq!(pages.len(), count);
        });
        Ok(())
    }

    pub fn count() -> usize {
        PAGES.with(|allocations| allocations.borrow().len())
    }

    pub fn byte(address: u64, offset: usize) -> u8 {
        PAGES.with(|allocations| {
            allocations.borrow()[&(address as usize)][offset / PAGE_SIZE].0[offset % PAGE_SIZE]
        })
    }
}

#[test]
fn initializer_borrows_zeroed_pages_and_keeps_writes_until_drop() {
    let pages = ResidentPages::allocate_initialized(2, AddressConstraint::Max(u64::MAX), |bytes| {
        assert_eq!(bytes, &[0; 2 * PAGE_SIZE]);
        bytes[0] = 0x12;
        bytes[2 * PAGE_SIZE - 1] = 0x34;
    })
    .unwrap();
    assert_eq!(pages.pages(), 2);
    assert_eq!(boot::count(), 1);
    assert_eq!(boot::byte(pages.physical_address(), 0), 0x12);
    assert_eq!(
        boot::byte(pages.physical_address(), 2 * PAGE_SIZE - 1),
        0x34
    );
    drop(pages);
    assert_eq!(boot::count(), 0);
}

#[test]
fn invalid_sizes_are_rejected_before_allocation_or_initialization() {
    for pages in [
        0,
        usize::MAX,
        usize::MAX / PAGE_SIZE + 1,
        isize::MAX as usize / PAGE_SIZE + 1,
    ] {
        let result = ResidentPages::allocate_initialized(pages, AddressConstraint::Any, |_| {
            panic!("invalid allocation reached its initializer");
        });
        assert_eq!(result.err(), Some(Status::INVALID_PARAMETER));
        assert_eq!(boot::count(), 0);
    }
}

#[test]
fn initializer_panic_releases_the_allocation() {
    assert!(
        std::panic::catch_unwind(|| {
            let _ = ResidentPages::allocate_initialized(1, AddressConstraint::Any, |_| {
                panic!("initializer failed");
            });
        })
        .is_err()
    );
    assert_eq!(boot::count(), 0);
}
