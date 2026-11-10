use crate::protocol::memory::*;

/// Per-session hook metadata that interception consults for data-shadow pages.
/// Watch/context/event capture state was removed from the ABI.
#[repr(C)]
pub(crate) struct Observation {
    pub hook_flags: [u32; HOOK_MAX_PATCHES],
    pub data_pages: [u64; HOOK_MAX_PAGES],
    pub data_count: usize,
}

impl Observation {
    pub fn data_shadow(&self, gpa: u64) -> bool {
        self.data_pages[..self.data_count].contains(&(gpa & !4095))
    }
}
