use super::vt_vmcs::{self, VmcsError, VmcsReport};
use super::vt_vmxon::{self, VmxonError, VmxonReport};

pub fn probe_vmxon() -> Result<VmxonReport, VmxonError> {
    vt_vmxon::probe_vmxon()
}

pub fn probe_vmcs() -> Result<VmcsReport, VmcsError> {
    vt_vmcs::probe_vmcs()
}
