use super::vt_entry::{self, VmlaunchError, VmlaunchReport};
use super::vt_vmcs::{self, VmcsError, VmcsReport};
use super::vt_vmxon::{self, VmxonError, VmxonReport};

pub fn probe_vmxon() -> Result<VmxonReport, VmxonError> {
    vt_vmxon::probe_vmxon()
}

pub fn probe_vmcs() -> Result<VmcsReport, VmcsError> {
    vt_vmcs::probe_vmcs()
}

pub fn probe_vmlaunch() -> Result<VmlaunchReport, VmlaunchError> {
    vt_entry::probe_vmlaunch()
}
