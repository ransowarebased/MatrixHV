#[derive(Debug)]
pub struct HypervisorStatus {
    pub hypervisor_present: bool,
    pub hypervisor_vendor: String,
    pub matrixhv_present: bool,
    pub matrixhv_protocol: u32,
}

const HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;
const HYPERVISOR_VENDOR_LEAF: u32 = 0x4000_0000;
const MATRIXHV_STATUS_LEAF: u32 = 0x4d48_5652;
const MATRIXHV_SIGNATURE_EAX: u32 = 0x4d48_5631;
const MATRIXHV_SIGNATURE_EBX: u32 = u32::from_le_bytes(*b"MATR");
const MATRIXHV_SIGNATURE_ECX: u32 = u32::from_le_bytes(*b"IXHV");

pub fn query() -> HypervisorStatus {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid_count;

        let feature = __cpuid_count(1, 0);
        let hypervisor_present = feature.ecx & HYPERVISOR_PRESENT_BIT != 0;
        let vendor = if hypervisor_present {
            let result = __cpuid_count(HYPERVISOR_VENDOR_LEAF, 0);
            let mut bytes = Vec::with_capacity(12);
            bytes.extend_from_slice(&result.ebx.to_le_bytes());
            bytes.extend_from_slice(&result.ecx.to_le_bytes());
            bytes.extend_from_slice(&result.edx.to_le_bytes());
            String::from_utf8_lossy(&bytes)
                .trim_end_matches('\0')
                .to_string()
        } else {
            "none".to_string()
        };
        let matrixhv = __cpuid_count(MATRIXHV_STATUS_LEAF, 0);
        let matrixhv_present = matrixhv.eax == MATRIXHV_SIGNATURE_EAX
            && matrixhv.ebx == MATRIXHV_SIGNATURE_EBX
            && matrixhv.ecx == MATRIXHV_SIGNATURE_ECX;
        HypervisorStatus {
            hypervisor_present,
            hypervisor_vendor: vendor,
            matrixhv_present,
            matrixhv_protocol: if matrixhv_present { matrixhv.edx } else { 0 },
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    HypervisorStatus {
        hypervisor_present: false,
        hypervisor_vendor: "unsupported-architecture".to_string(),
        matrixhv_present: false,
        matrixhv_protocol: 0,
    }
}
