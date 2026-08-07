use ptcov::{PtCpu, PtCpuVendor};
use raw_cpuid::CpuId;

pub fn current_cpu() -> Option<PtCpu> {
    let cpuid = CpuId::new();
    cpuid.get_feature_info().map(|fi| {
        PtCpu::new(
            PtCpuVendor::Intel,
            fi.family_id().into(),
            fi.model_id(),
            fi.stepping_id(),
        )
    })
}
