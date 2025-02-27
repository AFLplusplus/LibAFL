//! Intel Processor Trace (PT) low level code
//!
//! This crate interacts with the linux kernel (specifically with perf) and therefore it only works
//! on linux hosts

// Just in case this crate will have real `no_std` support in the future
#![no_std]
#![cfg(target_arch = "x86_64")]
#![cfg(feature = "std")]
#![cfg(feature = "libipt")]

#[macro_use]
extern crate std;

extern crate alloc;

use alloc::{borrow::ToOwned, string::String, vec::Vec};
#[cfg(target_os = "linux")]
use std::fs;

use raw_cpuid::CpuId;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

/// Size of a memory page
pub const PAGE_SIZE: usize = 4096;

/// Check if Intel PT is available on the current system.
///
/// Returns `Ok(())` if Intel PT is available and has the features used by `LibAFL`, otherwise
/// returns an `Err` containing a description of the reasons.
///
/// If you use this with QEMU check out [`Self::availability_in_qemu()`] instead.
///
/// Due to the numerous factors that can affect `IntelPT` availability, this function was
/// developed on a best-effort basis.
/// The outcome of these checks does not fully guarantee whether `IntelPT` will function or not.
pub fn availability() -> Result<(), String> {
    let mut reasons = Vec::new();

    let cpuid = CpuId::new();
    if let Some(vendor) = cpuid.get_vendor_info() {
        if vendor.as_str() != "GenuineIntel" && vendor.as_str() != "GenuineIotel" {
            reasons.push("Only Intel CPUs are supported".to_owned());
        }
    } else {
        reasons.push("Failed to read CPU vendor".to_owned());
    }

    if let Some(ef) = cpuid.get_extended_feature_info() {
        if !ef.has_processor_trace() {
            reasons.push("Intel PT is not supported by the CPU".to_owned());
        }
    } else {
        reasons.push("Failed to read CPU Extended Features".to_owned());
    }

    #[cfg(target_os = "linux")]
    if let Err(r) = availability_in_linux() {
        reasons.push(r);
    }
    #[cfg(not(target_os = "linux"))]
    reasons.push("Only linux hosts are supported at the moment".to_owned());

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons.join("; "))
    }
}

/// Check if Intel PT is available on the current system and can be used in combination with
/// QEMU.
///
/// If you don't use this with QEMU check out [`IntelPT::availability()`] instead.
pub fn availability_in_qemu_kvm() -> Result<(), String> {
    let mut reasons = match availability() {
        Err(s) => vec![s],
        Ok(()) => Vec::new(),
    };

    #[cfg(target_os = "linux")]
    {
        let kvm_pt_mode_path = "/sys/module/kvm_intel/parameters/pt_mode";
        // Ignore the case when the file does not exist since it has been removed.
        // KVM default is `System` mode
        // https://lore.kernel.org/all/20241101185031.1799556-1-seanjc@google.com/t/#u
        if let Ok(s) = fs::read_to_string(kvm_pt_mode_path) {
            match s.trim().parse::<i32>().map(TryInto::try_into) {
                Ok(Ok(KvmPTMode::System)) => (),
                Ok(Ok(KvmPTMode::HostGuest)) => reasons.push(format!(
                    "KVM Intel PT mode must be set to {:?} `{}` to be used with libafl_qemu",
                    KvmPTMode::System,
                    KvmPTMode::System as i32
                )),
                _ => reasons.push(format!(
                    "Failed to parse KVM Intel PT mode in {kvm_pt_mode_path}"
                )),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    reasons.push("Only linux hosts are supported at the moment".to_owned());

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons.join("; "))
    }
}

#[cfg(test)]
mod test {
    use static_assertions::assert_eq_size;

    use super::*;

    // Only 64-bit systems are supported, ensure we can use usize and u64 interchangeably
    assert_eq_size!(usize, u64);

    /// Quick way to check if your machine is compatible with Intel PT's features used by libafl
    ///
    /// Simply run `cargo test intel_pt_check_availability -- --show-output`
    #[test]
    fn intel_pt_check_availability() {
        print!("Intel PT availability:\t\t\t");
        match availability() {
            Ok(()) => println!("✔"),
            Err(e) => println!("❌\tReasons: {e}"),
        }

        print!("Intel PT availability in QEMU/KVM:\t");
        match availability_in_qemu_kvm() {
            Ok(()) => println!("✔"),
            Err(e) => println!("❌\tReasons: {e}"),
        }
    }
}
