use core::fmt::Debug;

pub trait ShadowLayout: Debug + Send {
    const LOW_MEM_OFFSET: usize;
    const LOW_MEM_SIZE: usize;

    const LOW_SHADOW_OFFSET: usize;
    const LOW_SHADOW_SIZE: usize;

    const HIGH_SHADOW_OFFSET: usize;
    const HIGH_SHADOW_SIZE: usize;

    const HIGH_MEM_OFFSET: usize;
    const HIGH_MEM_SIZE: usize;

    const SHADOW_OFFSET: usize;
    const ALLOC_ALIGN_POW: usize;
    const ALLOC_ALIGN_SIZE: usize;
}

#[cfg(not(feature = "dynamic_layout"))]
pub use default::DefaultShadowLayout;
#[cfg(feature = "dynamic_layout")]
pub use generated::DefaultShadowLayout;

#[cfg(not(feature = "dynamic_layout"))]
mod default {
    use super::ShadowLayout;
    use crate::GuestAddr;

    #[derive(Debug)]
    pub struct DefaultShadowLayout;

    #[cfg(target_pointer_width = "32")]
    impl ShadowLayout for DefaultShadowLayout {
        // https://github.com/llvm/llvm-project/blob/1deee91bf52ca15e47b59a2929e5e5a323f4864c/compiler-rt/lib/asan/asan_mapping.h#L45
        // Default Linux/i386 mapping on x86_64 machine:
        // || `[0x40000000, 0xffffffff]` || HighMem    ||
        // || `[0x28000000, 0x3fffffff]` || HighShadow ||
        // || `[0x24000000, 0x27ffffff]` || ShadowGap  ||
        // || `[0x20000000, 0x23ffffff]` || LowShadow  ||
        // || `[0x00000000, 0x1fffffff]` || LowMem     ||
        const SHADOW_OFFSET: usize = 0x20000000;
        const LOW_MEM_OFFSET: GuestAddr = 0x0;
        const LOW_MEM_SIZE: usize = 0x20000000;
        const LOW_SHADOW_OFFSET: GuestAddr = 0x20000000;
        const LOW_SHADOW_SIZE: usize = 0x4000000;
        const HIGH_SHADOW_OFFSET: GuestAddr = 0x28000000;
        const HIGH_SHADOW_SIZE: usize = 0x18000000;
        const HIGH_MEM_OFFSET: GuestAddr = 0x40000000;
        const HIGH_MEM_SIZE: usize = 0xc0000000;

        const ALLOC_ALIGN_POW: usize = 3;
        const ALLOC_ALIGN_SIZE: usize = 1 << Self::ALLOC_ALIGN_POW;
    }

    #[cfg(target_pointer_width = "64")]
    impl ShadowLayout for DefaultShadowLayout {
        // https://github.com/llvm/llvm-project/blob/1deee91bf52ca15e47b59a2929e5e5a323f4864c/compiler-rt/lib/asan/asan_mapping.h#L103
        // Default Linux/AArch64 (48-bit VMA) mapping:
        // || `[0x201000000000, 0xffffffffffff]` || HighMem    || 229312GB
        // || `[0x041200000000, 0x200fffffffff]` || HighShadow || 28664GB
        // || `[0x001200000000, 0x0411ffffffff]` || ShadowGap  || 4096GB
        // || `[0x001000000000, 0x0011ffffffff]` || LowShadow  || 8GB
        // || `[0x000000000000, 0x000fffffffff]` || LowMem     || 64GB
        const SHADOW_OFFSET: usize = 0x001000000000;
        const LOW_MEM_OFFSET: GuestAddr = 0x0;
        const LOW_MEM_SIZE: usize = 0x1000000000;
        const LOW_SHADOW_OFFSET: GuestAddr = 0x001000000000;
        const LOW_SHADOW_SIZE: usize = 0x200000000;
        const HIGH_SHADOW_OFFSET: GuestAddr = 0x041200000000;
        const HIGH_SHADOW_SIZE: usize = 0x1bfe00000000;
        const HIGH_MEM_OFFSET: GuestAddr = 0x201000000000;
        const HIGH_MEM_SIZE: usize = 0xdff000000000;

        const ALLOC_ALIGN_POW: usize = 3;
        const ALLOC_ALIGN_SIZE: usize = 1 << Self::ALLOC_ALIGN_POW;
    }
}

#[cfg(feature = "dynamic_layout")]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/gen_layout.rs"));
}
