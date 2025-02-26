#[cfg(test)]
#[cfg(feature = "libc")]
mod tests {
    use asan::{
        GuestAddr,
        mmap::{Mmap, MmapProt, linux::LinuxMmap},
        patch::{Patch, raw::RawPatch},
    };
    use log::info;

    #[unsafe(no_mangle)]
    extern "C" fn test1(a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(a3, 3);
        assert_eq!(a4, 4);
        assert_eq!(a5, 5);
        assert_eq!(a6, 6);
        return 0xdeadface;
    }

    #[unsafe(no_mangle)]
    extern "C" fn test2(a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(a3, 3);
        assert_eq!(a4, 4);
        assert_eq!(a5, 5);
        assert_eq!(a6, 6);
        return 0xd00df00d;
    }

    #[test]
    fn test_patch() {
        let ret1 = test1(1, 2, 3, 4, 5, 6);
        assert_eq!(ret1, 0xdeadface);

        let ret2 = test2(1, 2, 3, 4, 5, 6);
        assert_eq!(ret2, 0xd00df00d);

        let ptest1 = test1 as *const () as GuestAddr;
        let ptest2 = test2 as *const () as GuestAddr;
        info!("pfn: {:#x}", ptest1);
        let aligned_pfn = ptest1 & !0xfff;
        info!("aligned_pfn: {:#x}", aligned_pfn);
        LinuxMmap::protect(
            aligned_pfn,
            0x4096,
            MmapProt::READ | MmapProt::WRITE | MmapProt::EXEC,
        )
        .unwrap();

        RawPatch::patch(ptest1, ptest2).unwrap();
        let ret = test1(1, 2, 3, 4, 5, 6);
        assert_eq!(ret, 0xd00df00d);
    }
}
