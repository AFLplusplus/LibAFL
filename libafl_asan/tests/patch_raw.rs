#![cfg_attr(target_arch = "arm", feature(arm_target_feature))]

#[cfg(test)]
#[cfg(feature = "libc")]
#[cfg(not(target_arch = "arm"))]
mod tests {
    use libafl_asan::{
        GuestAddr,
        mmap::{Mmap, MmapProt, libc::LibcMmap},
        patch::{Patch, raw::RawPatch},
        symbols::dlsym::{DlSymSymbols, LookupTypeNext},
    };
    use libc::{_SC_PAGESIZE, sysconf};
    use log::info;

    type HostMmap = LibcMmap<DlSymSymbols<LookupTypeNext>>;

    #[unsafe(no_mangle)]
    extern "C" fn test1(a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(a3, 3);
        assert_eq!(a4, 4);
        assert_eq!(a5, 5);
        assert_eq!(a6, 6);
        0xdeadface
    }

    #[unsafe(no_mangle)]
    extern "C" fn test2(a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(a3, 3);
        assert_eq!(a4, 4);
        assert_eq!(a5, 5);
        assert_eq!(a6, 6);
        0xd00df00d
    }

    #[test]
    fn test_patch() {
        let ret1 = test1(1, 2, 3, 4, 5, 6);
        assert_eq!(ret1, 0xdeadface);

        let ret2 = test2(1, 2, 3, 4, 5, 6);
        assert_eq!(ret2, 0xd00df00d);

        let ptest1 = test1 as *const () as GuestAddr;
        let ptest2 = test2 as *const () as GuestAddr;
        info!("pfn: {ptest1:#x}");
        let aligned_pfn = ptest1 & !0xfff;
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        info!("aligned_pfn: {aligned_pfn:#x}");
        info!("page_size: {page_size:#x}");
        HostMmap::protect(
            aligned_pfn,
            page_size * 2,
            MmapProt::READ | MmapProt::WRITE | MmapProt::EXEC,
        )
        .unwrap();

        RawPatch::patch(ptest1, ptest2).unwrap();
        let ret = test1(1, 2, 3, 4, 5, 6);
        assert_eq!(ret, 0xd00df00d);
        HostMmap::protect(aligned_pfn, page_size * 2, MmapProt::READ | MmapProt::EXEC).unwrap();
    }
}

#[cfg(test)]
#[cfg(feature = "libc")]
#[cfg(target_arch = "arm")]
mod tests {
    use libafl_asan::{
        GuestAddr,
        mmap::{Mmap, MmapProt, libc::LibcMmap},
        patch::{Patch, raw::RawPatch},
        symbols::dlsym::{DlSymSymbols, LookupTypeNext},
    };
    use libc::{_SC_PAGESIZE, sysconf};
    use log::info;

    type HostMmap = LibcMmap<DlSymSymbols<LookupTypeNext>>;

    macro_rules! define_test_function {
        ($fn_name:ident, $ret_val:expr) => {
            define_test_function!([], $fn_name, $ret_val);
        };

        ($attr:meta, $fn_name:ident, $ret_val:expr) => {
            define_test_function!([$attr], $fn_name, $ret_val);
        };

        ([$($attr:meta)*], $fn_name:ident, $ret_val:expr) => {
            #[unsafe(no_mangle)]
            $(#[$attr])*
            extern "C" fn $fn_name(
                a1: usize,
                a2: usize,
                a3: usize,
                a4: usize,
                a5: usize,
                a6: usize,
            ) -> usize {
                assert_eq!(a1, 1);
                assert_eq!(a2, 2);
                assert_eq!(a3, 3);
                assert_eq!(a4, 4);
                assert_eq!(a5, 5);
                assert_eq!(a6, 6);
                return $ret_val;
            }
        };
    }

    macro_rules! define_test {
        (
            $fn_name:ident,
            $test_fn1:ident,
            $test_fn2:ident,
            $test_ret_val1:expr,
            $test_ret_val2:expr
        ) => {
            #[test]
            fn $fn_name() {
                #[allow(unused_unsafe)]
                unsafe {
                    let ret1 = $test_fn1(1, 2, 3, 4, 5, 6);
                    assert_eq!(ret1, $test_ret_val1);

                    let ret2 = $test_fn2(1, 2, 3, 4, 5, 6);
                    assert_eq!(ret2, $test_ret_val2);

                    let ptest1 = $test_fn1 as *const () as GuestAddr;
                    let ptest2 = $test_fn2 as *const () as GuestAddr;
                    info!("pfn: {:#x}", ptest1);
                    let aligned_pfn = ptest1 & !0xfff;
                    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
                    info!("aligned_pfn: {:#x}", aligned_pfn);
                    info!("page_size: {:#x}", page_size);
                    HostMmap::protect(
                        aligned_pfn,
                        page_size * 2,
                        MmapProt::READ | MmapProt::WRITE | MmapProt::EXEC,
                    )
                    .unwrap();

                    RawPatch::patch(ptest1, ptest2).unwrap();
                    let ret = $test_fn1(1, 2, 3, 4, 5, 6);
                    assert_eq!(ret, $test_ret_val2);
                    HostMmap::protect(aligned_pfn, page_size * 2, MmapProt::READ | MmapProt::EXEC)
                        .unwrap();
                }
            }
        };
    }

    define_test_function!(arm_patch_target, 0xdeadface);
    define_test_function!(patched_arm_to_arm, 0xd00df00d);
    define_test_function!(patched_arm_to_thumb, 0xfeeddeaf);
    define_test_function!(
        target_feature(enable = "thumb-mode"),
        thumb_patch_target,
        0xcafebabe
    );
    define_test_function!(
        target_feature(enable = "thumb-mode"),
        patched_thumb_to_thumb,
        0xbeeffade
    );
    define_test_function!(
        target_feature(enable = "thumb-mode"),
        patched_thumb_to_arm,
        0xdeedcede
    );

    define_test!(
        test_patch_arm_to_arm,
        patched_arm_to_arm,
        arm_patch_target,
        0xd00df00d,
        0xdeadface
    );
    define_test!(
        test_patch_arm_to_thumb,
        patched_arm_to_thumb,
        thumb_patch_target,
        0xfeeddeaf,
        0xcafebabe
    );
    define_test!(
        test_patch_thumb_to_arm,
        patched_thumb_to_arm,
        arm_patch_target,
        0xdeedcede,
        0xdeadface
    );
    define_test!(
        test_patch_thumb_to_thumb,
        patched_thumb_to_thumb,
        thumb_patch_target,
        0xbeeffade,
        0xcafebabe
    );
}
