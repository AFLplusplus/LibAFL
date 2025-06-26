#[cfg(test)]
#[cfg(feature = "guest")]
mod tests {
    use std::sync::Mutex;

    use libafl_asan::{
        GuestAddr,
        mmap::libc::LibcMmap,
        shadow::{
            PoisonType, Shadow,
            guest::{DefaultShadowLayout, GuestShadow, GuestShadowError},
        },
        symbols::dlsym::{DlSymSymbols, LookupTypeNext},
    };
    use spin::Lazy;

    type GS = GuestShadow<LibcMmap<DlSymSymbols<LookupTypeNext>>, DefaultShadowLayout>;

    const ALIGN: usize = GS::ALLOC_ALIGN_SIZE;

    static INIT_ONCE: Lazy<Mutex<()>> = Lazy::new(|| {
        {
            env_logger::init();
        };
        Mutex::new(())
    });

    fn get_shadow() -> GS {
        drop(INIT_ONCE.lock().unwrap());
        GS::new().unwrap()
    }

    #[test]
    fn test_init() {
        get_shadow();
    }

    // [0x10007fff8000, 0x7fffffffffff] 	HighMem
    // [0x02008fff7000, 0x10007fff7fff] 	HighShadow
    // [0x00008fff7000, 0x02008fff6fff] 	ShadowGap
    // [0x00007fff8000, 0x00008fff6fff] 	LowShadow
    // [0x000000000000, 0x00007fff7fff] 	LowMem

    // [0x40000000, 0xffffffff] 	HighMem
    // [0x28000000, 0x3fffffff] 	HighShadow
    // [0x24000000, 0x27ffffff] 	ShadowGap
    // [0x20000000, 0x23ffffff] 	LowShadow
    // [0x00000000, 0x1fffffff] 	LowMem
    #[test]
    fn test_posion_bottom_of_low_mem() {
        let mut shadow = get_shadow();
        shadow
            .poison(GS::LOW_MEM_OFFSET, 0x8, PoisonType::AsanUser)
            .unwrap();
    }

    #[test]
    fn test_posion_top_of_low_mem() {
        let mut shadow = get_shadow();
        shadow
            .poison(GS::LOW_MEM_LIMIT - 0x7, 0x8, PoisonType::AsanUser)
            .unwrap();
    }

    #[test]
    fn test_posion_bottom_of_low_shadow() {
        let mut shadow = get_shadow();
        let result = shadow.poison(GS::LOW_SHADOW_OFFSET, 0x8, PoisonType::AsanUser);
        assert_eq!(
            result,
            Err(GuestShadowError::InvalidMemoryAddress(
                GS::LOW_SHADOW_OFFSET
            ))
        );
    }

    #[test]
    fn test_posion_top_of_low_shadow() {
        let mut shadow = get_shadow();
        const ADDR: GuestAddr = GS::LOW_SHADOW_OFFSET + GS::LOW_SHADOW_SIZE - 8;
        let result = shadow.poison(ADDR, 0x8, PoisonType::AsanUser);
        assert_eq!(result, Err(GuestShadowError::InvalidMemoryAddress(ADDR)));
    }

    #[test]
    fn test_posion_bottom_of_high_shadow() {
        let mut shadow = get_shadow();
        let result = shadow.poison(GS::HIGH_SHADOW_OFFSET, 0x8, PoisonType::AsanUser);
        assert_eq!(
            result,
            Err(GuestShadowError::InvalidMemoryAddress(
                GS::HIGH_SHADOW_OFFSET
            ))
        );
    }

    #[test]
    fn test_posion_top_of_high_shadow() {
        let mut shadow = get_shadow();
        const ADDR: GuestAddr = GS::HIGH_SHADOW_OFFSET + GS::HIGH_SHADOW_SIZE - 8;
        let result = shadow.poison(ADDR, 0x8, PoisonType::AsanUser);
        assert_eq!(result, Err(GuestShadowError::InvalidMemoryAddress(ADDR)));
    }

    #[test]
    fn test_posion_bottom_of_high_mem() {
        let mut shadow = get_shadow();
        shadow
            .poison(GS::HIGH_MEM_OFFSET, 0x8, PoisonType::AsanUser)
            .unwrap();
    }

    #[test]
    fn test_posion_top_of_high_mem() {
        let mut shadow = get_shadow();
        shadow
            .poison(GS::HIGH_MEM_LIMIT - 0x7, 0x8, PoisonType::AsanUser)
            .unwrap();
    }

    #[test]
    fn test_unaligned_end() {
        let mut shadow = get_shadow();
        let result = shadow.poison(0, 7, PoisonType::AsanUser);
        assert_eq!(result, Err(GuestShadowError::UnalignedEndAddress(0, 7)));
    }

    #[test]
    fn test_aligned_one() {
        let mut shadow = get_shadow();
        shadow.poison(7, 1, PoisonType::AsanUser).unwrap();
    }

    #[test]
    fn test_aligned_two() {
        let mut shadow = get_shadow();
        shadow.poison(6, 2, PoisonType::AsanUser).unwrap();
    }

    #[test]
    fn test_aligned_three() {
        let mut shadow = get_shadow();
        shadow.poison(5, 3, PoisonType::AsanUser).unwrap();
    }

    #[test]
    fn test_aligned_four() {
        let mut shadow = get_shadow();
        shadow.poison(4, 4, PoisonType::AsanUser).unwrap();
    }

    #[test]
    fn test_aligned_five() {
        let mut shadow = get_shadow();
        shadow.poison(3, 5, PoisonType::AsanUser).unwrap();
    }

    #[test]
    fn test_aligned_six() {
        let mut shadow = get_shadow();
        shadow.poison(2, 6, PoisonType::AsanUser).unwrap();
    }

    #[test]
    fn test_aligned_seven() {
        let mut shadow = get_shadow();
        shadow.poison(1, 7, PoisonType::AsanUser).unwrap();
    }

    #[test]
    fn test_overflow_address_range() {
        let mut shadow = get_shadow();
        let start = usize::MAX - (ALIGN - 1);
        let end = ALIGN * 2;
        let result = shadow.poison(usize::MAX - (ALIGN - 1), ALIGN * 2, PoisonType::AsanUser);
        assert_eq!(
            result,
            Err(GuestShadowError::AddressRangeOverflow(start, end))
        );
    }
}
