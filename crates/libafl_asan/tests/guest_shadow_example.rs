#[cfg(test)]
#[cfg(all(feature = "guest", target_pointer_width = "64"))]
mod tests {
    use std::sync::Mutex;

    use libafl_asan::{
        mmap::libc::LibcMmap,
        shadow::{
            PoisonType, Shadow,
            guest::{DefaultShadowLayout, GuestShadow},
        },
        symbols::dlsym::{DlSymSymbols, LookupTypeNext},
    };
    use spin::Lazy;

    type GS = GuestShadow<LibcMmap<DlSymSymbols<LookupTypeNext>>, DefaultShadowLayout>;

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
    fn test_poison_example1() {
        let mut shadow = get_shadow();
        // poison - start: 0x7fff2bffff00, len: 0x100, pioson: AsanUser
        // is_poison - start: 0x7fff2bfffc01, len: 0x300
        assert_eq!(
            shadow.poison(0x7fff2bffff00, 0x100, PoisonType::AsanUser),
            Ok(())
        );
        assert_eq!(shadow.is_poison(0x7fff2bfffc01, 0x300), Ok(true));
    }

    #[test]
    fn test_poison_example2() {
        let mut shadow = get_shadow();
        // poison - start: 0x7dff13ffffff, len: 0x3b9, pioson: AsanUser
        // is_poison - start: 0x7dff14000302, len: 0x2
        assert_eq!(
            shadow.poison(0x7dff13ffffff, 0x3b9, PoisonType::AsanUser),
            Ok(())
        );
        assert_eq!(shadow.is_poison(0x7dff14000302, 0x2), Ok(true));
    }

    #[test]
    fn test_poison_example3() {
        let mut shadow = get_shadow();
        // poison - start: 0x7fffffffff00, len: 0x100, pioson: AsanUser
        // is_poison - start: 0x7fffffffff00, len: 0xff
        assert_eq!(
            shadow.poison(0x7fffffffff00, 0x100, PoisonType::AsanUser),
            Ok(())
        );
        assert_eq!(shadow.is_poison(0x7fffffffff00, 0xff), Ok(true));
    }
}
