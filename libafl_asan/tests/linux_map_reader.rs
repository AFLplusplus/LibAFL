#[cfg(all(test, feature = "linux", target_os = "linux"))]
mod tests {
    use itertools::Itertools;
    use libafl_asan::{
        file::linux::LinuxFileReader,
        maps::{entry::MapEntry, iterator::MapIterator},
        mmap::MmapProt,
        symbols::{
            Symbols,
            dlsym::{DlSymSymbols, LookupTypeNext},
        },
    };

    type Syms = DlSymSymbols<LookupTypeNext>;

    #[test]
    fn test_linux_map_reader() {
        let iterator = MapIterator::<LinuxFileReader>::new().unwrap();
        let maps = iterator.collect::<Vec<MapEntry>>();
        for entry in &maps {
            println!("{entry:?}");
        }
        let memcpy_addr = Syms::lookup(c"memcpy").unwrap();
        assert_ne!(maps.len(), 0);
        assert!(maps.iter().any(|e| e.contains(memcpy_addr)));
        let entry = maps
            .iter()
            .filter(|e| e.contains(memcpy_addr))
            .exactly_one()
            .unwrap();
        assert!(entry.path().ends_with("libc.so.6"));
        assert_eq!(entry.prot() & MmapProt::EXEC, MmapProt::EXEC)
    }
}
