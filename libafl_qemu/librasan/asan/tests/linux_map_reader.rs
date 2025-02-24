#[cfg(test)]
#[cfg(feature = "libc")]
mod tests {
    use asan::{
        maps::{entry::MapEntry, iterator::MapIterator, linux::LinuxMapReader, MapReader},
        mmap::MmapProt,
        symbols::{
            dlsym::{DlSymSymbols, LookupTypeNext},
            SymbolsLookupStr,
        },
    };
    use itertools::Itertools;

    type Syms = DlSymSymbols<LookupTypeNext>;

    #[test]
    fn test_linux_map_reader() {
        let reader = LinuxMapReader::new().unwrap();
        let iterator = MapIterator::new(reader);
        let maps = iterator.collect::<Vec<MapEntry>>();
        for entry in &maps {
            println!("{:?}", entry);
        }
        let memcpy_addr = Syms::lookup_str(c"memcpy").unwrap();
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
