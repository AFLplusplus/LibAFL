#[cfg(test)]
#[cfg(feature = "libc")]
mod tests {
    use asan::{
        file::libc::LibcFileReader,
        maps::{entry::MapEntry, iterator::MapIterator},
        mmap::MmapProt,
        symbols::{
            Symbols,
            dlsym::{DlSymSymbols, LookupTypeNext},
        },
    };
    use itertools::Itertools;

    type Syms = DlSymSymbols<LookupTypeNext>;

    #[test]
    fn test_libc_map_reader() {
        let iterator = MapIterator::<LibcFileReader<Syms>>::new().unwrap();
        let maps = iterator.collect::<Vec<MapEntry>>();
        for entry in &maps {
            println!("{:?}", entry);
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
