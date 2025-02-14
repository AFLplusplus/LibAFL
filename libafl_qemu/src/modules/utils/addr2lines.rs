use std::borrow::Cow;

use object::{Object, ObjectSection};

pub fn load_file_section<'input, 'arena, Endian: addr2line::gimli::Endianity>(
    id: addr2line::gimli::SectionId,
    file: &object::File<'input>,
    endian: Endian,
    arena_data: &'arena typed_arena::Arena<Cow<'input, [u8]>>,
) -> Result<addr2line::gimli::EndianSlice<'arena, Endian>, object::Error> {
    // TODO: Unify with dwarfdump.rs in gimli.
    let name = id.name();
    match file.section_by_name(name) {
        Some(section) => match section.uncompressed_data()? {
            Cow::Borrowed(b) => Ok(addr2line::gimli::EndianSlice::new(b, endian)),
            Cow::Owned(b) => Ok(addr2line::gimli::EndianSlice::new(
                arena_data.alloc(b.into()),
                endian,
            )),
        },
        None => Ok(addr2line::gimli::EndianSlice::new(&[][..], endian)),
    }
}

/// Taken from `addr2line` [v0.22](https://github.com/gimli-rs/addr2line/blob/5c3c83f74f992220b2d9a17b3ac498a89214bf92/src/builtin_split_dwarf_loader.rs)
/// has been removed in version v0.23 for some reason.
/// TODO: find another cleaner solution.
pub mod addr2line_legacy {
    use std::{borrow::Cow, env, ffi::OsString, fs::File, path::PathBuf, sync::Arc};

    use addr2line::{gimli, LookupContinuation, LookupResult};
    use object::Object;

    #[cfg(unix)]
    fn convert_path<R: gimli::Reader<Endian = gimli::RunTimeEndian>>(
        r: &R,
    ) -> Result<PathBuf, gimli::Error> {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        let bytes = r.to_slice()?;
        let s = OsStr::from_bytes(&bytes);
        Ok(PathBuf::from(s))
    }

    #[cfg(not(unix))]
    fn convert_path<R: gimli::Reader<Endian = gimli::RunTimeEndian>>(
        r: &R,
    ) -> Result<PathBuf, gimli::Error> {
        let bytes = r.to_slice()?;
        let s = str::from_utf8(&bytes).map_err(|_| gimli::Error::BadUtf8)?;
        Ok(PathBuf::from(s))
    }

    fn load_section<'data, O, R, F>(
        id: gimli::SectionId,
        file: &O,
        endian: R::Endian,
        loader: &mut F,
    ) -> R
    where
        O: Object<'data>,
        R: gimli::Reader<Endian = gimli::RunTimeEndian>,
        F: FnMut(Cow<'data, [u8]>, R::Endian) -> R,
    {
        use object::ObjectSection;

        let data = id
            .dwo_name()
            .and_then(|dwo_name| {
                file.section_by_name(dwo_name)
                    .and_then(|section| section.uncompressed_data().ok())
            })
            .unwrap_or(Cow::Borrowed(&[]));
        loader(data, endian)
    }

    /// A simple builtin split DWARF loader.
    pub struct SplitDwarfLoader<R, F>
    where
        R: gimli::Reader<Endian = gimli::RunTimeEndian>,
        F: FnMut(Cow<'_, [u8]>, R::Endian) -> R,
    {
        loader: F,
        dwarf_package: Option<gimli::DwarfPackage<R>>,
    }

    impl<R, F> SplitDwarfLoader<R, F>
    where
        R: gimli::Reader<Endian = gimli::RunTimeEndian>,
        F: FnMut(Cow<'_, [u8]>, R::Endian) -> R,
    {
        fn load_dwarf_package(
            loader: &mut F,
            path: Option<PathBuf>,
        ) -> Option<gimli::DwarfPackage<R>> {
            let mut path = path.map_or_else(env::current_exe, Ok).ok()?;
            let dwp_extension = path.extension().map_or_else(
                || OsString::from("dwp"),
                |previous_extension| {
                    let mut previous_extension = previous_extension.to_os_string();
                    previous_extension.push(".dwp");
                    previous_extension
                },
            );
            path.set_extension(dwp_extension);
            let file = File::open(&path).ok()?;
            let map = unsafe { memmap2::Mmap::map(&file).ok()? };
            let dwp = object::File::parse(&*map).ok()?;

            let endian = if dwp.is_little_endian() {
                gimli::RunTimeEndian::Little
            } else {
                gimli::RunTimeEndian::Big
            };

            let empty = loader(Cow::Borrowed(&[]), endian);
            gimli::DwarfPackage::load::<_, gimli::Error>(
                |section_id| Ok(load_section(section_id, &dwp, endian, loader)),
                empty,
            )
            .ok()
        }

        /// Create a new split DWARF loader.
        pub fn new(mut loader: F, path: Option<PathBuf>) -> SplitDwarfLoader<R, F> {
            let dwarf_package = SplitDwarfLoader::load_dwarf_package(&mut loader, path);
            SplitDwarfLoader {
                loader,
                dwarf_package,
            }
        }

        /// Run the provided `LookupResult` to completion, loading any necessary
        /// split DWARF along the way.
        pub fn run<L>(&mut self, mut l: LookupResult<L>) -> L::Output
        where
            L: LookupContinuation<Buf = R>,
        {
            loop {
                let (load, continuation) = match l {
                    LookupResult::Output(output) => break output,
                    LookupResult::Load { load, continuation } => (load, continuation),
                };

                let mut r: Option<Arc<gimli::Dwarf<_>>> = None;
                if let Some(dwp) = self.dwarf_package.as_ref() {
                    if let Ok(Some(cu)) = dwp.find_cu(load.dwo_id, &load.parent) {
                        r = Some(Arc::new(cu));
                    }
                }

                if r.is_none() {
                    let mut path = PathBuf::new();
                    if let Some(p) = load.comp_dir.as_ref() {
                        if let Ok(p) = convert_path(p) {
                            path.push(p);
                        }
                    }

                    if let Some(p) = load.path.as_ref() {
                        if let Ok(p) = convert_path(p) {
                            path.push(p);
                        }
                    }

                    if let Ok(file) = File::open(&path) {
                        if let Ok(map) = unsafe { memmap2::Mmap::map(&file) } {
                            if let Ok(file) = object::File::parse(&*map) {
                                let endian = if file.is_little_endian() {
                                    gimli::RunTimeEndian::Little
                                } else {
                                    gimli::RunTimeEndian::Big
                                };

                                r = gimli::Dwarf::load::<_, gimli::Error>(|id| {
                                    Ok(load_section(id, &file, endian, &mut self.loader))
                                })
                                .ok()
                                .map(|mut dwo_dwarf| {
                                    dwo_dwarf.make_dwo(&load.parent);
                                    Arc::new(dwo_dwarf)
                                });
                            }
                        }
                    }
                }

                l = continuation.resume(r);
            }
        }
    }
}
