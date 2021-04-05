pub mod frida_asan_rt {
    use hashbrown::HashMap;
    use nix::{
        libc::{memcpy, memmove, memset},
        sys::mman::{mmap, mprotect, MapFlags, ProtFlags},
    };

    use libc::{_SC_PAGESIZE, pthread_atfork, sysconf};
    use std::{cell::RefCell, cell::RefMut, ffi::c_void, ffi::CString, io::{BufReader, BufRead}, fs::File};

    use libloading::Library;
    use regex::Regex;
    use object::{Object, ObjectSymbol};
    use xmas_elf::ElfFile;
    static mut ALLOCATOR_SINGLETON: Option<RefCell<Allocator>> = None;

    struct Allocator {
        page_size: usize,
        shadow_offset: usize,
        allocations: HashMap<usize, usize>,
    }

    impl Allocator {
        pub fn new() -> Self {
            Self {
                page_size: unsafe { sysconf(_SC_PAGESIZE) as usize },
                shadow_offset: 1 << 36,
                allocations: HashMap::new(),
            }
        }

        pub fn get() -> RefMut<'static, Allocator> {
            unsafe {
                match ALLOCATOR_SINGLETON.as_mut() {
                    None => {
                        ALLOCATOR_SINGLETON = Some(RefCell::new(Allocator::new()));
                    },
                    _ => (),
                }

                // we need to loop in case there is a race between threads at init time.
                loop {
                    match ALLOCATOR_SINGLETON.as_mut().unwrap().try_borrow_mut() {
                        Ok(allocref) => return allocref,
                        Err(_) => (),
                    }
                }
                //ALLOCATOR_SINGLETON.as_mut().unwrap().try_borrow_mut().unwrap()
            }
        }

        pub fn init(&self) {
            unsafe extern "C" fn atfork() {
                ALLOCATOR_SINGLETON = None;
                Allocator::get();
            }
            unsafe {
                pthread_atfork(None, None, Some(atfork));
            }
        }

        #[inline]
        fn round_up_to_page(&self, size: usize) -> usize {
            ((size + self.page_size) / self.page_size) * self.page_size
        }

        #[inline]
        fn round_down_to_page(&self, value: usize) -> usize {
            (value / self.page_size) * self.page_size
        }

        pub unsafe fn alloc(&mut self, size: usize, _alignment: usize) -> *mut c_void {
            //dbg!("in allocate");
            let rounded_up_size = self.round_up_to_page(size);

            let mapping = match mmap(
                0 as *mut c_void,
                rounded_up_size + 2 * self.page_size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                -1,
                0,
            ) {
                Ok(mapping) => mapping as usize,
                Err(err) => {
                    println!("An error occurred while mapping memory: {:?}", err);
                    return 0 as *mut c_void;
                }
            };

            let shadow_mapping_start = ((mapping + self.page_size) >> 3) + self.shadow_offset;

            let shadow_mapping = match mmap(
                self.round_down_to_page(shadow_mapping_start) as *mut c_void,
                self.round_up_to_page((rounded_up_size + 2 * self.page_size) / 8),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
                -1,
                0,
            ) {
                Ok(mapping) => mapping as usize,
                Err(err) => {
                    println!("An error occurred while mapping shadow memory: {:?}", err);
                    return 0 as *mut c_void;
                }
            };

            assert_eq!(
                shadow_mapping,
                self.round_down_to_page(shadow_mapping_start)
            );

            // unpoison the shadow memory for the allocation itself
            memset((shadow_mapping_start) as *mut c_void, 0xff, size / 8);

            self.allocations.insert(mapping + self.page_size, size);

            (mapping + self.page_size) as *mut c_void
        }

        pub unsafe fn release(&self, ptr: *mut c_void) {
            let size = match self.allocations.get(&(ptr as usize)) {
                Some(size) => size,
                None => return,
            };
            let shadow_mapping_start = (ptr as usize >> 3) + self.shadow_offset;

            // poison the shadow memory for the allocation
            memset(shadow_mapping_start as *mut c_void, 0x00, size / 8);
        }

        pub fn get_usable_size(&self, ptr: *mut c_void) -> usize {
            *self.allocations.get(&(ptr as usize)).unwrap()
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xmalloc(size: usize) -> *mut c_void {
        Allocator::get().alloc(size, 0x8)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xpvalloc(size: usize) -> *mut c_void {
        Allocator::get().alloc(size, 0x8)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xvalloc(size: usize) -> *mut c_void {
        Allocator::get().alloc(size, 0x8)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xcalloc(nmemb: usize, size: usize) -> *mut c_void {
        Allocator::get().alloc(size * nmemb, 0x8)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xrealloc(ptr: *mut c_void, size: usize) -> *mut c_void {
        let mut allocator = Allocator::get();
        let ret = allocator.alloc(size, 0x8);
        if ptr != 0 as *mut c_void {
            memmove(ret, ptr, allocator.get_usable_size(ptr));
        }
        allocator.release(ptr);
        ret
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xfree(ptr: *mut c_void) {
        if ptr != 0 as *mut c_void {
            Allocator::get().release(ptr);
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xmalloc_usable_size(ptr: *mut c_void) -> usize {
        Allocator::get().get_usable_size(ptr)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xmemalign(size: usize, alignment: usize) -> *mut c_void {
        Allocator::get().alloc(size, alignment)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xposix_memalign(
        pptr: *mut *mut c_void,
        size: usize,
        alignment: usize,
    ) -> i32 {
        *pptr = Allocator::get().alloc(size, alignment);
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn Xmallinfo() -> *mut c_void {
        0 as *mut c_void
    }

    pub struct AsanRuntime {
    }

    impl AsanRuntime {
        pub fn new() -> Self {
            Allocator::get().init();
            Self {}
        }

        pub fn hook_library(&mut self, path: &str) {
            let target_lib = HookerTargetLibrary::new(path, false);
            target_lib.hook_function("malloc", Xmalloc as *const c_void);
            target_lib.hook_function("calloc", Xcalloc as *const c_void);
            target_lib.hook_function("pvalloc", Xpvalloc as *const c_void);
            target_lib.hook_function("valloc", Xvalloc as *const c_void);
            target_lib.hook_function("realloc", Xrealloc as *const c_void);
            target_lib.hook_function("free", Xfree as *const c_void);
            target_lib.hook_function("memalign", Xmemalign as *const c_void);
            target_lib.hook_function("posix_memalign", Xposix_memalign as *const c_void);
            target_lib.hook_function("malloc_usable_size", Xmalloc_usable_size as *const c_void);
        }
    }
    struct HookerTargetLibrary<'a> {
        path: &'a str,
        start: usize,
        end: usize,
        file_in_memory: Box<&'a [u8]>,
        elf: goblin::elf::Elf<'a>,
    }

    struct Mapping {
        start: usize,
        end: usize,
        permissions: String,
        path: String,
    }

    impl<'a> HookerTargetLibrary<'a> {
        /// Create a new library to be hooked from a path. If the load boolean is true, the library will first be
        /// loaded.
        pub fn new(path: &'a str, load: bool) -> Self {
            println!("Path is {:?}", path);
            let library = if load {
                Some(unsafe { Library::new(path) })
            } else {
                None
            };

            println!("library: {:?}", library);

            let mappings =  Self::mappings_for_path(path);
            for mapping in &mappings {
                println!("start: {:x}, end: {:x}", mapping.start, mapping.end);
            }
            let start = mappings.get(0).expect("Expected at least one mapping").start;
            let end = mappings.get(mappings.len() - 1).expect("Expected at least one mapping").end;

            let file_in_memory = unsafe { std::slice::from_raw_parts(start as *const u8, end - start) };
            let mut elf = goblin::elf::Elf::lazy_parse(goblin::elf::Elf::parse_header(file_in_memory).expect("Failed to parse elf")).expect("Failed to parse elf lazily");

            let ctx = goblin::container::Ctx {
                le: scroll::Endian::Little,
                container: goblin::container::Container::Big,
            };
            elf.program_headers =  goblin::elf::ProgramHeader::parse(
                &file_in_memory,
                elf.header.e_phoff as usize,
                elf.header.e_phnum as usize,
                ctx,
            ).expect("parse program headers");
            // because we're in memory, we need to use teh vaddr. goblin uses offsets, so we'll
            // just patch the PHDRS so that they have offsets equal to vaddr.
            for mut program_header in &mut elf.program_headers {
                program_header.p_offset  = program_header.p_vaddr;
            }
            elf.dynamic = goblin::elf::dynamic::Dynamic::parse(
                &file_in_memory,
                &elf.program_headers,
                ctx,
            ).expect("parse dynamic section");

            //let mut relandroid_offset = 0;
            //let mut relandroid_size = 0;

            //for dynentry in elf.dynamic.unwrap().dyns {
                //match dynentry.d_tag {
                    //goblin::elf64::dynamic::DT_LOOS + 2 | goblin::elf64::dynamic::DT_LOOS + 4 => {
                        //relandroid_offset = dynentry.d_val;
                    //},
                    //goblin::elf64::dynamic::DT_LOOS + 3 | goblin::elf64::dynamic::DT_LOOS + 5 => {
                        //relandroid_size = dynentry.d_val;
                    //},
                //}
            //}

            let info = &elf.dynamic.as_ref().unwrap().info;

            // second word of hash
            let chain_count = unsafe { std::slice::from_raw_parts((start + info.hash.unwrap() as usize + 4) as *mut u32, 1)[0] };

            elf.dynsyms = goblin::elf::sym::Symtab::parse(
                &file_in_memory,
                info.symtab,
                chain_count as usize,
                ctx,
            ).expect("parse dynsyms");
            elf.dynstrtab = goblin::strtab::Strtab::parse(
                &file_in_memory,
                info.strtab,
                info.strsz,
                b'\x00'
            ).expect("parse dynstrtab");
            println!("info: {:?}", info);
            elf.pltrelocs = goblin::elf::RelocSection::parse(
                &file_in_memory,
                info.jmprel,
                info.pltrelsz,
                info.pltrel == goblin::elf64::dynamic::DT_RELA,
                ctx
            ).expect("parse pltrel");
            //
            //let dynsyms = &elf.dynsyms.to_vec();
            //let gnu_hash_metadata = unsafe { std::slice::from_raw_parts((start + dynamic.info.gnu_hash.unwrap() as usize) as *mut u32, 4)};
            //let gnu_hash_size = (dynsyms.len() - gnu_hash_metadata[1] as usize) * 4 + gnu_hash_metadata[0] as usize * 4 + gnu_hash_metadata[2] as usize  * 8 + 4 * 4;
            //let gnu_hash = unsafe { goblin::elf64::gnu_hash::GnuHash::from_raw_table(
                //std::slice::from_raw_parts((start + dynamic.info.gnu_hash.unwrap() as usize) as *mut u8,  gnu_hash_size as usize),
                //dynsyms) }.expect("parse gnu_hash");

            Self {
                path,
                start,
                end,
                file_in_memory: Box::new(file_in_memory),
                elf,
            }
        }

        fn mappings_for_path(path: &str) -> Vec<Mapping> {
            let re = Regex::new(r"^(?P<start>[0-9a-f]{8,16})-(?P<end>[0-9a-f]{8,16}) (?P<perm>[-rwxp]{4}) (?P<offset>[0-9a-f]{8}) [0-9a-f]+:[0-9a-f]+ [0-9]+\s+(?P<path>.*)$")
                .unwrap();

            let mapsfile = File::open("/proc/self/maps").expect("Unable to open /proc/self/maps");

            let mut mappings: Vec<Mapping> = vec!();

            for line in BufReader::new(mapsfile).lines() {
                let line = line.unwrap();
                match re.captures(&line) {
                    Some(caps) => {
                        //println!("caps: {:?}", caps.name("path").unwrap().as_str());
                        if caps.name("path").unwrap().as_str() == path {
                            mappings.push(Mapping {
                                start: usize::from_str_radix(caps.name("start").unwrap().as_str(), 16).unwrap(),
                                end: usize::from_str_radix(caps.name("end").unwrap().as_str(), 16).unwrap(),
                                permissions: caps.name("perm").unwrap().as_str().to_string(),
                                path: caps.name("path").unwrap().as_str().to_string(),
                            });
                        }
                    },
                    _ => (),
                }
            };

            mappings
        }

        pub fn hook_function(&self, name: &str, newfunc: *const c_void) -> bool {
            let mut symindex: isize  = -1;
            for (i, symbol) in self.elf.dynsyms.iter().enumerate() {
                if name == self.elf.dynstrtab.get(symbol.st_name).unwrap().unwrap() {;
                    symindex = i as isize;
                    break;
                }
            };

            if symindex == -1 {
                println!("failed to find function {:?}", name);
                return false;
            }

            let mut offset: isize = -1;
            for reloc in self.elf.pltrelocs.iter() {
                if reloc.r_sym == symindex as usize {
                    offset = reloc.r_offset as isize;
                    break;
                }
            };

            unsafe {
                let address = self.start + offset as usize;
                let value = std::ptr::read(address as *const *const c_void);
                println!("found {:?} at address {:x}, with value {:x}, replacing...", name, address, value as usize);
                mprotect(((address / 0x1000) * 0x1000) as *mut c_void, 0x1000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE);
                std::ptr::replace(address as *mut *const c_void, newfunc);
                mprotect(((address / 0x1000) * 0x1000) as *mut c_void, 0x1000, ProtFlags::PROT_READ);

                let value = std::ptr::read(address as *const *const c_void);
                println!("verified value set to {:x}, expected {:x}", value as usize, newfunc as usize);

                value == newfunc
            }
        }
    }
}
