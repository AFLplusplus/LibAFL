//! The allocator hooks for address sanitizer.
use core::ffi::c_void;

use backtrace::Backtrace;
use libc::{c_char, wchar_t};

use crate::{
    allocator::Allocator,
    asan::{
        asan_rt::AsanRuntime,
        errors::{AsanError, AsanErrors},
    },
};

#[cfg(windows)]
unsafe extern "system" {
    fn memcpy(dst: *mut c_void, src: *const c_void, size: usize) -> *mut c_void;
}
#[cfg(windows)]
unsafe extern "system" {
    fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
}

use core::ptr;

#[cfg(windows)]
use winapi::um::memoryapi::VirtualQuery;
#[cfg(windows)]
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

#[expect(clippy::not_unsafe_ptr_arg_deref)]
impl AsanRuntime {
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_NtGdiCreateCompatibleDC(
        &mut self,
        _original: extern "C" fn(_hdc: *const c_void) -> *mut c_void,
        _hdc: *const c_void,
    ) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(8, 8) }
    }

    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_CreateThread(
        &mut self,
        original: extern "C" fn(
            thread_attributes: *const c_void,
            stack_size: usize,
            start_address: *const c_void,
            parameter: *const c_void,
            creation_flags: i32,
            thread_id: *mut i32,
        ) -> usize,
        thread_attributes: *const c_void,
        stack_size: usize,
        start_address: *const c_void,
        parameter: *const c_void,
        creation_flags: i32,
        thread_id: *mut i32,
    ) -> usize {
        original(
            thread_attributes,
            stack_size,
            start_address,
            parameter,
            creation_flags,
            thread_id,
        )
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_CreateFileMappingW(
        &mut self,
        original: extern "C" fn(
            file: usize,
            file_mapping_attributes: *const c_void,
            protect: i32,
            maximum_size_high: u32,
            maximum_size_low: u32,
            name: *const c_void,
        ) -> usize,
        file: usize,
        file_mapping_attributes: *const c_void,
        protect: i32,
        maximum_size_high: u32,
        maximum_size_low: u32,
        name: *const c_void,
    ) -> usize {
        //        winsafe::OutputDebugString("In CreateFileMapping\n");
        original(
            file,
            file_mapping_attributes,
            protect,
            maximum_size_high,
            maximum_size_low,
            name,
        )
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LdrLoadDll(
        &mut self,
        original: extern "C" fn(
            search_path: *const c_void,
            charecteristics: *const u32,
            dll_name: *const c_void,
            base_address: *mut *const c_void,
        ) -> usize,
        search_path: *const c_void,
        charecteristics: *const u32,
        dll_name: *const c_void,
        base_address: *mut *const c_void,
    ) -> usize {
        //        winsafe::OutputDebugString("LdrLoadDll");
        log::trace!("LdrLoadDll");
        let result = original(search_path, charecteristics, dll_name, base_address);

        self.allocator_mut().unpoison_all_existing_memory();
        result
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LdrpCallInitRoutine(
        &mut self,
        _original: extern "C" fn(
            _base_address: *const c_void,
            _reason: usize,
            _base_address: *const c_void,
            _entry_point: usize,
        ) -> usize,
        _base_address: *const c_void,
        _reason: usize,
        _context: usize,
        _entry_point: usize,
    ) -> usize {
        log::trace!("LdrpCallInitRoutine");
        //        winsafe::OutputDebugString("LdrpCallInitRoutine");
        // let result = unsafe { LdrLoadDll(path, file, flags,x )};
        // self.allocator_mut().unpoison_all_existing_memory();
        // result
        0
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LoadLibraryExW(
        &mut self,
        original: extern "C" fn(path: *const c_void, file: usize, flags: i32) -> usize,
        path: *const c_void,
        file: usize,
        flags: i32,
    ) -> usize {
        log::trace!("Loaded library!");

        let result = original(path, file, flags);
        self.allocator_mut().unpoison_all_existing_memory();
        result
    }

    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlCreateHeap(
        &mut self,
        _original: extern "C" fn(
            _flags: u32,
            _heap_base: *const c_void,
            _reserve_size: usize,
            _commit_size: usize,
            _lock: *const c_void,
            _parameters: *const c_void,
        ) -> *mut c_void,
        _flags: u32,
        _heap_base: *const c_void,
        _reserve_size: usize,
        _commit_size: usize,
        _lock: *const c_void,
        _parameters: *const c_void,
    ) -> *mut c_void {
        log::trace!("RtlCreateHeap");
        0xc0debeef as *mut c_void
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlDestroyHeap(
        &mut self,
        _original: extern "C" fn(_handle: *const c_void) -> *mut c_void,
        _handle: *const c_void,
    ) -> *mut c_void {
        log::trace!("RtlDestroyHeap");
        ptr::null_mut()
    }

    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_HeapAlloc(
        &mut self,
        _original: extern "C" fn(_handle: *mut c_void, flags: u32, size: usize) -> *mut c_void,
        _handle: *mut c_void,
        flags: u32,
        size: usize,
    ) -> *mut c_void {
        log::trace!("HeapAlloc");
        let mut allocator = self.allocator_mut();
        let ret = unsafe { allocator.alloc(size, 8) };

        if flags & 8 == 8 {
            unsafe {
                memset(ret, 0, size);
            }
        }
        if flags & 4 == 4 && ret.is_null() {
            unimplemented!();
        }
        ret
    }

    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlAllocateHeap(
        &mut self,
        _original: extern "C" fn(_handle: *mut c_void, flags: u32, size: usize) -> *mut c_void,
        _handle: *mut c_void,
        flags: u32,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook_RtlAllocateHeap handle {_handle:#?} flags {flags:x} size {size}");

        let mut allocator = self.allocator_mut();
        let ret = unsafe { allocator.alloc(size, 8) };

        if flags & 8 == 8 {
            unsafe {
                memset(ret, 0, size);
            }
        }
        if flags & 4 == 4 && ret.is_null() {
            unimplemented!();
        }
        ret
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_HeapReAlloc(
        &mut self,
        original: extern "C" fn(
            handle: *mut c_void,
            flags: u32,
            ptr: *mut c_void,
            size: usize,
        ) -> *mut c_void,
        handle: *mut c_void,
        flags: u32,
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook_HeapReAlloc handle {handle:#?} flags {flags:x} ptr {ptr:#?} size {size}");
        let mut allocator = self.allocator_mut();
        if !allocator.is_managed(ptr) {
            return original(handle, flags, ptr, size);
        }
        let ret = unsafe {
            let ret = allocator.alloc(size, 8);

            memcpy(ret, ptr, allocator.get_usable_size(ptr));
            allocator.release(ptr);
            ret
        };

        if flags & 8 == 8 {
            unsafe extern "system" {
                fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
            }
            unsafe {
                memset(ret, 0, size);
            }
        }
        if flags & 4 == 4 && ret.is_null() {
            unimplemented!();
        }
        if flags & 0x10 == 0x10 && ret != ptr {
            unimplemented!();
        }
        ret
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlReAllocateHeap(
        &mut self,
        original: extern "C" fn(
            handle: *mut c_void,
            flags: u32,
            ptr: *mut c_void,
            size: usize,
        ) -> *mut c_void,
        handle: *mut c_void,
        flags: u32,
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        let mut allocator = self.allocator_mut();
        log::trace!("RtlReAllocateHeap({ptr:?}, {size:x})");
        if !allocator.is_managed(ptr) {
            return original(handle, flags, ptr, size);
        }
        let ret = unsafe {
            let ret = allocator.alloc(size, 8);

            memcpy(ret, ptr, allocator.get_usable_size(ptr));
            allocator.release(ptr);
            ret
        };

        if flags & 8 == 8 {
            unsafe extern "system" {
                fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
            }
            unsafe {
                memset(ret, 0, size);
            }
        }
        if flags & 4 == 4 && ret.is_null() {
            unimplemented!();
        }
        if flags & 0x10 == 0x10 && ret != ptr {
            unimplemented!();
        }
        ret
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_RtlFreeHeap(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        log::trace!("hook_check_RtlFreeHeap ptr {ptr:#?}");
        self.allocator_mut().is_managed(ptr)
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlFreeHeap(
        &mut self,
        _original: extern "C" fn(_handle: *mut c_void, _flags: u32, ptr: *mut c_void) -> usize,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> usize {
        log::trace!("hook_RtlFreeHeap address handle {_handle:#?} flags 0x{_flags:x} ptr {ptr:#?}");
        unsafe { self.allocator_mut().release(ptr) };
        0
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_HeapFree(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        log::trace!("hook_check_HeapFree");
        self.allocator_mut().is_managed(ptr)
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_HeapFree(
        &mut self,
        _original: extern "C" fn(_handle: *mut c_void, _flags: u32, ptr: *mut c_void) -> bool,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        log::trace!("hook_HeapFree");
        unsafe { self.allocator_mut().release(ptr) };
        true
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_HeapSize(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        log::trace!("hook_check_HeapSize");
        self.allocator_mut().is_managed(ptr)
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_HeapSize(
        &mut self,
        _original: extern "C" fn(_handle: *mut c_void, _flags: u32, ptr: *mut c_void) -> usize,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> usize {
        log::trace!("hook_HeapSize");
        self.allocator().get_usable_size(ptr)
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_RtlSizeHeap(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        log::trace!("hook_check_RtlSizeHeap");
        self.allocator_mut().is_managed(ptr)
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlSizeHeap(
        &mut self,
        _original: extern "C" fn(_handle: *mut c_void, _flags: u32, ptr: *mut c_void) -> usize,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> usize {
        log::trace!("hook_RtlSizeHeap");
        self.allocator().get_usable_size(ptr)
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_RtlValidateHeap(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        log::trace!("hook_check_RtlValidateHeap");
        self.allocator_mut().is_managed(ptr)
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlValidateHeap(
        &mut self,
        _original: extern "C" fn(_handle: *mut c_void, _flags: u32, _ptr: *mut c_void) -> bool,
        _handle: *mut c_void,
        _flags: u32,
        _ptr: *mut c_void,
    ) -> bool {
        log::trace!("hook_RtlValidateHeap");
        true
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalAlloc(
        &mut self,
        _original: extern "C" fn(flags: u32, size: usize) -> *mut c_void,
        flags: u32,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook_LocalAlloc");
        let ret = unsafe { self.allocator_mut().alloc(size, 8) };

        if flags & 0x40 == 0x40 {
            unsafe {
                memset(ret, 0, size);
            }
        }
        ret
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalReAlloc(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void, size: usize, _flags: u32) -> *mut c_void,
        mem: *mut c_void,
        size: usize,
        _flags: u32,
    ) -> *mut c_void {
        log::trace!("hook_LocalReAlloc");
        unsafe {
            let ret = self.allocator_mut().alloc(size, 0x8);
            if !mem.is_null() && !ret.is_null() {
                let old_size = self.allocator_mut().get_usable_size(mem);
                let copy_size = if size < old_size { size } else { old_size };
                (mem as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator_mut().release(mem);
            ret
        }
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalFree(&mut self, mem: *mut c_void) -> bool {
        log::trace!("hook_check_LocalFree");
        let res = self.allocator_mut().is_managed(mem);
        res
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalFree(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void) -> *mut c_void,
        mem: *mut c_void,
    ) -> *mut c_void {
        log::trace!("hook_LocalFree");
        unsafe { self.allocator_mut().release(mem) };
        mem
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalHandle(&mut self, mem: *mut c_void) -> bool {
        log::trace!("hook_check_LocalHandle");
        self.allocator_mut().is_managed(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalHandle(
        &mut self,
        _soriginal: extern "C" fn(mem: *mut c_void) -> *mut c_void,
        mem: *mut c_void,
    ) -> *mut c_void {
        log::trace!("hook_LocalHandle");
        mem
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalLock(&mut self, mem: *mut c_void) -> bool {
        log::trace!("hook_check_LocalLock");
        self.allocator_mut().is_managed(mem)
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalLock(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void) -> *mut c_void,
        mem: *mut c_void,
    ) -> *mut c_void {
        log::trace!("hook_LocalLock");
        mem
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalUnlock(&mut self, mem: *mut c_void) -> bool {
        log::trace!("hook_check_LocalUnlock");
        self.allocator_mut().is_managed(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalUnlock(
        &mut self,
        _original: extern "C" fn(_mem: *mut c_void) -> bool,
        _mem: *mut c_void,
    ) -> bool {
        log::trace!("hook_LocalUnlock");
        false
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalSize(&mut self, mem: *mut c_void) -> bool {
        log::trace!("hook_check_LocalSize");
        self.allocator_mut().is_managed(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalSize(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void) -> usize,
        mem: *mut c_void,
    ) -> usize {
        log::trace!("hook_LocalSize");
        self.allocator_mut().get_usable_size(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalFlags(&mut self, mem: *mut c_void) -> bool {
        log::trace!("hook_check_LocalFlags");
        self.allocator_mut().is_managed(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalFlags(
        &mut self,
        _original: extern "C" fn(_mem: *mut c_void) -> u32,
        _mem: *mut c_void,
    ) -> u32 {
        log::trace!("hook_LocalFlags");
        0
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalAlloc(
        &mut self,
        _original: extern "C" fn(flags: u32, size: usize) -> *mut c_void,
        flags: u32,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook_GlobalAlloc");
        let ret = unsafe { self.allocator_mut().alloc(size, 8) };

        if flags & 0x40 == 0x40 {
            unsafe extern "system" {
                fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
            }
            unsafe {
                memset(ret, 0, size);
            }
        }
        ret
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalReAlloc(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void, _flags: u32, size: usize) -> *mut c_void,
        mem: *mut c_void,
        _flags: u32,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook_GlobalReAlloc");
        unsafe {
            let ret = self.allocator_mut().alloc(size, 0x8);
            if !mem.is_null() && !ret.is_null() {
                let old_size = self.allocator_mut().get_usable_size(mem);
                let copy_size = if size < old_size { size } else { old_size };
                (mem as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator_mut().release(mem);
            ret
        }
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalFree(&mut self, mem: *mut c_void) -> bool {
        log::trace!("hook_check_GlobalFree");
        self.allocator_mut().is_managed(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalFree(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void) -> *mut c_void,
        mem: *mut c_void,
    ) -> *mut c_void {
        log::trace!("hook_GlobalFree");
        unsafe { self.allocator_mut().release(mem) };
        mem
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalHandle(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalHandle(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void) -> *mut c_void,
        mem: *mut c_void,
    ) -> *mut c_void {
        log::trace!("hook_GlobalHandle");
        mem
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalLock(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }

    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalLock(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void) -> *mut c_void,
        mem: *mut c_void,
    ) -> *mut c_void {
        log::trace!("hook_GlobalLock");
        mem
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalUnlock(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalUnlock(
        &mut self,
        _original: extern "C" fn(_mem: *mut c_void) -> bool,
        _mem: *mut c_void,
    ) -> bool {
        log::trace!("hook_GlobalUnlock");
        false
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalSize(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalSize(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void) -> usize,
        mem: *mut c_void,
    ) -> usize {
        log::trace!("hook_GlobalSize");
        self.allocator_mut().get_usable_size(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalFlags(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalFlags(
        &mut self,
        _original: extern "C" fn(mem: *mut c_void) -> u32,
        _mem: *mut c_void,
    ) -> u32 {
        log::trace!("hook_GlobalFlags");
        0
    }

    #[inline]
    #[cfg(target_vendor = "apple")]
    pub fn hook_valloc(
        &mut self,
        _original: extern "C" fn(size: usize) -> *mut c_void,
        size: usize,
    ) -> *mut c_void {
        unsafe {
            log::trace!("hook_malloc");
            self.allocator_mut().alloc(size, 8)
        }
    }

    #[inline]
    pub fn hook_malloc(
        &mut self,
        _original: extern "C" fn(size: usize) -> *mut c_void,
        size: usize,
    ) -> *mut c_void {
        unsafe {
            log::trace!("hook_malloc");
            self.allocator_mut().alloc(size, 8)
        }
    }

    #[inline]
    pub fn hook_o_malloc(
        &mut self,
        _original: extern "C" fn(size: usize) -> *mut c_void,
        size: usize,
    ) -> *mut c_void {
        unsafe {
            log::trace!("hook_o_malloc");
            self.allocator_mut().alloc(size, 8)
        }
    }

    #[expect(non_snake_case)]
    #[inline]
    pub fn hook__Znam(
        &mut self,
        _original: extern "C" fn(size: usize) -> *mut c_void,
        size: usize,
    ) -> *mut c_void {
        unsafe {
            log::trace!("hook__Znam");
            self.allocator_mut().alloc(size, 8)
        }
    }

    #[expect(non_snake_case)]
    #[inline]
    pub fn hook__ZnamRKSt9nothrow_t(
        &mut self,
        _original: extern "C" fn(size: usize, _nothrow: *const c_void) -> *mut c_void,
        size: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        log::trace!("hook__ZnamRKSt9nothrow_t");
        unsafe { self.allocator_mut().alloc(size, 8) }
    }

    #[expect(non_snake_case)]
    #[inline]
    pub fn hook__ZnamSt11align_val_t(
        &mut self,
        _original: extern "C" fn(size: usize, alignment: usize) -> *mut c_void,
        size: usize,
        alignment: usize,
    ) -> *mut c_void {
        log::trace!("hook__ZnamSt11align_val_t");
        unsafe { self.allocator_mut().alloc(size, alignment) }
    }

    #[expect(non_snake_case)]
    #[inline]
    pub fn hook__ZnamSt11align_val_tRKSt9nothrow_t(
        &mut self,
        _original: extern "C" fn(
            size: usize,
            alignment: usize,
            _nothrow: *const c_void,
        ) -> *mut c_void,
        size: usize,
        alignment: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        log::trace!("hook__ZnamSt11align_val_tRKSt9nothrow_t");
        unsafe { self.allocator_mut().alloc(size, alignment) }
    }

    #[expect(non_snake_case)]
    #[allow(unknown_lints)] // the compiler is contradicting itself
    #[inline]
    pub fn hook__Znwm(
        &mut self,
        _original: extern "C" fn(size: usize) -> *mut c_void,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook__Znwm");
        let result = unsafe { self.allocator_mut().alloc(size, 8) };
        if result.is_null() {
            unsafe extern "system" {
                fn _ZSt17__throw_bad_allocv();
            }

            unsafe {
                _ZSt17__throw_bad_allocv();
            }
            0xabcdef as *mut c_void
        } else {
            result
        }
    }

    #[expect(non_snake_case)]
    #[inline]
    pub fn hook__ZnwmRKSt9nothrow_t(
        &mut self,
        _original: extern "C" fn(size: usize, _nothrow: *const c_void) -> *mut c_void,
        size: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        log::trace!("hook__ZnwmRKSt9nothrow_t");
        unsafe { self.allocator_mut().alloc(size, 8) }
    }

    #[expect(non_snake_case)]
    #[allow(unknown_lints)] // the compiler is contradicting itself
    #[inline]
    pub fn hook__ZnwmSt11align_val_t(
        &mut self,
        _original: extern "C" fn(size: usize, alignment: usize) -> *mut c_void,
        size: usize,
        alignment: usize,
    ) -> *mut c_void {
        log::trace!("hook__ZnwmSt11align_val_t");
        let result = unsafe { self.allocator_mut().alloc(size, alignment) };
        if result.is_null() {
            unsafe extern "system" {
                fn _ZSt17__throw_bad_allocv();
            }

            unsafe {
                _ZSt17__throw_bad_allocv();
            }
        }
        result
    }

    #[expect(non_snake_case)]
    #[inline]
    pub fn hook__ZnwmSt11align_val_tRKSt9nothrow_t(
        &mut self,
        _original: extern "C" fn(
            size: usize,
            alignment: usize,
            _nothrow: *const c_void,
        ) -> *mut c_void,
        size: usize,
        alignment: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        log::trace!("hook__ZnwmSt11align_val_tRKSt9nothrow_t");
        unsafe { self.allocator_mut().alloc(size, alignment) }
    }

    #[expect(non_snake_case)]
    #[inline]
    pub fn hook__o_malloc(
        &mut self,
        _original: extern "C" fn(size: usize) -> *mut c_void,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook__o_malloc");
        unsafe { self.allocator_mut().alloc(size, 8) }
    }
    #[inline]
    pub fn hook_calloc(
        &mut self,
        _original: extern "C" fn(nmemb: usize, size: usize) -> *mut c_void,
        nmemb: usize,
        size: usize,
    ) -> *mut c_void {
        unsafe extern "system" {
            fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        log::trace!("hook_calloc");
        let ret = unsafe { self.allocator_mut().alloc(size * nmemb, 8) };
        // if size * nmemb == 0x10 {
        //     log::error!("backtrace: {:0x?}", frida_gum::Backtracer::accurate());
        //     let x:usize = 0x12345;
        //   unsafe {  (x as *const usize).read(); }
        // }
        unsafe {
            memset(ret, 0, size * nmemb);
        }
        ret
    }

    #[expect(non_snake_case)]
    #[inline]
    pub fn hook__o_calloc(
        &mut self,
        _original: extern "C" fn(nmemb: usize, size: usize) -> *mut c_void,
        nmemb: usize,
        size: usize,
    ) -> *mut c_void {
        unsafe extern "system" {
            fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        log::trace!("hook__o_calloc");
        let ret = unsafe { self.allocator_mut().alloc(size * nmemb, 8) };
        unsafe {
            memset(ret, 0, size * nmemb);
        }
        ret
    }

    #[inline]
    pub fn hook_check_realloc(&mut self, ptr: *mut c_void, _size: usize) -> bool {
        self.allocator_mut().is_managed(ptr)
    }

    #[inline]
    #[expect(clippy::cmp_null)]
    pub fn hook_realloc(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, size: usize) -> *mut c_void,
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook_realloc");
        unsafe {
            if size == 0 {
                self.allocator_mut().release(ptr);
                #[cfg(not(target_vendor = "apple"))]
                return ptr::null_mut();
                #[cfg(target_vendor = "apple")]
                return self.allocator_mut().alloc(0, 0x8);
            }
            let ret = self.allocator_mut().alloc(size, 0x8);
            if ptr != ptr::null_mut() && ret != ptr::null_mut() {
                let old_size = self.allocator_mut().get_usable_size(ptr);
                let copy_size = if size < old_size { size } else { old_size };
                (ptr as *mut u8).copy_to(ret as *mut u8, copy_size);
                self.allocator_mut().release(ptr);
            }
            ret
        }
    }

    #[inline]
    #[cfg(target_vendor = "apple")]
    pub fn hook_check_reallocf(&mut self, ptr: *mut c_void, _size: usize) -> bool {
        self.allocator_mut().is_managed(ptr)
    }

    #[inline]
    #[expect(clippy::cmp_null)]
    #[cfg(target_vendor = "apple")]
    pub fn hook_reallocf(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, size: usize) -> *mut c_void,
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        unsafe {
            if size == 0 {
                self.allocator_mut().release(ptr);
                return self.allocator_mut().alloc(0, 0x8);
            }
            let ret = self.allocator_mut().alloc(size, 0x8);
            if ptr != ptr::null_mut() && ret != ptr::null_mut() {
                let old_size = self.allocator_mut().get_usable_size(ptr);
                let copy_size = if size < old_size { size } else { old_size };
                (ptr as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator_mut().release(ptr);
            ret
        }
    }

    #[expect(non_snake_case)]
    #[inline]
    #[expect(clippy::cmp_null)]
    pub fn hook__o_realloc(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, size: usize) -> *mut c_void,
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook__o_realloc");
        unsafe {
            let ret = self.allocator_mut().alloc(size, 0x8);
            if ptr != ptr::null_mut() && ret != ptr::null_mut() {
                let old_size = self.allocator_mut().get_usable_size(ptr);
                let copy_size = if size < old_size { size } else { old_size };
                (ptr as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator_mut().release(ptr);
            ret
        }
    }

    #[expect(non_snake_case)]
    #[inline]
    pub fn hook_check__o_free(&mut self, ptr: *mut c_void) -> bool {
        log::trace!("hook_check__o_free");
        self.allocator_mut().is_managed(ptr)
    }

    #[expect(non_snake_case)]
    #[inline]
    #[expect(clippy::cmp_null)]
    pub fn hook__o_free(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void) -> usize,
        ptr: *mut c_void,
    ) -> usize {
        log::trace!("hook__o_free");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }
    #[inline]
    pub fn hook_check_free(&mut self, ptr: *mut c_void) -> bool {
        self.allocator_mut().is_managed(ptr)
    }

    #[inline]
    #[expect(clippy::cmp_null)]
    pub fn hook_free(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void) -> usize,
        ptr: *mut c_void,
    ) -> usize {
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[cfg(not(target_vendor = "apple"))]
    #[inline]
    pub fn hook_memalign(
        &mut self,
        _original: extern "C" fn(alignment: usize, size: usize) -> *mut c_void,
        alignment: usize,
        size: usize,
    ) -> *mut c_void {
        log::trace!("hook_memalign");
        unsafe { self.allocator_mut().alloc(size, alignment) }
    }

    #[inline]
    pub fn hook_posix_memalign(
        &mut self,
        _original: extern "C" fn(pptr: *mut *mut c_void, alignment: usize, size: usize) -> i32,
        pptr: *mut *mut c_void,
        alignment: usize,
        size: usize,
    ) -> i32 {
        log::trace!("hook_posix_memalign");
        unsafe {
            *pptr = self.allocator_mut().alloc(size, alignment);
        }
        0
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    pub fn hook_malloc_usable_size(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void) -> usize,
        ptr: *mut c_void,
    ) -> usize {
        log::trace!("hook_malloc_usable_size");
        self.allocator_mut().get_usable_size(ptr)
    }
    #[inline]
    #[cfg(target_vendor = "apple")]
    pub fn hook_check_malloc_size(&mut self, ptr: *mut c_void) -> bool {
        self.allocator_mut().is_managed(ptr)
    }
    #[inline]
    #[cfg(target_vendor = "apple")]
    pub fn hook_malloc_size(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void) -> usize,
        ptr: *mut c_void,
    ) -> usize {
        self.allocator_mut().get_usable_size(ptr)
    }
    #[inline]
    #[cfg(target_vendor = "apple")]
    pub fn hook_check_malloc_good_size(&mut self, ptr: *mut c_void) -> bool {
        self.allocator_mut().is_managed(ptr)
    }
    #[inline]
    #[cfg(target_vendor = "apple")]
    pub fn hook_malloc_good_size(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void) -> usize,
        ptr: *mut c_void,
    ) -> usize {
        self.allocator_mut().get_usable_size(ptr)
    }
    #[inline]
    #[cfg(target_vendor = "apple")]
    pub fn hook_os_log_type_enabled(
        &mut self,
        _original: extern "C" fn(oslog: *mut c_void, r#type: u8) -> bool,
        _oslog: *mut c_void,
        r#_type: u8,
    ) -> bool {
        false
    }
    #[inline]
    #[cfg(target_vendor = "apple")]
    #[allow(clippy::too_many_arguments)]
    #[allow(non_snake_case)]
    pub fn hook__os_log_impl(
        &mut self,
        _original: extern "C" fn(
            dso: *const c_void,
            log: *mut c_void,
            r#type: u8,
            format: *const c_char,
            buf: *const u8,
            size: u32,
        ),
        _dso: *const c_void,
        _log: *mut c_void,
        r#_type: u8,
        _format: *const c_char,
        _buf: *const u8,
        _size: u32,
    ) {
    }
    #[inline]
    #[cfg(target_vendor = "apple")]
    #[allow(clippy::too_many_arguments)]
    #[allow(non_snake_case)]
    pub fn hook__os_log_fault_impl(
        &mut self,
        _original: extern "C" fn(
            dso: *const c_void,
            log: *mut c_void,
            r#type: u8,
            format: *const c_char,
            buf: *const u8,
            size: u32,
        ),
        _dso: *const c_void,
        _log: *mut c_void,
        r#_type: u8,
        _format: *const c_char,
        _buf: *const u8,
        _size: u32,
    ) {
    }
    #[inline]
    #[cfg(target_vendor = "apple")]
    #[allow(clippy::too_many_arguments)]
    #[allow(non_snake_case)]
    pub fn hook__os_log_error_impl(
        &mut self,
        _original: extern "C" fn(
            dso: *const c_void,
            log: *mut c_void,
            r#type: u8,
            format: *const c_char,
            buf: *const u8,
            size: u32,
        ),
        _dso: *const c_void,
        _log: *mut c_void,
        r#_type: u8,
        _format: *const c_char,
        _buf: *const u8,
        _size: u32,
    ) {
    }
    #[inline]
    #[cfg(target_vendor = "apple")]
    #[allow(clippy::too_many_arguments)]
    #[allow(non_snake_case)]
    pub fn hook__os_log_debug_impl(
        &mut self,
        _original: extern "C" fn(
            dso: *const c_void,
            log: *mut c_void,
            r#type: u8,
            format: *const c_char,
            buf: *const u8,
            size: u32,
        ),
        _dso: *const c_void,
        _log: *mut c_void,
        r#_type: u8,
        _format: *const c_char,
        _buf: *const u8,
        _size: u32,
    ) {
    }

    #[inline]
    #[expect(non_snake_case)]
    pub fn hook___cxa_allocate_exception(
        &mut self,
        _original: extern "C" fn(size: usize) -> *const c_void,
        size: usize,
    ) -> *const c_void {
        unsafe {
            self.allocator_mut()
                .alloc((size + 0x8f) & 0xfffffffffffffff0, 8)
                .add(0x80)
        }
    }
    #[inline]
    #[expect(non_snake_case)]
    pub fn hook___cxa_free_exception(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void) -> usize,
        ptr: *mut c_void,
    ) -> usize {
        unsafe {
            self.allocator_mut().release(ptr.sub(0x80));
        }
        0
    }
    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_MapViewOfFile(
        &mut self,
        original: extern "C" fn(
            handle: *const c_void,
            desired_access: u32,
            file_offset_high: u32,
            file_offset_low: u32,
            size: usize,
        ) -> *const c_void,
        _handle: *const c_void,
        _desired_access: u32,
        _file_offset_high: u32,
        _file_offset_low: u32,
        size: usize,
    ) -> *const c_void {
        log::trace!("hook_MapViewOfFile size {:?}", size);
        let ret = original(
            _handle,
            _desired_access,
            _file_offset_high,
            _file_offset_low,
            size,
        );

        let mut size = size;
        if size == 0 {
            // The entire file is mapped starting from the offset
            // We need to get the real size before unpoisoning it
            // Use VirtualQuery to get the size of the mapped memory
            let mut mem_info = MEMORY_BASIC_INFORMATION {
                BaseAddress: ptr::null_mut(),
                AllocationBase: ptr::null_mut(),
                AllocationProtect: 0,
                RegionSize: 0,
                State: 0,
                Protect: 0,
                Type: 0,
            };

            let result = unsafe {
                VirtualQuery(
                    ret as *const winapi::ctypes::c_void,
                    &mut mem_info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 {
                log::error!("Failed to query virtual memory");
            } else {
                size = mem_info.RegionSize;
            }
        }

        self.unpoison(ret as usize, size);
        log::trace!("hook_MapViewOfFile returns {:p}", ret);
        ret
    }

    #[inline]
    #[expect(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_UnmapViewOfFile(
        &mut self,
        original: extern "C" fn(ptr: *const c_void) -> bool,
        ptr: *const c_void,
    ) -> bool {
        log::info!("hook_UnmapViewOfFile {:p}", ptr);

        let mut size = 0;
        // We need to get the mapping size before poisoning it
        // Use VirtualQuery to get the size of the mapped memory
        let mut mem_info = MEMORY_BASIC_INFORMATION {
            BaseAddress: ptr::null_mut(),
            AllocationBase: ptr::null_mut(),
            AllocationProtect: 0,
            RegionSize: 0,
            State: 0,
            Protect: 0,
            Type: 0,
        };

        let result = unsafe {
            VirtualQuery(
                ptr as *const winapi::ctypes::c_void,
                &mut mem_info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            log::error!("Failed to query virtual memory for poisoning");
        } else {
            size = mem_info.RegionSize;
            log::info!("Size of mapped memory: {} bytes", size);
        }

        let ret = original(ptr);

        if size > 0 {
            unsafe { self.poison(ptr as usize, size) };
        }

        ret
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPv(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void) -> usize,
        ptr: *mut c_void,
    ) -> usize {
        log::trace!("delete[]");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvm(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, _ulong: u64) -> usize,
        ptr: *mut c_void,
        _ulong: u64,
    ) -> usize {
        log::trace!("delete[]");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvmSt11align_val_t(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, _ulong: u64, _alignment: usize) -> usize,
        ptr: *mut c_void,
        _ulong: u64,
        _alignment: usize,
    ) -> usize {
        log::trace!("delete[](void*, std::size_t)");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvRKSt9nothrow_t(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, _nothrow: *const c_void) -> usize,
        ptr: *mut c_void,
        _nothrow: *const c_void,
    ) -> usize {
        log::trace!("delete[](void*, std::size_t, std::align_val_t)");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvSt11align_val_tRKSt9nothrow_t(
        &mut self,
        _original: extern "C" fn(
            ptr: *mut c_void,
            _alignment: usize,
            _nothrow: *const c_void,
        ) -> usize,
        ptr: *mut c_void,
        _alignment: usize,
        _nothrow: *const c_void,
    ) -> usize {
        log::trace!("delete[](void*, std::nothrow_t const&)");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvSt11align_val_t(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, _alignment: usize) -> usize,
        ptr: *mut c_void,
        _alignment: usize,
    ) -> usize {
        log::trace!("delete[](void*, std::align_val_t)");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPv(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void) -> usize,
        ptr: *mut c_void,
    ) -> usize {
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvm(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, _ulong: u64) -> usize,
        ptr: *mut c_void,
        _ulong: u64,
    ) -> usize {
        log::trace!("delete(void*)");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvmSt11align_val_t(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, _ulong: u64, _alignment: usize) -> usize,
        ptr: *mut c_void,
        _ulong: u64,
        _alignment: usize,
    ) -> usize {
        log::trace!("delete(void*)");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvRKSt9nothrow_t(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, _nothrow: *const c_void) -> usize,
        ptr: *mut c_void,
        _nothrow: *const c_void,
    ) -> usize {
        log::trace!("delete(void*)");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvSt11align_val_tRKSt9nothrow_t(
        &mut self,
        _original: extern "C" fn(
            ptr: *mut c_void,
            _alignment: usize,
            _nothrow: *const c_void,
        ) -> usize,
        ptr: *mut c_void,
        _alignment: usize,
        _nothrow: *const c_void,
    ) -> usize {
        log::trace!("delete(void*)");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[expect(non_snake_case)]
    #[expect(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvSt11align_val_t(
        &mut self,
        _original: extern "C" fn(ptr: *mut c_void, _alignment: usize) -> usize,
        ptr: *mut c_void,
        _alignment: usize,
    ) -> usize {
        log::trace!("delete(void*)");
        if ptr != ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[inline]
    #[expect(clippy::too_many_arguments)]
    pub fn hook_mmap(
        &mut self,
        original: extern "C" fn(
            addr: *const c_void,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: usize,
        ) -> *mut c_void,
        addr: *const c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: usize,
    ) -> *mut c_void {
        log::trace!("hook_mmap");
        let res = original(addr, length, prot, flags, fd, offset);
        if !ptr::addr_eq(res, ptr::null_mut::<c_void>().wrapping_sub(1)) {
            self.allocator_mut()
                .map_shadow_for_region(res as usize, res as usize + length, true);
        }
        res
    }

    /// # Safety
    /// `addr` will get dereferenced.
    #[inline]
    pub unsafe fn hook_munmap(
        &mut self,
        original: extern "C" fn(addr: *const c_void, length: usize) -> i32,
        addr: *const c_void,
        length: usize,
    ) -> i32 {
        log::trace!("hook_munmap");
        let res = original(addr, length);
        if res != -1 {
            unsafe {
                Allocator::poison(self.allocator_mut().map_to_shadow(addr as usize), length);
            }
        }
        res
    }

    #[inline]
    #[expect(non_snake_case)]
    pub fn hook__write(
        &mut self,
        original: extern "C" fn(fd: i32, buf: *const c_void, count: usize) -> usize,
        fd: i32,
        buf: *const c_void,
        count: usize,
    ) -> usize {
        log::trace!("hook__write");
        self.hook_write(original, fd, buf, count)
    }
    #[inline]
    pub fn hook_write(
        &mut self,
        original: extern "C" fn(fd: i32, buf: *const c_void, count: usize) -> usize,
        fd: i32,
        buf: *const c_void,
        count: usize,
    ) -> usize {
        log::trace!("hook_write");
        if !self.allocator_mut().check_shadow(buf, count)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "write".to_string(),
                self.real_address_for_stalked(self.pc()),
                buf as usize,
                count,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(fd, buf, count)
    }

    #[inline]
    #[expect(non_snake_case)]
    pub fn hook__read(
        &mut self,
        original: extern "C" fn(fd: i32, buf: *mut c_void, count: usize) -> usize,
        fd: i32,
        buf: *mut c_void,
        count: usize,
    ) -> usize {
        log::trace!("hook__read");
        self.hook_read(original, fd, buf, count)
    }
    #[inline]
    pub fn hook_read(
        &mut self,
        original: extern "C" fn(fd: i32, buf: *mut c_void, count: usize) -> usize,
        fd: i32,
        buf: *mut c_void,
        count: usize,
    ) -> usize {
        log::trace!("hook_read");
        if !self.allocator_mut().check_shadow(buf, count)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "read".to_string(),
                self.real_address_for_stalked(self.pc()),
                buf as usize,
                count,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(fd, buf, count)
    }

    #[inline]
    pub fn hook_fgets(
        &mut self,
        original: extern "C" fn(s: *mut c_void, size: u32, stream: *mut c_void) -> *mut c_void,
        s: *mut c_void,
        size: u32,
        stream: *mut c_void,
    ) -> *mut c_void {
        log::trace!("hook_fgets");
        if !self.allocator_mut().check_shadow(s, size as usize)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "fgets".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                size as usize,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, size, stream)
    }

    #[inline]
    pub fn hook_memcmp(
        &mut self,
        original: extern "C" fn(s1: *const c_void, s2: *const c_void, n: usize) -> i32,
        s1: *const c_void,
        s2: *const c_void,
        n: usize,
    ) -> i32 {
        log::trace!("hook_memcmp");
        if !self.allocator_mut().check_shadow(s1, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(s2, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s1, s2, n)
    }

    #[inline]
    pub fn hook_memcpy(
        &mut self,
        original: extern "C" fn(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void,
        dest: *mut c_void,
        src: *const c_void,
        n: usize,
    ) -> *mut c_void {
        log::trace!("hook_memcpy dest {dest:#?} src {src:#?} size {n}");
        if !self.allocator_mut().check_shadow(dest, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(src, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(dest, src, n)
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    pub fn hook_mempcpy(
        &mut self,
        original: extern "C" fn(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void,
        dest: *mut c_void,
        src: *const c_void,
        n: usize,
    ) -> *mut c_void {
        log::trace!("hook_mempcpy");
        if !self.allocator_mut().check_shadow(dest, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "mempcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(src, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "mempcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(dest, src, n)
    }

    #[inline]
    pub fn hook_memmove(
        &mut self,
        original: extern "C" fn(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void,
        dest: *mut c_void,
        src: *const c_void,
        n: usize,
    ) -> *mut c_void {
        log::trace!("hook_memmove");
        if !self.allocator_mut().check_shadow(dest, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memmove".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(src, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memmove".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }

        original(dest, src, n)
    }

    #[inline]
    pub fn hook_memset(
        &mut self,
        original: extern "C" fn(dest: *mut c_void, c: i32, n: usize) -> *mut c_void,
        dest: *mut c_void,
        c: i32,
        n: usize,
    ) -> *mut c_void {
        log::trace!("hook_memset");
        if !self.allocator_mut().check_shadow(dest, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(dest, c, n)
    }

    #[inline]
    pub fn hook_memchr(
        &mut self,
        original: extern "C" fn(s: *mut c_void, c: i32, n: usize) -> *mut c_void,
        s: *mut c_void,
        c: i32,
        n: usize,
    ) -> *mut c_void {
        log::trace!("hook_memchr");
        if !self.allocator_mut().check_shadow(s, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memchr".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, c, n)
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    pub fn hook_memrchr(
        &mut self,
        original: extern "C" fn(s: *mut c_void, c: i32, n: usize) -> *mut c_void,
        s: *mut c_void,
        c: i32,
        n: usize,
    ) -> *mut c_void {
        log::trace!("hook_memrchr");
        if !self.allocator_mut().check_shadow(s, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memrchr".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, c, n)
    }

    #[inline]
    pub fn hook_memmem(
        &mut self,
        original: extern "C" fn(
            haystack: *const c_void,
            haystacklen: usize,
            needle: *const c_void,
            needlelen: usize,
        ) -> *mut c_void,
        haystack: *const c_void,
        haystacklen: usize,
        needle: *const c_void,
        needlelen: usize,
    ) -> *mut c_void {
        log::trace!("hook_memmem");
        if !self.allocator_mut().check_shadow(haystack, haystacklen)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memmem".to_string(),
                self.real_address_for_stalked(self.pc()),
                haystack as usize,
                haystacklen,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(needle, needlelen)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memmem".to_string(),
                self.real_address_for_stalked(self.pc()),
                needle as usize,
                needlelen,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(haystack, haystacklen, needle, needlelen)
    }

    #[cfg(not(target_os = "android"))]
    #[inline]
    pub fn hook_bzero(
        &mut self,
        original: extern "C" fn(s: *mut c_void, n: usize) -> usize,
        s: *mut c_void,
        n: usize,
    ) -> usize {
        log::trace!("hook_bzero");
        if !self.allocator_mut().check_shadow(s, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "bzero".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, n)
    }

    #[cfg(all(not(target_os = "android"), not(target_vendor = "apple")))]
    #[inline]
    pub fn hook_explicit_bzero(
        &mut self,
        original: extern "C" fn(s: *mut c_void, n: usize) -> usize,
        s: *mut c_void,
        n: usize,
    ) -> usize {
        log::trace!("hook_explicit_bzero");
        if !self.allocator_mut().check_shadow(s, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "explicit_bzero".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, n)
    }

    #[cfg(not(target_os = "android"))]
    #[inline]
    pub fn hook_bcmp(
        &mut self,
        original: extern "C" fn(s1: *const c_void, s2: *const c_void, n: usize) -> i32,
        s1: *const c_void,
        s2: *const c_void,
        n: usize,
    ) -> i32 {
        log::trace!("hook_bcmp");
        if !self.allocator_mut().check_shadow(s1, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(s2, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s1, s2, n)
    }

    #[inline]
    pub fn hook_strchr(
        &mut self,
        original: extern "C" fn(s: *mut c_char, c: i32) -> *mut c_char,
        s: *mut c_char,
        c: i32,
    ) -> *mut c_char {
        unsafe extern "system" {

            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_strchr");
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strchr".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, c)
    }

    #[inline]
    pub fn hook_strrchr(
        &mut self,
        original: extern "C" fn(s: *mut c_char, c: i32) -> *mut c_char,
        s: *mut c_char,
        c: i32,
    ) -> *mut c_char {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_strrchr");
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strrchr".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, c)
    }

    #[inline]
    pub fn hook_strcasecmp(
        &mut self,
        original: extern "C" fn(s1: *const c_char, s2: *const c_char) -> i32,
        s1: *const c_char,
        s2: *const c_char,
    ) -> i32 {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_strcasecmp");
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { strlen(s1) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { strlen(s2) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s1, s2)
    }

    #[inline]
    pub fn hook_strncasecmp(
        &mut self,
        original: extern "C" fn(s1: *const c_char, s2: *const c_char, n: usize) -> i32,
        s1: *const c_char,
        s2: *const c_char,
        n: usize,
    ) -> i32 {
        log::trace!("hook_strncasecmp");
        if !self.allocator_mut().check_shadow(s1 as *const c_void, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(s2 as *const c_void, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s1, s2, n)
    }

    #[inline]
    pub fn hook_strcat(
        &mut self,
        original: extern "C" fn(s1: *mut c_char, s2: *const c_char) -> *mut c_char,
        s1: *mut c_char,
        s2: *const c_char,
    ) -> *mut c_char {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_strcat");
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { strlen(s1) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { strlen(s2) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s1, s2)
    }

    #[inline]
    pub fn hook_strcmp(
        &mut self,
        original: extern "C" fn(s1: *const c_char, s2: *const c_char) -> i32,
        s1: *const c_char,
        s2: *const c_char,
    ) -> i32 {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_strcmp");
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { strlen(s1) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { strlen(s2) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s1, s2)
    }

    #[inline]
    pub fn hook_strncmp(
        &mut self,
        original: extern "C" fn(s1: *const c_char, s2: *const c_char, n: usize) -> i32,
        s1: *const c_char,
        s2: *const c_char,
        n: usize,
    ) -> i32 {
        unsafe extern "system" {
            fn strnlen(s: *const c_char, n: usize) -> usize;
        }
        log::trace!("hook_strncmp");
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { strnlen(s1, n) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { strnlen(s2, n) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s1, s2, n)
    }

    #[inline]
    pub fn hook_strcpy(
        &mut self,
        original: extern "C" fn(dest: *mut c_char, src: *const c_char) -> *mut c_char,
        dest: *mut c_char,
        src: *const c_char,
    ) -> *mut c_char {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_strcpy");
        if !self
            .allocator_mut()
            .check_shadow(dest as *const c_void, unsafe { strlen(src) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "strcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(src as *const c_void, unsafe { strlen(src) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(dest, src)
    }

    #[inline]
    pub fn hook_strncpy(
        &mut self,
        original: extern "C" fn(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char,
        dest: *mut c_char,
        src: *const c_char,
        n: usize,
    ) -> *mut c_char {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_strncpy");
        if !self.allocator_mut().check_shadow(dest as *const c_void, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "strncpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        let mn = core::cmp::min(n, unsafe { strlen(src) } + 1);
        if !self.allocator_mut().check_shadow(src as *const c_void, mn)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                mn,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(dest, src, n)
    }

    #[inline]
    pub fn hook_stpcpy(
        &mut self,
        original: extern "C" fn(dest: *mut c_char, src: *const c_char) -> *mut c_char,
        dest: *mut c_char,
        src: *const c_char,
    ) -> *mut c_char {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_stpcpy");
        if !self
            .allocator_mut()
            .check_shadow(dest as *const c_void, unsafe { strlen(src) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "stpcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(src as *const c_void, unsafe { strlen(src) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "stpcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(dest, src)
    }

    #[inline]
    #[expect(non_snake_case)]
    pub fn hook__strdup(
        &mut self,
        original: extern "C" fn(s: *const c_char) -> *mut c_char,
        s: *const c_char,
    ) -> *mut c_char {
        log::trace!("hook__strdup");
        self.hook_strdup(original, s)
    }
    #[inline]
    pub fn hook_strdup(
        &mut self,
        _original: extern "C" fn(s: *const c_char) -> *mut c_char,
        s: *const c_char,
    ) -> *mut c_char {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
            fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
        }
        log::trace!("hook_strdup");
        let size = unsafe { strlen(s) + 1 };
        if !self.allocator_mut().check_shadow(s as *const c_void, size)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strdup".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) + 1 },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }

        unsafe {
            let ret = self.allocator_mut().alloc(size, 8) as *mut c_char;
            strcpy(ret, s);
            ret
        }
    }

    #[inline]
    pub fn hook_strlen(
        &mut self,
        original: extern "C" fn(s: *const c_char) -> usize,
        s: *const c_char,
    ) -> usize {
        log::trace!("hook_strlen");
        let size = original(s);
        if !self.allocator_mut().check_shadow(s as *const c_void, size)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strlen".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                size,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        size
    }

    #[inline]
    pub fn hook_strnlen(
        &mut self,
        original: extern "C" fn(s: *const c_char, n: usize) -> usize,
        s: *const c_char,
        n: usize,
    ) -> usize {
        log::trace!("hook_strnlen");
        let size = original(s, n);
        if !self.allocator_mut().check_shadow(s as *const c_void, size)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strnlen".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                size,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        size
    }

    #[inline]
    pub fn hook_strstr(
        &mut self,
        original: extern "C" fn(haystack: *const c_char, needle: *const c_char) -> *mut c_char,
        haystack: *const c_char,
        needle: *const c_char,
    ) -> *mut c_char {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_strstr");
        if !self
            .allocator_mut()
            .check_shadow(haystack as *const c_void, unsafe { strlen(haystack) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strstr".to_string(),
                self.real_address_for_stalked(self.pc()),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(needle as *const c_void, unsafe { strlen(needle) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strstr".to_string(),
                self.real_address_for_stalked(self.pc()),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(haystack, needle)
    }

    #[inline]
    pub fn hook_strcasestr(
        &mut self,
        original: extern "C" fn(haystack: *const c_char, needle: *const c_char) -> *mut c_char,
        haystack: *const c_char,
        needle: *const c_char,
    ) -> *mut c_char {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_strcasestr");
        if !self
            .allocator_mut()
            .check_shadow(haystack as *const c_void, unsafe { strlen(haystack) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcasestr".to_string(),
                self.real_address_for_stalked(self.pc()),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(needle as *const c_void, unsafe { strlen(needle) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcasestr".to_string(),
                self.real_address_for_stalked(self.pc()),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(haystack, needle)
    }

    #[inline]
    pub fn hook_atoi(
        &mut self,
        original: extern "C" fn(s: *const c_char) -> i32,
        s: *const c_char,
    ) -> i32 {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_atoi");
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "atoi".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s)
    }

    /// Hooks `atol`
    #[inline]
    pub fn hook_atol(
        &mut self,
        original: extern "C" fn(s: *const c_char) -> i32,
        s: *const c_char,
    ) -> i32 {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_atol");
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "atol".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s)
    }

    /// Hooks `atoll`
    #[inline]
    pub fn hook_atoll(
        &mut self,
        original: extern "C" fn(s: *const c_char) -> i64,
        s: *const c_char,
    ) -> i64 {
        unsafe extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        log::trace!("hook_atoll");
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "atoll".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s)
    }

    /// Hooks `wcslen`
    #[inline]
    pub fn hook_wcslen(
        &mut self,
        original: extern "C" fn(s: *const wchar_t) -> usize,
        s: *const wchar_t,
    ) -> usize {
        log::trace!("hook_wcslen");
        let size = original(s);
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, (size + 1) * 2)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "wcslen".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                (size + 1) * 2,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        size
    }

    /// Hooks `wcscpy`
    #[inline]
    pub fn hook_wcscpy(
        &mut self,
        original: extern "C" fn(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t,
        dest: *mut wchar_t,
        src: *const wchar_t,
    ) -> *mut wchar_t {
        unsafe extern "system" {
            fn wcslen(s: *const wchar_t) -> usize;
        }
        log::trace!("hook_wcscpy");
        if !self
            .allocator_mut()
            .check_shadow(dest as *const c_void, unsafe { (wcslen(src) + 1) * 2 })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "wcscpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                (unsafe { wcslen(src) } + 1) * 2,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(src as *const c_void, unsafe { (wcslen(src) + 1) * 2 })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "wcscpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                (unsafe { wcslen(src) } + 1) * 2,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(dest, src)
    }

    /// Hooks `wcscmp`
    #[inline]
    pub fn hook_wcscmp(
        &mut self,
        original: extern "C" fn(s1: *const wchar_t, s2: *const wchar_t) -> i32,
        s1: *const wchar_t,
        s2: *const wchar_t,
    ) -> i32 {
        unsafe extern "system" {
            fn wcslen(s: *const wchar_t) -> usize;
        }
        log::trace!("hook_wcscmp");
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { (wcslen(s1) + 1) * 2 })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                (unsafe { wcslen(s1) } + 1) * 2,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { (wcslen(s2) + 1) * 2 })
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                (unsafe { wcslen(s2) } + 1) * 2,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s1, s2)
    }

    #[cfg(target_vendor = "apple")]
    #[inline]
    pub fn hook_memset_pattern4(
        &mut self,
        original: extern "C" fn(s: *mut c_void, p4: *const c_void, n: usize),
        s: *mut c_void,
        p4: *const c_void,
        n: usize,
    ) {
        if !self.allocator_mut().check_shadow(s, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern4".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(p4, n / 4)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern4".to_string(),
                self.real_address_for_stalked(self.pc()),
                p4 as usize,
                n / 4,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, p4, n);
    }

    #[cfg(target_vendor = "apple")]
    #[inline]
    pub fn hook_memset_pattern8(
        &mut self,
        original: extern "C" fn(s: *mut c_void, p8: *const c_void, n: usize),
        s: *mut c_void,
        p8: *const c_void,
        n: usize,
    ) {
        if !self.allocator_mut().check_shadow(s, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern8".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(p8, n / 8)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern8".to_string(),
                self.real_address_for_stalked(self.pc()),
                p8 as usize,
                n / 8,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, p8, n);
    }

    #[cfg(target_vendor = "apple")]
    #[inline]
    pub fn hook_memset_pattern16(
        &mut self,
        original: extern "C" fn(s: *mut c_void, p16: *const c_void, n: usize),
        s: *mut c_void,
        p16: *const c_void,
        n: usize,
    ) {
        if !self.allocator_mut().check_shadow(s, n)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern16".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        if !self.allocator_mut().check_shadow(p16, n / 16)
            && AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern16".to_string(),
                self.real_address_for_stalked(self.pc()),
                p16 as usize,
                n / 16,
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        original(s, p16, n);
    }
}
