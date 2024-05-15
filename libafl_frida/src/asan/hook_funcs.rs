//! The allocator hooks for address sanitizer.
use std::ffi::c_void;

use backtrace::Backtrace;
use libc::{c_char, wchar_t};

use crate::{
    alloc::Allocator,
    asan::{
        asan_rt::AsanRuntime,
        errors::{AsanError, AsanErrors},
    },
};

#[allow(clippy::not_unsafe_ptr_arg_deref)]
impl AsanRuntime {
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_NtGdiCreateCompatibleDC(&mut self, _hdc: *const c_void) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(8, 8) }
    }

    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_CreateThread(
        &mut self,
        thread_attributes: *const c_void,
        stack_size: usize,
        start_address: *const c_void,
        parameter: *const c_void,
        creation_flags: i32,
        thread_id: *mut i32,
    ) -> usize {
        extern "system" {
            fn CreateThread(
                thread_attributes: *const c_void,
                stack_size: usize,
                start_address: *const c_void,
                parameter: *const c_void,
                creation_flags: i32,
                thread_id: *mut i32,
            ) -> usize;
        }
        unsafe {
            CreateThread(
                thread_attributes,
                stack_size,
                start_address,
                parameter,
                creation_flags,
                thread_id,
            )
        }
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_CreateFileMappingW(
        &mut self,
        file: usize,
        file_mapping_attributes: *const c_void,
        protect: i32,
        maximum_size_high: u32,
        maximum_size_low: u32,
        name: *const c_void,
    ) -> usize {
        extern "system" {
            fn CreateFileMappingW(
                file: usize,
                file_mapping_attributes: *const c_void,
                protect: i32,
                maximum_size_high: u32,
                maximum_size_low: u32,
                name: *const c_void,
            ) -> usize;
        }
        winsafe::OutputDebugString("In CreateFileMapping\n");
        unsafe {
            CreateFileMappingW(
                file,
                file_mapping_attributes,
                protect,
                maximum_size_high,
                maximum_size_low,
                name,
            )
        }
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LdrLoadDll(
        &mut self,
        search_path: *const c_void,
        charecteristics: *const u32,
        dll_name: *const c_void,
        base_address: *mut *const c_void,
    ) -> usize {
        extern "system" {
            fn LdrLoadDll(
                search_path: *const c_void,
                charecteristics: *const u32,
                dll_name: *const c_void,
                base_address: *mut *const c_void,
            ) -> usize;
        }
        winsafe::OutputDebugString("LdrLoadDll");
        log::trace!("LdrLoadDll");
        let result = unsafe { LdrLoadDll(search_path, charecteristics, dll_name, base_address) };
        self.allocator_mut().unpoison_all_existing_memory();
        result
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LdrpCallInitRoutine(
        &mut self,
        _base_address: *const c_void,
        _reason: usize,
        _context: usize,
        _entry_point: usize,
    ) -> usize {
        winsafe::OutputDebugString("LdrpCallInitRoutine");
        // let result = unsafe { LdrLoadDll(path, file, flags,x )};
        // self.allocator_mut().unpoison_all_existing_memory();
        // result
        0
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LoadLibraryExW(&mut self, path: *const c_void, file: usize, flags: i32) -> usize {
        log::trace!("Loaded library!");
        extern "system" {
            fn LoadLibraryExW(path: *const c_void, file: usize, flags: i32) -> usize;
        }
        let result = unsafe { LoadLibraryExW(path, file, flags) };
        self.allocator_mut().unpoison_all_existing_memory();
        result
    }

    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlCreateHeap(
        &mut self,
        _flags: u32,
        _heap_base: *const c_void,
        _reserve_size: usize,
        _commit_size: usize,
        _lock: *const c_void,
        _parameters: *const c_void,
    ) -> *mut c_void {
        0xc0debeef as *mut c_void
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlDestroyHeap(&mut self, _handle: *const c_void) -> *mut c_void {
        std::ptr::null_mut()
    }

    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_HeapAlloc(&mut self, _handle: *mut c_void, flags: u32, size: usize) -> *mut c_void {
        let allocator = self.allocator_mut();
        let ret = unsafe { allocator.alloc(size, 8) };

        if flags & 8 == 8 {
            extern "system" {
                fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
            }
            unsafe {
                memset(ret, 0, size);
            }
        }
        if flags & 4 == 4 && ret == std::ptr::null_mut() {
            unimplemented!();
        }
        ret
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlAllocateHeap(
        &mut self,
        _handle: *mut c_void,
        flags: u32,
        size: usize,
    ) -> *mut c_void {
        let allocator = self.allocator_mut();
        let ret = unsafe { allocator.alloc(size, 8) };

        if flags & 8 == 8 {
            extern "system" {
                fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
            }
            unsafe {
                memset(ret, 0, size);
            }
        }
        if flags & 4 == 4 && ret == std::ptr::null_mut() {
            unimplemented!();
        }
        ret
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_HeapReAlloc(
        &mut self,
        handle: *mut c_void,
        flags: u32,
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        let allocator = self.allocator_mut();
        if !allocator.is_managed(ptr) {
            extern "system" {
                fn HeapReAlloc(
                    handle: *mut c_void,
                    flags: u32,
                    ptr: *mut c_void,
                    size: usize,
                ) -> *mut c_void;
            }
            return unsafe { HeapReAlloc(handle, flags, ptr, size) };
        }
        let ret = unsafe {
            let ret = allocator.alloc(size, 8);
            extern "system" {
                fn memcpy(dst: *mut c_void, src: *const c_void, size: usize) -> *mut c_void;
            }
            memcpy(ret as *mut c_void, ptr, allocator.get_usable_size(ptr));
            allocator.release(ptr);
            ret
        };

        if flags & 8 == 8 {
            extern "system" {
                fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
            }
            unsafe {
                memset(ret, 0, size);
            }
        }
        if flags & 4 == 4 && ret == std::ptr::null_mut() {
            unimplemented!();
        }
        if flags & 0x10 == 0x10 && ret != ptr {
            unimplemented!();
        }
        ret
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlReAllocateHeap(
        &mut self,
        handle: *mut c_void,
        flags: u32,
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        let allocator = self.allocator_mut();
        log::trace!("RtlReAllocateHeap({ptr:?}, {size:x})");
        if !allocator.is_managed(ptr) {
            extern "system" {
                fn HeapReAlloc(
                    handle: *mut c_void,
                    flags: u32,
                    ptr: *mut c_void,
                    size: usize,
                ) -> *mut c_void;
            }
            return unsafe { HeapReAlloc(handle, flags, ptr, size) };
        }
        let ret = unsafe {
            let ret = allocator.alloc(size, 8);
            extern "system" {
                fn memcpy(dst: *mut c_void, src: *const c_void, size: usize) -> *mut c_void;
            }
            memcpy(ret as *mut c_void, ptr, allocator.get_usable_size(ptr));
            allocator.release(ptr);
            ret
        };

        if flags & 8 == 8 {
            extern "system" {
                fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
            }
            unsafe {
                memset(ret, 0, size);
            }
        }
        if flags & 4 == 4 && ret == std::ptr::null_mut() {
            unimplemented!();
        }
        if flags & 0x10 == 0x10 && ret != ptr {
            unimplemented!();
        }
        ret
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_RtlFreeHeap(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        self.allocator_mut().is_managed(ptr)
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlFreeHeap(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> usize {
        unsafe { self.allocator_mut().release(ptr) };
        0
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_HeapFree(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        self.allocator_mut().is_managed(ptr)
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_HeapFree(&mut self, _handle: *mut c_void, _flags: u32, ptr: *mut c_void) -> bool {
        unsafe { self.allocator_mut().release(ptr) };
        true
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_HeapSize(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        self.allocator_mut().is_managed(ptr)
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_HeapSize(&mut self, _handle: *mut c_void, _flags: u32, ptr: *mut c_void) -> usize {
        self.allocator().get_usable_size(ptr)
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_RtlSizeHeap(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        self.allocator_mut().is_managed(ptr)
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlSizeHeap(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> usize {
        self.allocator().get_usable_size(ptr)
    }
    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_RtlValidateHeap(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        ptr: *mut c_void,
    ) -> bool {
        self.allocator_mut().is_managed(ptr)
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_RtlValidateHeap(
        &mut self,
        _handle: *mut c_void,
        _flags: u32,
        _ptr: *mut c_void,
    ) -> bool {
        true
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalAlloc(&mut self, flags: u32, size: usize) -> *mut c_void {
        let ret = unsafe { self.allocator_mut().alloc(size, 8) };

        if flags & 0x40 == 0x40 {
            extern "system" {
                fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
            }
            unsafe {
                memset(ret, 0, size);
            }
        }
        ret
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalReAlloc(&mut self, mem: *mut c_void, size: usize, _flags: u32) -> *mut c_void {
        unsafe {
            let ret = self.allocator_mut().alloc(size, 0x8);
            if mem != std::ptr::null_mut() && ret != std::ptr::null_mut() {
                let old_size = self.allocator_mut().get_usable_size(mem);
                let copy_size = if size < old_size { size } else { old_size };
                (mem as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator_mut().release(mem);
            ret
        }
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalFree(&mut self, mem: *mut c_void) -> bool {
        let res = self.allocator_mut().is_managed(mem);
        res
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalFree(&mut self, mem: *mut c_void) -> *mut c_void {
        unsafe { self.allocator_mut().release(mem) };
        mem
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalHandle(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalHandle(&mut self, mem: *mut c_void) -> *mut c_void {
        mem
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalLock(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalLock(&mut self, mem: *mut c_void) -> *mut c_void {
        mem
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalUnlock(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalUnlock(&mut self, _mem: *mut c_void) -> bool {
        false
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalSize(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalSize(&mut self, mem: *mut c_void) -> usize {
        self.allocator_mut().get_usable_size(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_LocalFlags(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_LocalFlags(&mut self, _mem: *mut c_void) -> u32 {
        0
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalAlloc(&mut self, flags: u32, size: usize) -> *mut c_void {
        let ret = unsafe { self.allocator_mut().alloc(size, 8) };

        if flags & 0x40 == 0x40 {
            extern "system" {
                fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
            }
            unsafe {
                memset(ret, 0, size);
            }
        }
        ret
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalReAlloc(
        &mut self,
        mem: *mut c_void,
        _flags: u32,
        size: usize,
    ) -> *mut c_void {
        unsafe {
            let ret = self.allocator_mut().alloc(size, 0x8);
            if mem != std::ptr::null_mut() && ret != std::ptr::null_mut() {
                let old_size = self.allocator_mut().get_usable_size(mem);
                let copy_size = if size < old_size { size } else { old_size };
                (mem as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator_mut().release(mem);
            ret
        }
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalFree(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalFree(&mut self, mem: *mut c_void) -> *mut c_void {
        unsafe { self.allocator_mut().release(mem) };
        mem
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalHandle(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalHandle(&mut self, mem: *mut c_void) -> *mut c_void {
        mem
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalLock(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }

    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalLock(&mut self, mem: *mut c_void) -> *mut c_void {
        mem
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalUnlock(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalUnlock(&mut self, _mem: *mut c_void) -> bool {
        false
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalSize(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalSize(&mut self, mem: *mut c_void) -> usize {
        self.allocator_mut().get_usable_size(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_check_GlobalFlags(&mut self, mem: *mut c_void) -> bool {
        self.allocator_mut().is_managed(mem)
    }
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_GlobalFlags(&mut self, _mem: *mut c_void) -> u32 {
        0
    }

    #[inline]
    pub fn hook_malloc(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, 8) }
    }

    #[inline]
    pub fn hook_o_malloc(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__Znam(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__ZnamRKSt9nothrow_t(
        &mut self,
        size: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__ZnamSt11align_val_t(&mut self, size: usize, alignment: usize) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, alignment) }
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__ZnamSt11align_val_tRKSt9nothrow_t(
        &mut self,
        size: usize,
        alignment: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, alignment) }
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__Znwm(&mut self, size: usize) -> *mut c_void {
        let result = unsafe { self.allocator_mut().alloc(size, 8) };
        if result.is_null() {
            extern "system" {
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

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__ZnwmRKSt9nothrow_t(
        &mut self,
        size: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__ZnwmSt11align_val_t(&mut self, size: usize, alignment: usize) -> *mut c_void {
        let result = unsafe { self.allocator_mut().alloc(size, alignment) };
        if result.is_null() {
            extern "system" {
                fn _ZSt17__throw_bad_allocv();
            }

            unsafe {
                _ZSt17__throw_bad_allocv();
            }
        }
        result
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__ZnwmSt11align_val_tRKSt9nothrow_t(
        &mut self,
        size: usize,
        alignment: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, alignment) }
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__o_malloc(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, 8) }
    }
    #[inline]
    pub fn hook_calloc(&mut self, nmemb: usize, size: usize) -> *mut c_void {
        extern "system" {
            fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        let ret = unsafe { self.allocator_mut().alloc(size * nmemb, 8) };
        unsafe {
            memset(ret, 0, size * nmemb);
        }
        ret
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook__o_calloc(&mut self, nmemb: usize, size: usize) -> *mut c_void {
        extern "system" {
            fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        let ret = unsafe { self.allocator_mut().alloc(size * nmemb, 8) };
        unsafe {
            memset(ret, 0, size * nmemb);
        }
        ret
    }

    #[allow(non_snake_case)]
    #[inline]
    #[allow(clippy::cmp_null)]
    pub fn hook_realloc(&mut self, ptr: *mut c_void, size: usize) -> *mut c_void {
        unsafe {
            let ret = self.allocator_mut().alloc(size, 0x8);
            if ptr != std::ptr::null_mut() && ret != std::ptr::null_mut() {
                let old_size = self.allocator_mut().get_usable_size(ptr);
                let copy_size = if size < old_size { size } else { old_size };
                (ptr as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator_mut().release(ptr);
            ret
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[allow(clippy::cmp_null)]
    pub fn hook__o_realloc(&mut self, ptr: *mut c_void, size: usize) -> *mut c_void {
        unsafe {
            let ret = self.allocator_mut().alloc(size, 0x8);
            if ptr != std::ptr::null_mut() && ret != std::ptr::null_mut() {
                let old_size = self.allocator_mut().get_usable_size(ptr);
                let copy_size = if size < old_size { size } else { old_size };
                (ptr as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator_mut().release(ptr);
            ret
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    pub fn hook_check__o_free(&mut self, ptr: *mut c_void) -> bool {
        self.allocator_mut().is_managed(ptr)
    }

    #[allow(non_snake_case)]
    #[inline]
    #[allow(clippy::cmp_null)]
    pub fn hook__o_free(&mut self, ptr: *mut c_void) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }
    #[inline]
    pub fn hook_check_free(&mut self, ptr: *mut c_void) -> bool {
        self.allocator_mut().is_managed(ptr)
    }

    #[inline]
    #[allow(clippy::cmp_null)]
    pub fn hook_free(&mut self, ptr: *mut c_void) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[cfg(not(target_vendor = "apple"))]
    #[inline]
    pub fn hook_memalign(&mut self, alignment: usize, size: usize) -> *mut c_void {
        unsafe { self.allocator_mut().alloc(size, alignment) }
    }

    #[inline]
    pub fn hook_posix_memalign(
        &mut self,
        pptr: *mut *mut c_void,
        alignment: usize,
        size: usize,
    ) -> i32 {
        unsafe {
            *pptr = self.allocator_mut().alloc(size, alignment);
        }
        0
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    pub fn hook_malloc_usable_size(&mut self, ptr: *mut c_void) -> usize {
        self.allocator_mut().get_usable_size(ptr)
    }

    #[inline]
    #[allow(non_snake_case)]
    #[cfg(windows)]
    pub fn hook_MapViewOfFile(
        &mut self,
        _handle: *const c_void,
        _desired_access: u32,
        _file_offset_high: u32,
        _file_offset_low: u32,
        size: usize,
    ) -> *const c_void {
        let original: extern "C" fn(*const c_void, u32, u32, u32, usize) -> *const c_void =
            unsafe { std::mem::transmute(self.hooks.get(&"MapViewOfFile".to_string()).unwrap().0) };
        let ret = (original)(
            _handle,
            _desired_access,
            _file_offset_high,
            _file_offset_low,
            size,
        );
        self.unpoison(ret as usize, size);
        ret
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPv(&mut self, ptr: *mut c_void) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvm(&mut self, ptr: *mut c_void, _ulong: u64) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvmSt11align_val_t(
        &mut self,
        ptr: *mut c_void,
        _ulong: u64,
        _alignment: usize,
    ) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvRKSt9nothrow_t(
        &mut self,
        ptr: *mut c_void,
        _nothrow: *const c_void,
    ) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvSt11align_val_tRKSt9nothrow_t(
        &mut self,
        ptr: *mut c_void,
        _alignment: usize,
        _nothrow: *const c_void,
    ) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdaPvSt11align_val_t(&mut self, ptr: *mut c_void, _alignment: usize) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPv(&mut self, ptr: *mut c_void) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvm(&mut self, ptr: *mut c_void, _ulong: u64) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvmSt11align_val_t(
        &mut self,
        ptr: *mut c_void,
        _ulong: u64,
        _alignment: usize,
    ) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvRKSt9nothrow_t(
        &mut self,
        ptr: *mut c_void,
        _nothrow: *const c_void,
    ) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvSt11align_val_tRKSt9nothrow_t(
        &mut self,
        ptr: *mut c_void,
        _alignment: usize,
        _nothrow: *const c_void,
    ) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    pub fn hook__ZdlPvSt11align_val_t(&mut self, ptr: *mut c_void, _alignment: usize) -> usize {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator_mut().release(ptr) }
        }
        0
    }

    #[inline]
    pub fn hook_mmap(
        &mut self,
        addr: *const c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: usize,
    ) -> *mut c_void {
        extern "system" {
            fn mmap(
                addr: *const c_void,
                length: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: usize,
            ) -> *mut c_void;
        }
        let res = unsafe { mmap(addr, length, prot, flags, fd, offset) };
        if res != (-1_isize as *mut c_void) {
            self.allocator_mut()
                .map_shadow_for_region(res as usize, res as usize + length, true);
        }
        res
    }

    #[inline]
    pub fn hook_munmap(&mut self, addr: *const c_void, length: usize) -> i32 {
        extern "system" {
            fn munmap(addr: *const c_void, length: usize) -> i32;
        }
        let res = unsafe { munmap(addr, length) };
        if res != -1 {
            Allocator::poison(self.allocator_mut().map_to_shadow(addr as usize), length);
        }
        res
    }

    #[inline]
    #[allow(non_snake_case)]
    pub fn hook__write(&mut self, fd: i32, buf: *const c_void, count: usize) -> usize {
        self.hook_write(fd, buf, count)
    }
    #[inline]
    pub fn hook_write(&mut self, fd: i32, buf: *const c_void, count: usize) -> usize {
        extern "system" {
            fn write(fd: i32, buf: *const c_void, count: usize) -> usize;
        }
        if !self.allocator_mut().check_shadow(buf, count) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "write".to_string(),
                self.real_address_for_stalked(self.pc()),
                buf as usize,
                count,
                Backtrace::new(),
            )));
        }
        unsafe { write(fd, buf, count) }
    }

    #[inline]
    #[allow(non_snake_case)]
    pub fn hook__read(&mut self, fd: i32, buf: *mut c_void, count: usize) -> usize {
        self.hook_read(fd, buf, count)
    }
    #[inline]
    pub fn hook_read(&mut self, fd: i32, buf: *mut c_void, count: usize) -> usize {
        extern "system" {
            fn read(fd: i32, buf: *mut c_void, count: usize) -> usize;
        }
        if !self.allocator_mut().check_shadow(buf, count) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "read".to_string(),
                self.real_address_for_stalked(self.pc()),
                buf as usize,
                count,
                Backtrace::new(),
            )));
        }
        unsafe { read(fd, buf, count) }
    }

    #[inline]
    pub fn hook_fgets(&mut self, s: *mut c_void, size: u32, stream: *mut c_void) -> *mut c_void {
        extern "system" {
            fn fgets(s: *mut c_void, size: u32, stream: *mut c_void) -> *mut c_void;
        }
        if !self.allocator_mut().check_shadow(s, size as usize) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "fgets".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                size as usize,
                Backtrace::new(),
            )));
        }
        unsafe { fgets(s, size, stream) }
    }

    #[inline]
    pub fn hook_memcmp(&mut self, s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        extern "system" {
            fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
        }
        if !self.allocator_mut().check_shadow(s1, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(s2, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memcmp(s1, s2, n) }
    }

    #[inline]
    pub fn hook_memcpy(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "system" {
            fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !self.allocator_mut().check_shadow(dest, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(src, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memcpy(dest, src, n) }
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    pub fn hook_mempcpy(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "system" {
            fn mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !self.allocator_mut().check_shadow(dest, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "mempcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(src, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "mempcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { mempcpy(dest, src, n) }
    }

    #[inline]
    pub fn hook_memmove(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "system" {
            fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !self.allocator_mut().check_shadow(dest, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memmove".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(src, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memmove".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }

        unsafe { memmove(dest, src, n) }
    }

    #[inline]
    pub fn hook_memset(&mut self, dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "system" {
            fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !self.allocator_mut().check_shadow(dest, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memset(dest, c, n) }
    }

    #[inline]
    pub fn hook_memchr(&mut self, s: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "system" {
            fn memchr(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !self.allocator_mut().check_shadow(s, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memchr".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memchr(s, c, n) }
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    pub fn hook_memrchr(&mut self, s: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "system" {
            fn memrchr(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !self.allocator_mut().check_shadow(s, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memrchr".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memrchr(s, c, n) }
    }

    #[inline]
    pub fn hook_memmem(
        &mut self,
        haystack: *const c_void,
        haystacklen: usize,
        needle: *const c_void,
        needlelen: usize,
    ) -> *mut c_void {
        extern "system" {
            fn memmem(
                haystack: *const c_void,
                haystacklen: usize,
                needle: *const c_void,
                needlelen: usize,
            ) -> *mut c_void;
        }
        if !self.allocator_mut().check_shadow(haystack, haystacklen) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memmem".to_string(),
                self.real_address_for_stalked(self.pc()),
                haystack as usize,
                haystacklen,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(needle, needlelen) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "memmem".to_string(),
                self.real_address_for_stalked(self.pc()),
                needle as usize,
                needlelen,
                Backtrace::new(),
            )));
        }
        unsafe { memmem(haystack, haystacklen, needle, needlelen) }
    }

    #[cfg(not(target_os = "android"))]
    #[inline]
    pub fn hook_bzero(&mut self, s: *mut c_void, n: usize) -> usize {
        extern "system" {
            fn bzero(s: *mut c_void, n: usize) -> usize;
        }
        if !self.allocator_mut().check_shadow(s, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "bzero".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { bzero(s, n) }
    }

    #[cfg(all(not(target_os = "android"), not(target_vendor = "apple")))]
    #[inline]
    pub fn hook_explicit_bzero(&mut self, s: *mut c_void, n: usize) -> usize {
        extern "system" {
            fn explicit_bzero(s: *mut c_void, n: usize) -> usize;
        }
        if !self.allocator_mut().check_shadow(s, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "explicit_bzero".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { explicit_bzero(s, n) }
    }

    #[cfg(not(target_os = "android"))]
    #[inline]
    pub fn hook_bcmp(&mut self, s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        extern "system" {
            fn bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
        }
        if !self.allocator_mut().check_shadow(s1, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(s2, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { bcmp(s1, s2, n) }
    }

    #[inline]
    pub fn hook_strchr(&mut self, s: *mut c_char, c: i32) -> *mut c_char {
        extern "system" {
            fn strchr(s: *mut c_char, c: i32) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strchr".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { strchr(s, c) }
    }

    #[inline]
    pub fn hook_strrchr(&mut self, s: *mut c_char, c: i32) -> *mut c_char {
        extern "system" {
            fn strrchr(s: *mut c_char, c: i32) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strrchr".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { strrchr(s, c) }
    }

    #[inline]
    pub fn hook_strcasecmp(&mut self, s1: *const c_char, s2: *const c_char) -> i32 {
        extern "system" {
            fn strcasecmp(s1: *const c_char, s2: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { strlen(s1) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { strlen(s2) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcasecmp(s1, s2) }
    }

    #[inline]
    pub fn hook_strncasecmp(&mut self, s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
        extern "system" {
            fn strncasecmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32;
        }
        if !self.allocator_mut().check_shadow(s1 as *const c_void, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(s2 as *const c_void, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncasecmp(s1, s2, n) }
    }

    #[inline]
    pub fn hook_strcat(&mut self, s1: *mut c_char, s2: *const c_char) -> *mut c_char {
        extern "system" {
            fn strcat(s1: *mut c_char, s2: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { strlen(s1) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { strlen(s2) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcat(s1, s2) }
    }

    #[inline]
    pub fn hook_strcmp(&mut self, s1: *const c_char, s2: *const c_char) -> i32 {
        extern "system" {
            fn strcmp(s1: *const c_char, s2: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { strlen(s1) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { strlen(s2) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcmp(s1, s2) }
    }

    #[inline]
    pub fn hook_strncmp(&mut self, s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
        extern "system" {
            fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32;
            fn strnlen(s: *const c_char, n: usize) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { strnlen(s1, n) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { strnlen(s2, n) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncmp(s1, s2, n) }
    }

    #[inline]
    pub fn hook_strcpy(&mut self, dest: *mut c_char, src: *const c_char) -> *mut c_char {
        extern "system" {
            fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(dest as *const c_void, unsafe { strlen(src) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "strcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(src as *const c_void, unsafe { strlen(src) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        unsafe { strcpy(dest, src) }
    }

    #[inline]
    pub fn hook_strncpy(&mut self, dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
        extern "system" {
            fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char;
        }
        if !self.allocator_mut().check_shadow(dest as *const c_void, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "strncpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(src as *const c_void, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strncpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncpy(dest, src, n) }
    }

    #[inline]
    pub fn hook_stpcpy(&mut self, dest: *mut c_char, src: *const c_char) -> *mut c_char {
        extern "system" {
            fn stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(dest as *const c_void, unsafe { strlen(src) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "stpcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(src as *const c_void, unsafe { strlen(src) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "stpcpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        unsafe { stpcpy(dest, src) }
    }

    #[inline]
    #[allow(non_snake_case)]
    pub fn hook__strdup(&mut self, s: *const c_char) -> *mut c_char {
        self.hook_strdup(s)
    }
    #[inline]
    pub fn hook_strdup(&mut self, s: *const c_char) -> *mut c_char {
        extern "system" {
            fn strlen(s: *const c_char) -> usize;
            fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
        }
        let size = unsafe { strlen(s) };
        if !self.allocator_mut().check_shadow(s as *const c_void, size) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strdup".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }

        unsafe {
            let ret = self.allocator_mut().alloc(size, 8) as *mut c_char;
            strcpy(ret, s);
            ret
        }
    }

    #[inline]
    pub fn hook_strlen(&mut self, s: *const c_char) -> usize {
        extern "system" {
            fn strlen(s: *const c_char) -> usize;
        }
        let size = unsafe { strlen(s) };
        if !self.allocator_mut().check_shadow(s as *const c_void, size) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strlen".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                size,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
    pub fn hook_strnlen(&mut self, s: *const c_char, n: usize) -> usize {
        extern "system" {
            fn strnlen(s: *const c_char, n: usize) -> usize;
        }
        let size = unsafe { strnlen(s, n) };
        if !self.allocator_mut().check_shadow(s as *const c_void, size) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strnlen".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                size,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
    pub fn hook_strstr(&mut self, haystack: *const c_char, needle: *const c_char) -> *mut c_char {
        extern "system" {
            fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(haystack as *const c_void, unsafe { strlen(haystack) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strstr".to_string(),
                self.real_address_for_stalked(self.pc()),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(needle as *const c_void, unsafe { strlen(needle) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strstr".to_string(),
                self.real_address_for_stalked(self.pc()),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )));
        }
        unsafe { strstr(haystack, needle) }
    }

    #[inline]
    pub fn hook_strcasestr(
        &mut self,
        haystack: *const c_char,
        needle: *const c_char,
    ) -> *mut c_char {
        extern "system" {
            fn strcasestr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(haystack as *const c_void, unsafe { strlen(haystack) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcasestr".to_string(),
                self.real_address_for_stalked(self.pc()),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(needle as *const c_void, unsafe { strlen(needle) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "strcasestr".to_string(),
                self.real_address_for_stalked(self.pc()),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )));
        }
        unsafe { strcasestr(haystack, needle) }
    }

    #[inline]
    pub fn hook_atoi(&mut self, s: *const c_char) -> i32 {
        extern "system" {
            fn atoi(s: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "atoi".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atoi(s) }
    }

    /// Hooks `atol`
    #[inline]
    pub fn hook_atol(&mut self, s: *const c_char) -> i32 {
        extern "system" {
            fn atol(s: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "atol".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atol(s) }
    }

    /// Hooks `atoll`
    #[inline]
    pub fn hook_atoll(&mut self, s: *const c_char) -> i64 {
        extern "system" {
            fn atoll(s: *const c_char) -> i64;
            fn strlen(s: *const c_char) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, unsafe { strlen(s) })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "atoll".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atoll(s) }
    }

    /// Hooks `wcslen`
    #[inline]
    pub fn hook_wcslen(&mut self, s: *const wchar_t) -> usize {
        extern "system" {
            fn wcslen(s: *const wchar_t) -> usize;
        }
        let size = unsafe { wcslen(s) };
        if !self
            .allocator_mut()
            .check_shadow(s as *const c_void, (size + 1) * 2)
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "wcslen".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                (size + 1) * 2,
                Backtrace::new(),
            )));
        }
        size
    }

    /// Hooks `wcscpy`
    #[inline]
    pub fn hook_wcscpy(&mut self, dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
        extern "system" {
            fn wcscpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t;
            fn wcslen(s: *const wchar_t) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(dest as *const c_void, unsafe { (wcslen(src) + 1) * 2 })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "wcscpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                dest as usize,
                (unsafe { wcslen(src) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(src as *const c_void, unsafe { (wcslen(src) + 1) * 2 })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "wcscpy".to_string(),
                self.real_address_for_stalked(self.pc()),
                src as usize,
                (unsafe { wcslen(src) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        unsafe { wcscpy(dest, src) }
    }

    /// Hooks `wcscmp`
    #[inline]
    pub fn hook_wcscmp(&mut self, s1: *const wchar_t, s2: *const wchar_t) -> i32 {
        extern "system" {
            fn wcscmp(s1: *const wchar_t, s2: *const wchar_t) -> i32;
            fn wcslen(s: *const wchar_t) -> usize;
        }
        if !self
            .allocator_mut()
            .check_shadow(s1 as *const c_void, unsafe { (wcslen(s1) + 1) * 2 })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s1 as usize,
                (unsafe { wcslen(s1) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        if !self
            .allocator_mut()
            .check_shadow(s2 as *const c_void, unsafe { (wcslen(s2) + 1) * 2 })
        {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(self.pc()),
                s2 as usize,
                (unsafe { wcslen(s2) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        unsafe { wcscmp(s1, s2) }
    }

    #[cfg(target_vendor = "apple")]
    #[inline]
    pub fn hook_memset_pattern4(&mut self, s: *mut c_void, p4: *const c_void, n: usize) {
        extern "system" {
            fn memset_pattern4(s: *mut c_void, p4: *const c_void, n: usize);
        }
        if !self.allocator_mut().check_shadow(s, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern4".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(p4, n / 4) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern4".to_string(),
                self.real_address_for_stalked(self.pc()),
                p4 as usize,
                n / 4,
                Backtrace::new(),
            )));
        }
        unsafe { memset_pattern4(s, p4, n) }
    }

    #[cfg(target_vendor = "apple")]
    #[inline]
    pub fn hook_memset_pattern8(&mut self, s: *mut c_void, p8: *const c_void, n: usize) {
        extern "system" {
            fn memset_pattern8(s: *mut c_void, p8: *const c_void, n: usize);
        }
        if !self.allocator_mut().check_shadow(s, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern8".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(p8, n / 8) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern8".to_string(),
                self.real_address_for_stalked(self.pc()),
                p8 as usize,
                n / 8,
                Backtrace::new(),
            )));
        }
        unsafe { memset_pattern8(s, p8, n) }
    }

    #[cfg(target_vendor = "apple")]
    #[inline]
    pub fn hook_memset_pattern16(&mut self, s: *mut c_void, p16: *const c_void, n: usize) {
        extern "system" {
            fn memset_pattern16(s: *mut c_void, p16: *const c_void, n: usize);
        }
        if !self.allocator_mut().check_shadow(s, n) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern16".to_string(),
                self.real_address_for_stalked(self.pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !self.allocator_mut().check_shadow(p16, n / 16) {
            AsanErrors::get_mut_blocking().report_error(AsanError::BadFuncArgWrite((
                "memset_pattern16".to_string(),
                self.real_address_for_stalked(self.pc()),
                p16 as usize,
                n / 16,
                Backtrace::new(),
            )));
        }
        unsafe { memset_pattern16(s, p16, n) }
    }
}
