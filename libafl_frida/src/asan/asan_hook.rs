use frida_gum::NativePointer;
use frida_gum::RangeDetails;
use hashbrown::HashMap;

use nix::sys::mman::{mmap, MapFlags, ProtFlags};

use nix::libc::memset;

use backtrace::Backtrace;

#[cfg(target_arch = "aarch64")]
use capstone::{
    arch::{arm64::Arm64OperandType, ArchOperand::Arm64Operand, BuildsCapstone},
    Capstone, Insn,
};

#[cfg(target_arch = "x86_64")]
use capstone::{
    arch::{self, x86::X86OperandType, ArchOperand::X86Operand, BuildsCapstone},
    Capstone, RegAccessType, RegId,
};

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use frida_gum::interceptor::Interceptor;
use frida_gum::{Gum, ModuleMap};
#[cfg(unix)]
use libc::RLIMIT_STACK;
use libc::{c_char, wchar_t};
#[cfg(target_vendor = "apple")]
use libc::{getrlimit, rlimit};
#[cfg(all(unix, not(target_vendor = "apple")))]
use libc::{getrlimit64, rlimit64};
use std::{ffi::c_void, ptr::write_volatile};

use crate::{
    alloc::Allocator,
    asan::asan_errors::{AsanError, AsanErrors, AsanReadWriteError, ASAN_ERRORS},
    FridaOptions,
};

impl AsanRuntime {
    
    #[inline]
    fn hook_malloc(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__Znam(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnamRKSt9nothrow_t(&mut self, size: usize, _nothrow: *const c_void) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnamSt11align_val_t(&mut self, size: usize, alignment: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnamSt11align_val_tRKSt9nothrow_t(
        &mut self,
        size: usize,
        alignment: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__Znwm(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnwmRKSt9nothrow_t(&mut self, size: usize, _nothrow: *const c_void) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnwmSt11align_val_t(&mut self, size: usize, alignment: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnwmSt11align_val_tRKSt9nothrow_t(
        &mut self,
        size: usize,
        alignment: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[inline]
    fn hook_calloc(&mut self, nmemb: usize, size: usize) -> *mut c_void {
        let ret = unsafe { self.allocator.alloc(size * nmemb, 8) };
        unsafe {
            memset(ret, 0, size * nmemb);
        }
        ret
    }

    #[inline]
    #[allow(clippy::cmp_null)]
    fn hook_realloc(&mut self, ptr: *mut c_void, size: usize) -> *mut c_void {
        unsafe {
            let ret = self.allocator.alloc(size, 0x8);
            if ptr != std::ptr::null_mut() && ret != std::ptr::null_mut() {
                let old_size = self.allocator.get_usable_size(ptr);
                let copy_size = if size < old_size { size } else { old_size };
                (ptr as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator.release(ptr);
            ret
        }
    }

    #[inline]
    fn hook_check_free(&mut self, ptr: *mut c_void) -> bool {
        self.allocator.is_managed(ptr)
    }

    #[inline]
    #[allow(clippy::cmp_null)]
    fn hook_free(&mut self, ptr: *mut c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[cfg(not(target_vendor = "apple"))]
    #[inline]
    fn hook_memalign(&mut self, alignment: usize, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[inline]
    fn hook_posix_memalign(
        &mut self,
        pptr: *mut *mut c_void,
        alignment: usize,
        size: usize,
    ) -> i32 {
        unsafe {
            *pptr = self.allocator.alloc(size, alignment);
        }
        0
    }

    #[inline]
    #[cfg(all(not(target_vendor = "apple")))]
    fn hook_malloc_usable_size(&mut self, ptr: *mut c_void) -> usize {
        self.allocator.get_usable_size(ptr)
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPv(&mut self, ptr: *mut c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPvm(&mut self, ptr: *mut c_void, _ulong: u64) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPvmSt11align_val_t(&mut self, ptr: *mut c_void, _ulong: u64, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPvRKSt9nothrow_t(&mut self, ptr: *mut c_void, _nothrow: *const c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPvSt11align_val_tRKSt9nothrow_t(
        &mut self,
        ptr: *mut c_void,
        _alignment: usize,
        _nothrow: *const c_void,
    ) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPvSt11align_val_t(&mut self, ptr: *mut c_void, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPv(&mut self, ptr: *mut c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPvm(&mut self, ptr: *mut c_void, _ulong: u64) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPvmSt11align_val_t(&mut self, ptr: *mut c_void, _ulong: u64, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPvRKSt9nothrow_t(&mut self, ptr: *mut c_void, _nothrow: *const c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPvSt11align_val_tRKSt9nothrow_t(
        &mut self,
        ptr: *mut c_void,
        _alignment: usize,
        _nothrow: *const c_void,
    ) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPvSt11align_val_t(&mut self, ptr: *mut c_void, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[inline]
    fn hook_mmap(
        &mut self,
        addr: *const c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: usize,
    ) -> *mut c_void {
        extern "C" {
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
            self.allocator
                .map_shadow_for_region(res as usize, res as usize + length, true);
        }
        res
    }

    #[inline]
    fn hook_munmap(&mut self, addr: *const c_void, length: usize) -> i32 {
        extern "C" {
            fn munmap(addr: *const c_void, length: usize) -> i32;
        }
        let res = unsafe { munmap(addr, length) };
        if res != -1 {
            Allocator::poison(self.allocator.map_to_shadow(addr as usize), length);
        }
        res
    }

    #[inline]
    fn hook_write(&mut self, fd: i32, buf: *const c_void, count: usize) -> usize {
        extern "C" {
            fn write(fd: i32, buf: *const c_void, count: usize) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(buf, count) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "write".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                buf as usize,
                count,
                Backtrace::new(),
            )));
        }
        unsafe { write(fd, buf, count) }
    }

    #[inline]
    fn hook_read(&mut self, fd: i32, buf: *mut c_void, count: usize) -> usize {
        extern "C" {
            fn read(fd: i32, buf: *mut c_void, count: usize) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(buf, count) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "read".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                buf as usize,
                count,
                Backtrace::new(),
            )));
        }
        unsafe { read(fd, buf, count) }
    }

    #[inline]
    fn hook_fgets(&mut self, s: *mut c_void, size: u32, stream: *mut c_void) -> *mut c_void {
        extern "C" {
            fn fgets(s: *mut c_void, size: u32, stream: *mut c_void) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(s, size as usize) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "fgets".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                size as usize,
                Backtrace::new(),
            )));
        }
        unsafe { fgets(s, size, stream) }
    }

    #[inline]
    fn hook_memcmp(&mut self, s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        extern "C" {
            fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memcmp(s1, s2, n) }
    }

    #[inline]
    fn hook_memcpy(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "C" {
            fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "memcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memcpy(dest, src, n) }
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    fn hook_mempcpy(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "C" {
            fn mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "mempcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "mempcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { mempcpy(dest, src, n) }
    }

    #[inline]
    fn hook_memmove(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "C" {
            fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "memmove".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memmove".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memmove(dest, src, n) }
    }

    #[inline]
    fn hook_memset(&mut self, dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "C" {
            fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "memset".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memset(dest, c, n) }
    }

    #[inline]
    fn hook_memchr(&mut self, s: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "C" {
            fn memchr(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memchr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memchr(s, c, n) }
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    fn hook_memrchr(&mut self, s: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "C" {
            fn memrchr(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memrchr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memrchr(s, c, n) }
    }

    #[inline]
    fn hook_memmem(
        &mut self,
        haystack: *const c_void,
        haystacklen: usize,
        needle: *const c_void,
        needlelen: usize,
    ) -> *mut c_void {
        extern "C" {
            fn memmem(
                haystack: *const c_void,
                haystacklen: usize,
                needle: *const c_void,
                needlelen: usize,
            ) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(haystack, haystacklen) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memmem".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                haystack as usize,
                haystacklen,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(needle, needlelen) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memmem".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                needle as usize,
                needlelen,
                Backtrace::new(),
            )));
        }
        unsafe { memmem(haystack, haystacklen, needle, needlelen) }
    }

    #[cfg(all(not(target_os = "android")))]
    #[inline]
    fn hook_bzero(&mut self, s: *mut c_void, n: usize) {
        extern "C" {
            fn bzero(s: *mut c_void, n: usize);
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "bzero".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { bzero(s, n) }
    }

    #[cfg(all(not(target_os = "android"), not(target_vendor = "apple")))]
    #[inline]
    fn hook_explicit_bzero(&mut self, s: *mut c_void, n: usize) {
        extern "C" {
            fn explicit_bzero(s: *mut c_void, n: usize);
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "explicit_bzero".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { explicit_bzero(s, n) }
    }

    #[cfg(all(not(target_os = "android")))]
    #[inline]
    fn hook_bcmp(&mut self, s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        extern "C" {
            fn bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { bcmp(s1, s2, n) }
    }

    #[inline]
    fn hook_strchr(&mut self, s: *mut c_char, c: i32) -> *mut c_char {
        extern "C" {
            fn strchr(s: *mut c_char, c: i32) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strchr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { strchr(s, c) }
    }

    #[inline]
    fn hook_strrchr(&mut self, s: *mut c_char, c: i32) -> *mut c_char {
        extern "C" {
            fn strrchr(s: *mut c_char, c: i32) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strrchr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { strrchr(s, c) }
    }

    #[inline]
    fn hook_strcasecmp(&mut self, s1: *const c_char, s2: *const c_char) -> i32 {
        extern "C" {
            fn strcasecmp(s1: *const c_char, s2: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { strlen(s1) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { strlen(s2) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcasecmp(s1, s2) }
    }

    #[inline]
    fn hook_strncasecmp(&mut self, s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
        extern "C" {
            fn strncasecmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncasecmp(s1, s2, n) }
    }

    #[inline]
    fn hook_strcat(&mut self, s1: *mut c_char, s2: *const c_char) -> *mut c_char {
        extern "C" {
            fn strcat(s1: *mut c_char, s2: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { strlen(s1) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { strlen(s2) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcat(s1, s2) }
    }

    #[inline]
    fn hook_strcmp(&mut self, s1: *const c_char, s2: *const c_char) -> i32 {
        extern "C" {
            fn strcmp(s1: *const c_char, s2: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { strlen(s1) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { strlen(s2) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcmp(s1, s2) }
    }

    #[inline]
    fn hook_strncmp(&mut self, s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
        extern "C" {
            fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncmp(s1, s2, n) }
    }

    #[inline]
    fn hook_strcpy(&mut self, dest: *mut c_char, src: *const c_char) -> *mut c_char {
        extern "C" {
            fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "strcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        unsafe { strcpy(dest, src) }
    }

    #[inline]
    fn hook_strncpy(&mut self, dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
        extern "C" {
            fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "strncpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncpy(dest, src, n) }
    }

    #[inline]
    fn hook_stpcpy(&mut self, dest: *mut c_char, src: *const c_char) -> *mut c_char {
        extern "C" {
            fn stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "stpcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "stpcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        unsafe { stpcpy(dest, src) }
    }

    #[inline]
    fn hook_strdup(&mut self, s: *const c_char) -> *mut c_char {
        extern "C" {
            fn strlen(s: *const c_char) -> usize;
            fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
        }
        let size = unsafe { strlen(s) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, size) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strdup".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }

        unsafe {
            let ret = self.allocator.alloc(size, 8) as *mut c_char;
            strcpy(ret, s);
            ret
        }
    }

    #[inline]
    fn hook_strlen(&mut self, s: *const c_char) -> usize {
        extern "C" {
            fn strlen(s: *const c_char) -> usize;
        }
        let size = unsafe { strlen(s) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, size) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strlen".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                size,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
    fn hook_strnlen(&mut self, s: *const c_char, n: usize) -> usize {
        extern "C" {
            fn strnlen(s: *const c_char, n: usize) -> usize;
        }
        let size = unsafe { strnlen(s, n) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, size) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strnlen".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                size,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
    fn hook_strstr(&mut self, haystack: *const c_char, needle: *const c_char) -> *mut c_char {
        extern "C" {
            fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(haystack as *const c_void, unsafe {
            strlen(haystack)
        }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strstr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(needle as *const c_void, unsafe { strlen(needle) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strstr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )));
        }
        unsafe { strstr(haystack, needle) }
    }

    #[inline]
    fn hook_strcasestr(&mut self, haystack: *const c_char, needle: *const c_char) -> *mut c_char {
        extern "C" {
            fn strcasestr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(haystack as *const c_void, unsafe {
            strlen(haystack)
        }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasestr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(needle as *const c_void, unsafe { strlen(needle) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasestr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )));
        }
        unsafe { strcasestr(haystack, needle) }
    }

    #[inline]
    fn hook_atoi(&mut self, s: *const c_char) -> i32 {
        extern "C" {
            fn atoi(s: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "atoi".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atoi(s) }
    }

    #[inline]
    fn hook_atol(&mut self, s: *const c_char) -> i32 {
        extern "C" {
            fn atol(s: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "atol".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atol(s) }
    }

    #[inline]
    fn hook_atoll(&mut self, s: *const c_char) -> i64 {
        extern "C" {
            fn atoll(s: *const c_char) -> i64;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "atoll".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atoll(s) }
    }

    #[inline]
    fn hook_wcslen(&mut self, s: *const wchar_t) -> usize {
        extern "C" {
            fn wcslen(s: *const wchar_t) -> usize;
        }
        let size = unsafe { wcslen(s) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, (size + 1) * 2) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcslen".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                (size + 1) * 2,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
    fn hook_wcscpy(&mut self, dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
        extern "C" {
            fn wcscpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t;
            fn wcslen(s: *const wchar_t) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, unsafe {
            (wcslen(src) + 1) * 2
        }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "wcscpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                (unsafe { wcslen(src) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, unsafe {
            (wcslen(src) + 1) * 2
        }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcscpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                (unsafe { wcslen(src) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        unsafe { wcscpy(dest, src) }
    }

    #[inline]
    fn hook_wcscmp(&mut self, s1: *const wchar_t, s2: *const wchar_t) -> i32 {
        extern "C" {
            fn wcscmp(s1: *const wchar_t, s2: *const wchar_t) -> i32;
            fn wcslen(s: *const wchar_t) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { (wcslen(s1) + 1) * 2 })
        {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                (unsafe { wcslen(s1) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { (wcslen(s2) + 1) * 2 })
        {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                (unsafe { wcslen(s2) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        unsafe { wcscmp(s1, s2) }
    }

    /// Hook all functions required for ASAN to function, replacing them with our own
    /// implementations.
    #[allow(clippy::items_after_statements)]
    #[allow(clippy::too_many_lines)]
    fn hook_functions(&mut self, gum: &Gum) {
        let mut interceptor = frida_gum::interceptor::Interceptor::obtain(gum);

        macro_rules! hook_func {
            ($lib:expr, $name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
                paste::paste! {
                    extern "C" {
                        fn $name($($param: $param_type),*) -> $return_type;
                    }
                    #[allow(non_snake_case)]
                    unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
                        let mut invocation = Interceptor::current_invocation();
                        let this = &mut *(invocation.replacement_data().unwrap().0 as *mut AsanRuntime);
                        if this.module_map.as_ref().unwrap().find(this.real_address_for_stalked(invocation.return_addr() as usize) as u64).is_some() {
                            this.[<hook_ $name>]($($param),*)
                        } else {
                            $name($($param),*)
                        }
                    }
                    interceptor.replace(
                        frida_gum::Module::find_export_by_name($lib, stringify!($name)).expect("Failed to find function"),
                        NativePointer([<replacement_ $name>] as *mut c_void),
                        NativePointer(self as *mut _ as *mut c_void)
                    ).ok();
                }
            }
        }

        macro_rules! hook_func_with_check {
            ($lib:expr, $name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
                paste::paste! {
                    extern "C" {
                        fn $name($($param: $param_type),*) -> $return_type;
                    }
                    #[allow(non_snake_case)]
                    unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
                        let mut invocation = Interceptor::current_invocation();
                        let this = &mut *(invocation.replacement_data().unwrap().0 as *mut AsanRuntime);
                        if this.[<hook_check_ $name>]($($param),*) {
                            this.[<hook_ $name>]($($param),*)
                        } else {
                            $name($($param),*)
                        }
                    }
                    interceptor.replace(
                        frida_gum::Module::find_export_by_name($lib, stringify!($name)).expect("Failed to find function"),
                        NativePointer([<replacement_ $name>] as *mut c_void),
                        NativePointer(self as *mut _ as *mut c_void)
                    ).ok();
                }
            }
        }

        // Hook the memory allocator functions
        hook_func!(None, malloc, (size: usize), *mut c_void);
        hook_func!(None, calloc, (nmemb: usize, size: usize), *mut c_void);
        hook_func!(None, realloc, (ptr: *mut c_void, size: usize), *mut c_void);
        hook_func_with_check!(None, free, (ptr: *mut c_void), ());
        #[cfg(not(target_vendor = "apple"))]
        hook_func!(None, memalign, (size: usize, alignment: usize), *mut c_void);
        hook_func!(
            None,
            posix_memalign,
            (pptr: *mut *mut c_void, size: usize, alignment: usize),
            i32
        );
        #[cfg(not(target_vendor = "apple"))]
        hook_func!(None, malloc_usable_size, (ptr: *mut c_void), usize);
        hook_func!(None, _Znam, (size: usize), *mut c_void);
        hook_func!(
            None,
            _ZnamRKSt9nothrow_t,
            (size: usize, _nothrow: *const c_void),
            *mut c_void
        );
        hook_func!(
            None,
            _ZnamSt11align_val_t,
            (size: usize, alignment: usize),
            *mut c_void
        );
        hook_func!(
            None,
            _ZnamSt11align_val_tRKSt9nothrow_t,
            (size: usize, alignment: usize, _nothrow: *const c_void),
            *mut c_void
        );
        hook_func!(None, _Znwm, (size: usize), *mut c_void);
        hook_func!(
            None,
            _ZnwmRKSt9nothrow_t,
            (size: usize, _nothrow: *const c_void),
            *mut c_void
        );
        hook_func!(
            None,
            _ZnwmSt11align_val_t,
            (size: usize, alignment: usize),
            *mut c_void
        );
        hook_func!(
            None,
            _ZnwmSt11align_val_tRKSt9nothrow_t,
            (size: usize, alignment: usize, _nothrow: *const c_void),
            *mut c_void
        );
        hook_func!(None, _ZdaPv, (ptr: *mut c_void), ());
        hook_func!(None, _ZdaPvm, (ptr: *mut c_void, _ulong: u64), ());
        hook_func!(
            None,
            _ZdaPvmSt11align_val_t,
            (ptr: *mut c_void, _ulong: u64, _alignment: usize),
            ()
        );
        hook_func!(
            None,
            _ZdaPvRKSt9nothrow_t,
            (ptr: *mut c_void, _nothrow: *const c_void),
            ()
        );
        hook_func!(
            None,
            _ZdaPvSt11align_val_t,
            (ptr: *mut c_void, _alignment: usize),
            ()
        );
        hook_func!(
            None,
            _ZdaPvSt11align_val_tRKSt9nothrow_t,
            (ptr: *mut c_void, _alignment: usize, _nothrow: *const c_void),
            ()
        );
        hook_func!(None, _ZdlPv, (ptr: *mut c_void), ());
        hook_func!(None, _ZdlPvm, (ptr: *mut c_void, _ulong: u64), ());
        hook_func!(
            None,
            _ZdlPvmSt11align_val_t,
            (ptr: *mut c_void, _ulong: u64, _alignment: usize),
            ()
        );
        hook_func!(
            None,
            _ZdlPvRKSt9nothrow_t,
            (ptr: *mut c_void, _nothrow: *const c_void),
            ()
        );
        hook_func!(
            None,
            _ZdlPvSt11align_val_t,
            (ptr: *mut c_void, _alignment: usize),
            ()
        );
        hook_func!(
            None,
            _ZdlPvSt11align_val_tRKSt9nothrow_t,
            (ptr: *mut c_void, _alignment: usize, _nothrow: *const c_void),
            ()
        );

        hook_func!(
            None,
            mmap,
            (
                addr: *const c_void,
                length: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: usize
            ),
            *mut c_void
        );
        hook_func!(None, munmap, (addr: *const c_void, length: usize), i32);

        // Hook libc functions which may access allocated memory
        hook_func!(
            None,
            write,
            (fd: i32, buf: *const c_void, count: usize),
            usize
        );
        hook_func!(None, read, (fd: i32, buf: *mut c_void, count: usize), usize);
        hook_func!(
            None,
            fgets,
            (s: *mut c_void, size: u32, stream: *mut c_void),
            *mut c_void
        );
        hook_func!(
            None,
            memcmp,
            (s1: *const c_void, s2: *const c_void, n: usize),
            i32
        );
        hook_func!(
            None,
            memcpy,
            (dest: *mut c_void, src: *const c_void, n: usize),
            *mut c_void
        );
        #[cfg(not(target_vendor = "apple"))]
        hook_func!(
            None,
            mempcpy,
            (dest: *mut c_void, src: *const c_void, n: usize),
            *mut c_void
        );
        hook_func!(
            None,
            memmove,
            (dest: *mut c_void, src: *const c_void, n: usize),
            *mut c_void
        );
        hook_func!(
            None,
            memset,
            (s: *mut c_void, c: i32, n: usize),
            *mut c_void
        );
        hook_func!(
            None,
            memchr,
            (s: *mut c_void, c: i32, n: usize),
            *mut c_void
        );
        #[cfg(not(target_vendor = "apple"))]
        hook_func!(
            None,
            memrchr,
            (s: *mut c_void, c: i32, n: usize),
            *mut c_void
        );
        hook_func!(
            None,
            memmem,
            (
                haystack: *const c_void,
                haystacklen: usize,
                needle: *const c_void,
                needlelen: usize
            ),
            *mut c_void
        );
        #[cfg(not(target_os = "android"))]
        hook_func!(None, bzero, (s: *mut c_void, n: usize), ());
        #[cfg(not(any(target_os = "android", target_vendor = "apple")))]
        hook_func!(None, explicit_bzero, (s: *mut c_void, n: usize), ());
        #[cfg(not(target_os = "android"))]
        hook_func!(
            None,
            bcmp,
            (s1: *const c_void, s2: *const c_void, n: usize),
            i32
        );
        hook_func!(None, strchr, (s: *mut c_char, c: i32), *mut c_char);
        hook_func!(None, strrchr, (s: *mut c_char, c: i32), *mut c_char);
        hook_func!(
            None,
            strcasecmp,
            (s1: *const c_char, s2: *const c_char),
            i32
        );
        hook_func!(
            None,
            strncasecmp,
            (s1: *const c_char, s2: *const c_char, n: usize),
            i32
        );
        hook_func!(
            None,
            strcat,
            (dest: *mut c_char, src: *const c_char),
            *mut c_char
        );
        hook_func!(None, strcmp, (s1: *const c_char, s2: *const c_char), i32);
        hook_func!(
            None,
            strncmp,
            (s1: *const c_char, s2: *const c_char, n: usize),
            i32
        );
        hook_func!(
            None,
            strcpy,
            (dest: *mut c_char, src: *const c_char),
            *mut c_char
        );
        hook_func!(
            None,
            strncpy,
            (dest: *mut c_char, src: *const c_char, n: usize),
            *mut c_char
        );
        hook_func!(
            None,
            stpcpy,
            (dest: *mut c_char, src: *const c_char),
            *mut c_char
        );
        hook_func!(None, strdup, (s: *const c_char), *mut c_char);
        hook_func!(None, strlen, (s: *const c_char), usize);
        hook_func!(None, strnlen, (s: *const c_char, n: usize), usize);
        hook_func!(
            None,
            strstr,
            (haystack: *const c_char, needle: *const c_char),
            *mut c_char
        );
        hook_func!(
            None,
            strcasestr,
            (haystack: *const c_char, needle: *const c_char),
            *mut c_char
        );
        hook_func!(None, atoi, (nptr: *const c_char), i32);
        hook_func!(None, atol, (nptr: *const c_char), i32);
        hook_func!(None, atoll, (nptr: *const c_char), i64);
        hook_func!(None, wcslen, (s: *const wchar_t), usize);
        hook_func!(
            None,
            wcscpy,
            (dest: *mut wchar_t, src: *const wchar_t),
            *mut wchar_t
        );
        hook_func!(None, wcscmp, (s1: *const wchar_t, s2: *const wchar_t), i32);
    }
}