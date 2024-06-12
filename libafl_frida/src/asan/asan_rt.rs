/*!
The frida address sanitizer runtime provides address sanitization.
When executing in `ASAN`, each memory access will get checked, using frida stalker under the hood.
The runtime can report memory errors that occurred during execution,
even if the target would not have crashed under normal conditions.
this helps finding mem errors early.
*/

use core::{
    fmt::{self, Debug, Formatter},
    ptr::addr_of_mut,
};
use std::{
    ffi::{c_char, c_void},
    ptr::write_volatile,
    rc::Rc,
    sync::MutexGuard,
};

use backtrace::Backtrace;
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86Register;
#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::{Aarch64Register, IndexMode};
use frida_gum::{
    instruction_writer::InstructionWriter, interceptor::Interceptor, stalker::StalkerOutput, Gum,
    Module, ModuleDetails, ModuleMap, NativePointer, PageProtection, RangeDetails,
};
use frida_gum_sys::Insn;
use hashbrown::HashMap;
use libafl_bolts::{cli::FuzzerOptions, AsSlice};
use libc::wchar_t;
use rangemap::RangeMap;
#[cfg(target_arch = "aarch64")]
use yaxpeax_arch::Arch;
#[cfg(target_arch = "aarch64")]
use yaxpeax_arm::armv8::a64::{ARMv8, InstDecoder, Opcode, Operand, ShiftStyle, SizeCode};
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::{
    amd64::{InstDecoder, Instruction, Opcode},
    long_mode::DisplayStyle,
};

#[cfg(target_arch = "x86_64")]
use crate::utils::frida_to_cs;
#[cfg(target_arch = "aarch64")]
use crate::utils::{instruction_width, writer_register};
#[cfg(target_arch = "x86_64")]
use crate::utils::{operand_details, AccessType};
use crate::{
    alloc::Allocator,
    asan::errors::{AsanError, AsanErrors, AsanReadWriteError, ASAN_ERRORS},
    helper::{FridaRuntime, SkipRange},
    utils::disas_count,
};

extern "C" {
    fn __register_frame(begin: *mut c_void);
}

#[cfg(not(target_os = "ios"))]
extern "C" {
    fn tls_ptr() -> *const c_void;
}

/// The count of registers that need to be saved by the asan runtime
/// sixteen general purpose registers are put in this order, rax, rbx, rcx, rdx, rbp, rsp, rsi, rdi, r8-r15, plus instrumented rip, accessed memory addr and true rip
#[cfg(target_arch = "x86_64")]
pub const ASAN_SAVE_REGISTER_COUNT: usize = 19;

/// The registers that need to be saved by the asan runtime, as names
#[cfg(target_arch = "x86_64")]
pub const ASAN_SAVE_REGISTER_NAMES: [&str; ASAN_SAVE_REGISTER_COUNT] = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rbp",
    "rsp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "instrumented rip",
    "fault address",
    "actual rip",
];

/// The count of registers that need to be saved by the asan runtime
#[cfg(target_arch = "aarch64")]
pub const ASAN_SAVE_REGISTER_COUNT: usize = 32;

#[cfg(target_arch = "aarch64")]
const ASAN_EH_FRAME_DWORD_COUNT: usize = 14;
#[cfg(target_arch = "aarch64")]
const ASAN_EH_FRAME_FDE_OFFSET: u32 = 20;
#[cfg(target_arch = "aarch64")]
const ASAN_EH_FRAME_FDE_ADDRESS_OFFSET: u32 = 28;

/// The frida address sanitizer runtime, providing address sanitization.
/// When executing in `ASAN`, each memory access will get checked, using frida stalker under the hood.
/// The runtime can report memory errors that occurred during execution,
/// even if the target would not have crashed under normal conditions.
/// this helps finding mem errors early.
pub struct AsanRuntime {
    check_for_leaks_enabled: bool,
    current_report_impl: u64,
    allocator: Allocator,
    regs: [usize; ASAN_SAVE_REGISTER_COUNT],
    blob_report: Option<Box<[u8]>>,
    blob_check_mem_byte: Option<Box<[u8]>>,
    blob_check_mem_halfword: Option<Box<[u8]>>,
    blob_check_mem_dword: Option<Box<[u8]>>,
    blob_check_mem_qword: Option<Box<[u8]>>,
    blob_check_mem_16bytes: Option<Box<[u8]>>,
    blob_check_mem_3bytes: Option<Box<[u8]>>,
    blob_check_mem_6bytes: Option<Box<[u8]>>,
    blob_check_mem_12bytes: Option<Box<[u8]>>,
    blob_check_mem_24bytes: Option<Box<[u8]>>,
    blob_check_mem_32bytes: Option<Box<[u8]>>,
    blob_check_mem_48bytes: Option<Box<[u8]>>,
    blob_check_mem_64bytes: Option<Box<[u8]>>,
    stalked_addresses: HashMap<usize, usize>,
    module_map: Option<Rc<ModuleMap>>,
    suppressed_addresses: Vec<usize>,
    skip_ranges: Vec<SkipRange>,
    continue_on_error: bool,
    pc: Option<usize>,
    hooks: Vec<NativePointer>,
    pub(crate) hooks_enabled: bool,
    #[cfg(target_arch = "aarch64")]
    eh_frame: [u32; ASAN_EH_FRAME_DWORD_COUNT],
}

impl Debug for AsanRuntime {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsanRuntime")
            .field("stalked_addresses", &self.stalked_addresses)
            .field("continue_on_error", &self.continue_on_error)
            .field("module_map", &"<ModuleMap>")
            .field("skip_ranges", &self.skip_ranges)
            .field("suppressed_addresses", &self.suppressed_addresses)
            .finish_non_exhaustive()
    }
}

impl FridaRuntime for AsanRuntime {
    /// Initialize the runtime so that it is read for action. Take care not to move the runtime
    /// instance after this function has been called, as the generated blobs would become
    /// invalid!
    fn init(
        &mut self,
        gum: &Gum,
        _ranges: &RangeMap<usize, (u16, String)>,
        module_map: &Rc<ModuleMap>,
    ) {
        self.allocator.init();

        AsanErrors::get_mut_blocking().set_continue_on_error(self.continue_on_error);

        self.module_map = Some(module_map.clone());
        self.suppressed_addresses
            .extend(self.skip_ranges.iter().map(|skip| match skip {
                SkipRange::Absolute(range) => range.start,
                SkipRange::ModuleRelative { name, range } => {
                    let module_details = ModuleDetails::with_name(name.clone()).unwrap();
                    let lib_start = module_details.range().base_address().0 as usize;
                    lib_start + range.start
                }
            }));

        self.register_hooks(gum);
        self.generate_instrumentation_blobs();
        self.unpoison_all_existing_memory();

        self.register_thread();
    }

    fn deinit(&mut self, gum: &Gum) {
        self.deregister_hooks(gum);
    }

    fn pre_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        input: &I,
    ) -> Result<(), libafl::Error> {
        let target_bytes = input.target_bytes();
        let slice = target_bytes.as_slice();

        self.unpoison(slice.as_ptr() as usize, slice.len());
        self.enable_hooks();
        Ok(())
    }

    fn post_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        input: &I,
    ) -> Result<(), libafl::Error> {
        self.disable_hooks();
        if self.check_for_leaks_enabled {
            self.check_for_leaks();
        }

        let target_bytes = input.target_bytes();
        let slice = target_bytes.as_slice();
        self.poison(slice.as_ptr() as usize, slice.len());
        self.reset_allocations();

        Ok(())
    }
}

impl AsanRuntime {
    /// Create a new `AsanRuntime`
    #[must_use]
    pub fn new(options: &FuzzerOptions) -> AsanRuntime {
        let skip_ranges = options
            .dont_instrument
            .iter()
            .map(|(name, offset)| SkipRange::ModuleRelative {
                name: name.clone(),
                range: *offset..*offset + 4,
            })
            .collect();
        let continue_on_error = options.continue_on_error;
        Self {
            check_for_leaks_enabled: options.detect_leaks,
            allocator: Allocator::new(options),
            skip_ranges,
            continue_on_error,
            ..Self::default()
        }
    }

    /// Reset all allocations so that they can be reused for new allocation requests.
    #[allow(clippy::unused_self)]
    pub fn reset_allocations(&mut self) {
        self.allocator.reset();
    }

    /// Gets the allocator
    #[must_use]
    pub fn allocator(&self) -> &Allocator {
        &self.allocator
    }

    /// Gets the allocator (mutable)
    pub fn allocator_mut(&mut self) -> &mut Allocator {
        &mut self.allocator
    }

    /// Check if the test leaked any memory and report it if so.
    pub fn check_for_leaks(&mut self) {
        self.allocator.check_for_leaks();
    }

    /// Returns the `AsanErrors` from the recent run.
    /// Will block if some other thread holds on to the `ASAN_ERRORS` Mutex.
    #[allow(clippy::unused_self)]
    pub fn errors(&mut self) -> MutexGuard<'static, AsanErrors> {
        ASAN_ERRORS.lock().unwrap()
    }

    /// Make sure the specified memory is unpoisoned
    #[allow(clippy::unused_self)]
    pub fn unpoison(&mut self, address: usize, size: usize) {
        self.allocator
            .map_shadow_for_region(address, address + size, true);
    }

    /// Make sure the specified memory is poisoned
    pub fn poison(&mut self, address: usize, size: usize) {
        Allocator::poison(self.allocator.map_to_shadow(address), size);
    }

    /// Add a stalked address to real address mapping.
    #[inline]
    pub fn add_stalked_address(&mut self, stalked: usize, real: usize) {
        self.stalked_addresses.insert(stalked, real);
    }

    /// Resolves the real address from a stalker stalked address if possible, if there is no
    /// real address, the stalked address is returned.
    #[must_use]
    pub fn real_address_for_stalked(&self, stalked: usize) -> usize {
        self.stalked_addresses
            .get(&stalked)
            .map_or(stalked, |addr| *addr)
    }

    /// Unpoison all the memory that is currently mapped with read/write permissions.
    #[allow(clippy::unused_self)]
    pub fn unpoison_all_existing_memory(&mut self) {
        self.allocator.unpoison_all_existing_memory();
    }

    /// Enable all function hooks
    pub fn enable_hooks(&mut self) {
        self.hooks_enabled = true;
    }
    /// Disable all function hooks
    pub fn disable_hooks(&mut self) {
        self.hooks_enabled = false;
    }

    /// Register the current thread with the runtime, implementing shadow memory for its stack and
    /// tls mappings.
    #[allow(clippy::unused_self)]
    #[cfg(not(target_os = "ios"))]
    pub fn register_thread(&mut self) {
        let (stack_start, stack_end) = Self::current_stack();
        let (tls_start, tls_end) = Self::current_tls();
        log::info!(
            "registering thread with stack {stack_start:x}:{stack_end:x} and tls {tls_start:x}:{tls_end:x}"
        );
        self.allocator
            .map_shadow_for_region(stack_start, stack_end, true);

        #[cfg(unix)]
        self.allocator
            .map_shadow_for_region(tls_start, tls_end, true);
    }

    /// Register the current thread with the runtime, implementing shadow memory for its stack mapping.
    #[allow(clippy::unused_self)]
    #[cfg(target_os = "ios")]
    pub fn register_thread(&mut self) {
        let (stack_start, stack_end) = Self::current_stack();
        self.allocator
            .map_shadow_for_region(stack_start, stack_end, true);

        log::info!("registering thread with stack {stack_start:x}:{stack_end:x}");
    }

    /// Get the maximum stack size for the current stack
    // #[must_use]
    // #[cfg(target_vendor = "apple")]
    // fn max_stack_size() -> usize {
    //     let mut stack_rlimit = rlimit {
    //         rlim_cur: 0,
    //         rlim_max: 0,
    //     };
    //     assert!(unsafe { getrlimit(RLIMIT_STACK, addr_of_mut!(stack_rlimit)) } == 0);
    //
    //     stack_rlimit.rlim_cur as usize
    // }
    //
    // /// Get the maximum stack size for the current stack
    // #[must_use]
    // #[cfg(all(unix, not(target_vendor = "apple")))]
    // fn max_stack_size() -> usize {
    //     let mut stack_rlimit = rlimit64 {
    //         rlim_cur: 0,
    //         rlim_max: 0,
    //     };
    //     assert!(unsafe { getrlimit64(RLIMIT_STACK, addr_of_mut!(stack_rlimit)) } == 0);
    //
    //     stack_rlimit.rlim_cur as usize
    // }

    /// Get the start and end of the memory region containing the given address
    /// Uses `RangeDetails::enumerate_with_prot` as `RangeDetails::with_address` has
    /// a [bug](https://github.com/frida/frida-rust/issues/120)
    /// Returns (start, end)
    fn range_for_address(address: usize) -> (usize, usize) {
        let mut start = 0;
        let mut end = 0;
        RangeDetails::enumerate_with_prot(PageProtection::NoAccess, &mut |range: &RangeDetails| {
            let range_start = range.memory_range().base_address().0 as usize;
            let range_end = range_start + range.memory_range().size();
            if range_start <= address && range_end >= address {
                start = range_start;
                end = range_end;
                // I want to stop iteration here
                return false;
            }
            true
        });

        if start == 0 {
            log::error!(
                "range_for_address: no range found for address {:#x}",
                address
            );
        }
        (start, end)
    }

    /// Determine the stack start, end for the currently running thread
    ///
    /// # Panics
    /// Panics, if no mapping for the `stack_address` at `0xeadbeef` could be found.
    #[must_use]
    pub fn current_stack() -> (usize, usize) {
        let mut stack_var = 0xeadbeef;
        let stack_address = addr_of_mut!(stack_var) as usize;
        // let range_details = RangeDetails::with_address(stack_address as u64).unwrap();
        // Write something to (hopefully) make sure the val isn't optimized out
        unsafe {
            write_volatile(&mut stack_var, 0xfadbeef);
        }
        let mut range = None;
        for area in mmap_rs::MemoryAreas::open(None).unwrap() {
            let area_ref = area.as_ref().unwrap();
            if area_ref.start() <= stack_address && stack_address <= area_ref.end() {
                range = Some((area_ref.end() - 1024 * 1024, area_ref.end()));
                break;
            }
        }
        if let Some((start, end)) = range {
            //     #[cfg(unix)]
            //     {
            //         let max_start = end - Self::max_stack_size();
            //
            //         let flags = ANONYMOUS_FLAG | MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE;
            //         #[cfg(not(target_vendor = "apple"))]
            //         let flags = flags | MapFlags::MAP_STACK;
            //
            //         if start != max_start {
            //             let mapping = unsafe {
            //                 mmap(
            //                     NonZeroUsize::new(max_start),
            //                     NonZeroUsize::new(start - max_start).unwrap(),
            //                     ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            //                     flags,
            //                     -1,
            //                     0,
            //                 )
            //             };
            //             assert!(mapping.unwrap() as usize == max_start);
            //         }
            //         (max_start, end)
            //     }
            //     #[cfg(windows)]
            (start, end)
        } else {
            panic!("Couldn't find stack mapping!");
        }
    }

    /// Determine the tls start, end for the currently running thread
    #[must_use]
    #[cfg(not(target_os = "ios"))]
    fn current_tls() -> (usize, usize) {
        let tls_address = unsafe { tls_ptr() } as usize;

        #[cfg(target_os = "android")]
        // Strip off the top byte, as scudo allocates buffers with top-byte set to 0xb4
        let tls_address = tls_address & 0xffffffffffffff;

        // let range_details = RangeDetails::with_address(tls_address as u64).unwrap();
        // log::info!("tls address: {:#x}, range_details {:x} size {:x}", tls_address,
        //     range_details.memory_range().base_address().0 as usize, range_details.memory_range().size());
        // let start = range_details.memory_range().base_address().0 as usize;
        // let end = start + range_details.memory_range().size();
        // (start, end)
        Self::range_for_address(tls_address)
    }

    /// Gets the current instruction pointer
    #[must_use]
    #[inline]
    pub fn pc(&self) -> usize {
        if let Some(pc) = self.pc.as_ref() {
            *pc
        } else {
            0
        }
    }

    /// Set the current program counter at hook time
    pub fn set_pc(&mut self, pc: usize) {
        self.pc = Some(pc);
    }
    /// Unset the current program counter
    pub fn unset_pc(&mut self) {
        self.pc = None;
    }

    /// Register the required hooks
    #[allow(clippy::too_many_lines)]
    pub fn register_hooks(&mut self, gum: &Gum) {
        let mut interceptor = Interceptor::obtain(gum);
        macro_rules! hook_func {
            //No library case
            ($name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
                paste::paste! {
                    log::trace!("Hooking {}", stringify!($name));

                    let target_function = frida_gum::Module::find_export_by_name(None, stringify!($name)).expect("Failed to find function");

                    static [<$name:snake:upper _PTR>]: std::sync::OnceLock<extern "C" fn($($param: $param_type),*) -> $return_type> = std::sync::OnceLock::new();

                    let _ = [<$name:snake:upper _PTR>].set(unsafe {std::mem::transmute::<*const c_void, extern "C" fn($($param: $param_type),*) -> $return_type>(target_function.0)}).unwrap();

                    #[allow(non_snake_case)]
                    unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
                        let mut invocation = Interceptor::current_invocation();
                        let this = &mut *(invocation.replacement_data().unwrap().0 as *mut AsanRuntime);
                        //is this necessary? The stalked return address will always be the real return address
                     //   let real_address = this.real_address_for_stalked(invocation.return_addr());
                        let original = [<$name:snake:upper _PTR>].get().unwrap();
                        if this.hooks_enabled {
                            let previous_hook_state = this.hooks_enabled;
                            this.hooks_enabled = false;
                            let ret = this.[<hook_ $name>](*original, $($param),*);
                            this.hooks_enabled = previous_hook_state;
                            ret
                        } else {

                            let previous_hook_state = this.hooks_enabled;
                            this.hooks_enabled = false;
                            let ret = (original)($($param),*);
                            this.hooks_enabled = previous_hook_state;
                            ret
                        }
                    }

                    let self_ptr = core::ptr::from_ref(self) as usize;
                    let _ = interceptor.replace(
                        target_function,
                        NativePointer([<replacement_ $name>] as *mut c_void),
                        NativePointer(self_ptr as *mut c_void)
                    );

                    self.hooks.push(target_function);
                }
            };
            //Library specific macro rule. lib and lib_ident are both needed because we need to generate a unique static variable and only name is insufficient. In addition, the lib name could contain invalid characters (i.e., lib.so is an invalid name)
            ($lib:literal, $lib_ident:ident, $name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
                paste::paste! {
                    log::trace!("Hooking {}:{}", $lib, stringify!($name));

                    let target_function = frida_gum::Module::find_export_by_name(Some($lib), stringify!($name)).expect("Failed to find function");

                    static [<$lib_ident:snake:upper _ $name:snake:upper _PTR>]: std::sync::OnceLock<extern "C" fn($($param: $param_type),*) -> $return_type> = std::sync::OnceLock::new();

                    let _ = [<$lib_ident:snake:upper _ $name:snake:upper _PTR>].set(unsafe {std::mem::transmute::<*const c_void, extern "C" fn($($param: $param_type),*) -> $return_type>(target_function.0)}).unwrap();

                    #[allow(non_snake_case)]
                    unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
                        let mut invocation = Interceptor::current_invocation();
                        let this = &mut *(invocation.replacement_data().unwrap().0 as *mut AsanRuntime);
                        //is this necessary? The stalked return address will always be the real return address
                     //   let real_address = this.real_address_for_stalked(invocation.return_addr());
                        let original = [<$lib_ident:snake:upper _ $name:snake:upper _PTR>].get().unwrap();
                        if this.hooks_enabled {
                            let previous_hook_state = this.hooks_enabled;
                            this.hooks_enabled = false;
                            let ret = this.[<hook_ $name>](*original, $($param),*);
                            this.hooks_enabled = previous_hook_state;
                            ret
                        } else {

                            let previous_hook_state = this.hooks_enabled;
                            this.hooks_enabled = false;
                            let ret = (original)($($param),*);
                            this.hooks_enabled = previous_hook_state;
                            ret
                        }
                    }

                    let self_ptr = core::ptr::from_ref(self) as usize;
                    let _ = interceptor.replace(
                        target_function,
                        NativePointer([<replacement_ $name>] as *mut c_void),
                        NativePointer(self_ptr as *mut c_void)
                    );

                    self.hooks.push(target_function);
                }
            };
        }

        #[allow(unused_macro_rules)]
        macro_rules! hook_func_with_check {
            //No library case
            ($name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
                paste::paste! {
                    log::trace!("Hooking {}", stringify!($name));
                    let target_function = frida_gum::Module::find_export_by_name(None, stringify!($name)).expect("Failed to find function");

                    static [<$name:snake:upper _PTR>]: std::sync::OnceLock<extern "C" fn($($param: $param_type),*) -> $return_type> = std::sync::OnceLock::new();



                    let _ = [<$name:snake:upper _PTR>].set(unsafe {std::mem::transmute::<*const c_void, extern "C" fn($($param: $param_type),*) -> $return_type>(target_function.0)}).unwrap_or_else(|e| println!("{:?}", e));

                    #[allow(non_snake_case)]
                    unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
                        let mut invocation = Interceptor::current_invocation();
                        let this = &mut *(invocation.replacement_data().unwrap().0 as *mut AsanRuntime);
                        let original = [<$name:snake:upper _PTR>].get().unwrap();

                        if this.hooks_enabled && this.[<hook_check_ $name>]($($param),*){
                            let previous_hook_state = this.hooks_enabled;
                            this.hooks_enabled = false;
                            let ret = this.[<hook_ $name>](*original, $($param),*);
                            this.hooks_enabled = previous_hook_state;
                            ret
                        } else {
                            let previous_hook_state = this.hooks_enabled;
                            this.hooks_enabled = false;
                            let ret = (original)($($param),*);
                            this.hooks_enabled = previous_hook_state;
                            ret
                        }

                    }

                    let self_ptr = core::ptr::from_ref(self) as usize;
                    let _ = interceptor.replace(
                        target_function,
                        NativePointer([<replacement_ $name>] as *mut c_void),
                        NativePointer(self_ptr as *mut c_void)
                    );
                    self.hooks.push(target_function);
                }
            };
            //Library specific macro rule. lib and lib_ident are both needed because we need to generate a unique static variable and only name is insufficient. In addition, the lib name could contain invalid characters (i.e., lib.so is an invalid name)
            ($lib:literal, $lib_ident:ident, $name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
                paste::paste! {
                    log::trace!("Hooking {}:{}", $lib, stringify!($name));
                    let target_function = frida_gum::Module::find_export_by_name(Some($lib), stringify!($name)).expect("Failed to find function");

                    static [<$lib_ident:snake:upper _ $name:snake:upper _PTR>]: std::sync::OnceLock<extern "C" fn($($param: $param_type),*) -> $return_type> = std::sync::OnceLock::new();



                    let _ = [<$lib_ident:snake:upper _ $name:snake:upper _PTR>].set(unsafe {std::mem::transmute::<*const c_void, extern "C" fn($($param: $param_type),*) -> $return_type>(target_function.0)}).unwrap_or_else(|e| println!("{:?}", e));

                    #[allow(non_snake_case)]
                    unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
                        let mut invocation = Interceptor::current_invocation();
                        let this = &mut *(invocation.replacement_data().unwrap().0 as *mut AsanRuntime);
                        let original = [<$lib_ident:snake:upper _ $name:snake:upper _PTR>].get().unwrap();

                        if this.hooks_enabled && this.[<hook_check_ $name>]($($param),*){
                            let previous_hook_state = this.hooks_enabled;
                            this.hooks_enabled = false;
                            let ret = this.[<hook_ $name>](*original, $($param),*);
                            this.hooks_enabled = previous_hook_state;
                            ret
                        } else {
                            let previous_hook_state = this.hooks_enabled;
                            this.hooks_enabled = false;
                            let ret = (original)($($param),*);
                            this.hooks_enabled = previous_hook_state;
                            ret
                        }

                    }

                    let self_ptr = core::ptr::from_ref(self) as usize;
                    let _ = interceptor.replace(
                        target_function,
                        NativePointer([<replacement_ $name>] as *mut c_void),
                        NativePointer(self_ptr as *mut c_void)
                    );
                    self.hooks.push(target_function);
                }
            }
        }
        // Hook the memory allocator functions

        #[cfg(not(windows))]
        hook_func!(malloc, (size: usize), *mut c_void);
        #[cfg(not(windows))]
        hook_func!(calloc, (nmemb: usize, size: usize), *mut c_void);
        #[cfg(not(windows))]
        hook_func!(realloc, (ptr: *mut c_void, size: usize), *mut c_void);
        #[cfg(not(windows))]
        hook_func_with_check!(free, (ptr: *mut c_void), usize);
        #[cfg(not(any(target_vendor = "apple", windows)))]
        hook_func!(memalign, (size: usize, alignment: usize), *mut c_void);
        #[cfg(not(windows))]
        hook_func!(
            posix_memalign,
            (pptr: *mut *mut c_void, size: usize, alignment: usize),
            i32
        );
        #[cfg(not(any(target_vendor = "apple", windows)))]
        hook_func!(malloc_usable_size, (ptr: *mut c_void), usize);
        // // #[cfg(windows)]
        // hook_priv_func!(
        //     "c:\\windows\\system32\\ntdll.dll",
        //     LdrpCallInitRoutine,
        //     (base_address: *const c_void, reason: usize, context: usize, entry_point: usize),
        //     usize
        // );
        // #[cfg(windows)]
        // hook_func!(
        //     None,
        //     LoadLibraryExW,
        //     (path: *const c_void, file: usize, flags: i32),
        //     usize
        // );
        // #[cfg(windows)]
        // hook_func!(
        //     None,
        //     CreateThread,
        //     (thread_attributes: *const c_void, stack_size: usize, start_address: *const c_void, parameter: *const c_void, creation_flags: i32, thread_id: *mut i32),
        //     usize
        // );
        // #[cfg(windows)]
        // hook_func!(
        //     None,
        //     CreateFileMappingW,
        //     (file: usize, file_mapping_attributes: *const c_void, protect: i32, maximum_size_high: u32, maximum_size_low: u32, name: *const c_void),
        //     usize
        // );
        #[cfg(windows)]
        macro_rules! hook_heap_windows {
            ($libname:literal, $lib_ident:ident) => {
            log::info!("Hooking allocator functions in {}", $libname);
            for export in Module::enumerate_exports($libname) {
                // log::trace!("- {}", export.name);
                match &export.name[..] {
                    "NtGdiCreateCompatibleDC" => {
                        hook_func!($libname, $lib_ident, NtGdiCreateCompatibleDC, (hdc: *const c_void), *mut c_void);
                    }
                    "RtlCreateHeap" => {
                        hook_func!($libname, $lib_ident, RtlCreateHeap, (flags: u32, heap_base: *const c_void, reserve_size: usize, commit_size: usize, lock: *const c_void, parameters: *const c_void), *mut c_void);
                    }
                    "RtlDestroyHeap" => {
                        hook_func!($libname, $lib_ident, RtlDestroyHeap, (handle: *const c_void), *mut c_void);
                    }
                    "HeapAlloc" => {
                        hook_func!($libname, $lib_ident, HeapAlloc, (handle: *mut c_void, flags: u32, bytes: usize), *mut c_void);
                    }
                    "RtlAllocateHeap" => {
                        hook_func!($libname, $lib_ident, RtlAllocateHeap, (handle: *mut c_void, flags: u32, bytes: usize), *mut c_void);
                    }
                    "HeapFree" => {
                        hook_func_with_check!($libname, $lib_ident, HeapFree, (handle: *mut c_void, flags: u32, mem: *mut c_void), bool);
                    }
                    "RtlFreeHeap" => {
                        hook_func_with_check!($libname, $lib_ident, RtlFreeHeap, (handle: *mut c_void, flags: u32, mem: *mut c_void), usize);
                    }
                    "HeapSize" => {
                        hook_func_with_check!($libname, $lib_ident, HeapSize, (handle: *mut c_void, flags: u32, mem: *mut c_void), usize);
                    }
                    "RtlSizeHeap" => {
                        hook_func_with_check!($libname, $lib_ident, RtlSizeHeap , (handle: *mut c_void, flags: u32, mem: *mut c_void), usize);
                    }
                    "RtlReAllocateHeap" => {
                        hook_func!(
                            $libname, $lib_ident,
                            RtlReAllocateHeap,
                            (
                                handle: *mut c_void,
                                flags: u32,
                                ptr: *mut c_void,
                                size: usize
                            ),
                            *mut c_void
                        );
                    }
                    "HeapReAlloc" => {
                        hook_func!(
                            $libname, $lib_ident,
                            HeapReAlloc,
                            (
                                handle: *mut c_void,
                                flags: u32,
                                ptr: *mut c_void,
                                size: usize
                            ),
                            *mut c_void
                        );
                    }
                    "LocalAlloc" => {
                        hook_func!($libname, $lib_ident, LocalAlloc, (flags: u32, size: usize), *mut c_void);
                    }
                    "LocalReAlloc" => {
                        hook_func!($libname, $lib_ident, LocalReAlloc, (mem: *mut c_void, size: usize, flags: u32), *mut c_void);
                    }
                    "LocalHandle" => {
                        hook_func_with_check!($libname, $lib_ident, LocalHandle, (mem: *mut c_void), *mut c_void);
                    }
                    "LocalLock" => {
                        hook_func_with_check!($libname, $lib_ident, LocalLock, (mem: *mut c_void), *mut c_void);
                    }
                    "LocalUnlock" => {
                        hook_func_with_check!($libname, $lib_ident, LocalUnlock, (mem: *mut c_void), bool);
                    }
                    "LocalSize" => {
                        hook_func_with_check!($libname, $lib_ident, LocalSize, (mem: *mut c_void),usize);
                    }
                    "LocalFree" => {
                        hook_func_with_check!($libname, $lib_ident, LocalFree, (mem: *mut c_void), *mut c_void);
                    }
                    "LocalFlags" => {
                        hook_func_with_check!($libname, $lib_ident, LocalFlags, (mem: *mut c_void),u32);
                    }
                    "GlobalAlloc" => {
                        hook_func!($libname, $lib_ident, GlobalAlloc, (flags: u32, size: usize), *mut c_void);
                    }
                    "GlobalReAlloc" => {
                        hook_func!($libname, $lib_ident, GlobalReAlloc, (mem: *mut c_void, flags: u32, size: usize), *mut c_void);
                    }
                    "GlobalHandle" => {
                        hook_func_with_check!($libname, $lib_ident, GlobalHandle, (mem: *mut c_void), *mut c_void);
                    }
                    "GlobalLock" => {
                        hook_func_with_check!($libname, $lib_ident, GlobalLock, (mem: *mut c_void), *mut c_void);
                    }
                    "GlobalUnlock" => {
                        hook_func_with_check!($libname, $lib_ident, GlobalUnlock, (mem: *mut c_void), bool);
                    }
                    "GlobalSize" => {
                        hook_func_with_check!($libname, $lib_ident, GlobalSize, (mem: *mut c_void),usize);
                    }
                    "GlobalFree" => {
                        hook_func_with_check!($libname, $lib_ident, GlobalFree, (mem: *mut c_void), *mut c_void);
                    }
                    "GlobalFlags" => {
                        hook_func_with_check!($libname, $lib_ident, GlobalFlags, (mem: *mut c_void),u32);
                    }
                    "memmove" => {
                        hook_func!(
                            $libname, $lib_ident,
                            memmove,
                            (dest: *mut c_void, src: *const c_void, n: usize),
                            *mut c_void
                        );
                    }
                    "memcpy" => {
                        hook_func!(
                            $libname, $lib_ident,
                            memcpy,
                            (dest: *mut c_void, src: *const c_void, n: usize),
                            *mut c_void
                        );
                    }
                    "malloc" => {
                        hook_func!($libname, $lib_ident, malloc, (size: usize), *mut c_void);
                    }
                    "_o_malloc" | "o_malloc" => {
                        hook_func!($libname, $lib_ident, _o_malloc, (size: usize), *mut c_void);
                    }
                    "calloc" => {
                        hook_func!($libname, $lib_ident, calloc, (nmemb: usize, size: usize), *mut c_void);
                    }
                    "_o_calloc" | "o_calloc" => {
                        hook_func!($libname, $lib_ident, _o_calloc, (nmemb: usize, size: usize), *mut c_void);
                    }
                    "realloc" => {
                        hook_func!($libname, $lib_ident, realloc, (ptr: *mut c_void, size: usize), *mut c_void);
                    }
                    "_o_realloc" | "o_realloc" => {
                        hook_func!($libname, $lib_ident, _o_realloc, (ptr: *mut c_void, size: usize), *mut c_void);
                    }
                    "free" => {
                        hook_func_with_check!($libname, $lib_ident, free, (ptr: *mut c_void), usize);
                    }
                    "_o_free" | "o_free" => {
                        hook_func_with_check!($libname, $lib_ident, _o_free, (ptr: *mut c_void), usize);
                    }
                    "_write" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _write,
                            (fd: i32, buf: *const c_void, count: usize),
                            usize
                        );
                    }
                    "_read" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _read,
                            (fd: i32, buf: *mut c_void, count: usize),
                            usize
                        );
                    }
                    "MapViewOfFile" => {
                        hook_func!(
                            $libname, $lib_ident,
                            MapViewOfFile,
                            (handle: *const c_void, desired_access: u32, file_offset_high: u32, file_offset_low: u32, size: usize),
                            *const c_void
                        );
                    }
                    "LoadLibraryExW" => {
                        hook_func!(
                            $libname, $lib_ident,
                            LoadLibraryExW,
                            (path: *const c_void, file: usize, flags: i32),
                            usize
                        );
                    }
                    "LdrLoadDll" => {
                        hook_func!(
                            $libname, $lib_ident,
                            LdrLoadDll,
                            (search_path: *const c_void, charecteristics: *const u32, dll_name: *const c_void, base_address: *mut *const c_void),
                            usize
                        );
                    }
                    _ => (),
                }
            }
            }
        }
        #[cfg(windows)]
        {
            hook_heap_windows!("ntdll", ntdll);
            hook_heap_windows!("win32u", win32u);
            hook_heap_windows!("ucrtbase", ucrtbase);
            hook_heap_windows!("kernelbase", kernelbase);
            hook_heap_windows!("kernel32", kernel32);
            hook_heap_windows!("msvcrt", msvcrt);
            hook_heap_windows!("api-ms-win-crt-private-l1-1-0", api_ms_win1);
            hook_heap_windows!("api-ms-win-crt-private-l1-1-0.dll", api_ms_win2);
            hook_heap_windows!("api-ms-win-core-heap-l1-1-0", api_ms_heap1);
            hook_heap_windows!("api-ms-win-core-heap-l2-1-0", api_ms_heap2);
            hook_heap_windows!(
                "api-ms-win-core-heap-obsolete-l1-1-0",
                api_ms_heap2_obsolete
            );
        }

        /*
        #[cfg(target_os = "linux")]
        let cpp_libs = [
            "libc++.so",
            "libc++.so.1",
            "libc++abi.so.1",
            "libc++_shared.so",
            "libstdc++.so",
            "libstdc++.so.6",
        ];

        #[cfg(target_vendor = "apple")]
        let cpp_libs = ["libc++.1.dylib", "libc++abi.dylib", "libsystem_c.dylib"];
        */

        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        macro_rules! hook_cpp {
           ($libname:literal, $lib_ident:ident) => {
            log::info!("Hooking c++ functions in {}", $libname);
            for export in Module::enumerate_exports($libname) {
                match &export.name[..] {
                    "_Znam" => {
                        hook_func!($libname, $lib_ident, _Znam, (size: usize), *mut c_void);
                    }
                    "_ZnamRKSt9nothrow_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZnamRKSt9nothrow_t,
                            (size: usize, _nothrow: *const c_void),
                            *mut c_void
                        );
                    }
                    "_ZnamSt11align_val_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZnamSt11align_val_t,
                            (size: usize, alignment: usize),
                            *mut c_void
                        );
                    }
                    "_ZnamSt11align_val_tRKSt9nothrow_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZnamSt11align_val_tRKSt9nothrow_t,
                            (size: usize, alignment: usize, _nothrow: *const c_void),
                            *mut c_void
                        );
                    }
                    "_Znwm" => {
                        hook_func!($libname, $lib_ident, _Znwm, (size: usize), *mut c_void);
                    }
                    "_ZnwmRKSt9nothrow_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZnwmRKSt9nothrow_t,
                            (size: usize, _nothrow: *const c_void),
                            *mut c_void
                        );
                    }
                    "_ZnwmSt11align_val_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZnwmSt11align_val_t,
                            (size: usize, alignment: usize),
                            *mut c_void
                        );
                    }
                    "_ZnwmSt11align_val_tRKSt9nothrow_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZnwmSt11align_val_tRKSt9nothrow_t,
                            (size: usize, alignment: usize, _nothrow: *const c_void),
                            *mut c_void
                        );
                    }
                    "_ZdaPv" => {
                        hook_func!($libname, $lib_ident, _ZdaPv, (ptr: *mut c_void), usize);
                    }
                    "_ZdaPvm" => {
                        hook_func!($libname, $lib_ident, _ZdaPvm, (ptr: *mut c_void, _ulong: u64), usize);
                    }
                    "_ZdaPvmSt11align_val_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZdaPvmSt11align_val_t,
                            (ptr: *mut c_void, _ulong: u64, _alignment: usize),
                            usize
                        );
                    }
                    "_ZdaPvRKSt9nothrow_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZdaPvRKSt9nothrow_t,
                            (ptr: *mut c_void, _nothrow: *const c_void),
                            usize
                        );
                    }
                    "_ZdaPvSt11align_val_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZdaPvSt11align_val_t,
                            (ptr: *mut c_void, _alignment: usize),
                            usize
                        );
                    }
                    "_ZdaPvSt11align_val_tRKSt9nothrow_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZdaPvSt11align_val_tRKSt9nothrow_t,
                            (ptr: *mut c_void, _alignment: usize, _nothrow: *const c_void),
                            usize
                        );
                    }
                    "_ZdlPv" => {
                        hook_func!($libname, $lib_ident, _ZdlPv, (ptr: *mut c_void), usize);
                    }
                    "_ZdlPvm" => {
                        hook_func!($libname, $lib_ident, _ZdlPvm, (ptr: *mut c_void, _ulong: u64), usize);
                    }
                    "_ZdlPvmSt11align_val_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZdlPvmSt11align_val_t,
                            (ptr: *mut c_void, _ulong: u64, _alignment: usize),
                            usize
                        );
                    }
                    "_ZdlPvRKSt9nothrow_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZdlPvRKSt9nothrow_t,
                            (ptr: *mut c_void, _nothrow: *const c_void),
                            usize
                        );
                    }
                    "_ZdlPvSt11align_val_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZdlPvSt11align_val_t,
                            (ptr: *mut c_void, _alignment: usize),
                            usize
                        );
                    }
                    "_ZdlPvSt11align_val_tRKSt9nothrow_t" => {
                        hook_func!(
                            $libname, $lib_ident,
                            _ZdlPvSt11align_val_tRKSt9nothrow_t,
                            (ptr: *mut c_void, _alignment: usize, _nothrow: *const c_void),
                            usize
                        );
                    }
                    _ => {}
                }
            }
           }
        }
        #[cfg(target_os = "linux")]
        {
            hook_cpp!("libc++.so", libcpp);
            hook_cpp!("libc++.so.1", libcpp1);
            hook_cpp!("libc++.so.1", libcpp1);
            hook_cpp!("libc++abi.so.1", libcppapi);
            hook_cpp!("libc++_shared.so", libcppshared);
            hook_cpp!("libstdc++.so", libstdcpp);
            hook_cpp!("libstdc++.so.6", libstdcpp6);
        }

        #[cfg(target_vendor = "apple")]
        {
            hook_cpp!("libc++.1.dylib", libcpp_darwin);
            hook_cpp!("libc++abi.dylib", libcppabi_darwin);
            hook_cpp!("libsystem_c.dylib", libsystem_c_darwin);
        }

        #[cfg(not(windows))]
        hook_func!(
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
        #[cfg(not(windows))]
        hook_func!(munmap, (addr: *const c_void, length: usize), i32);

        // Hook libc functions which may access allocated memory
        #[cfg(not(windows))]
        hook_func!(
            write,
            (fd: i32, buf: *const c_void, count: usize),
            usize
        );
        #[cfg(not(windows))]
        hook_func!(read, (fd: i32, buf: *mut c_void, count: usize), usize);
        hook_func!(
            fgets,
            (s: *mut c_void, size: u32, stream: *mut c_void),
            *mut c_void
        );
        hook_func!(
            memcmp,
            (s1: *const c_void, s2: *const c_void, n: usize),
            i32
        );
        hook_func!(
            memcpy,
            (dest: *mut c_void, src: *const c_void, n: usize),
            *mut c_void
        );
        #[cfg(not(any(target_vendor = "apple", windows)))]
        hook_func!(
            mempcpy,
            (dest: *mut c_void, src: *const c_void, n: usize),
            *mut c_void
        );
        // #[cfg(not(windows))]
        // hook_func!(
        //     None,
        //     memmove,
        //     (dest: *mut c_void, src: *const c_void, n: usize),
        //     *mut c_void
        // );
        hook_func!(
            memset,
            (s: *mut c_void, c: i32, n: usize),
            *mut c_void
        );
        hook_func!(
            memchr,
            (s: *mut c_void, c: i32, n: usize),
            *mut c_void
        );
        #[cfg(not(any(target_vendor = "apple", windows)))]
        hook_func!(
            memrchr,
            (s: *mut c_void, c: i32, n: usize),
            *mut c_void
        );
        #[cfg(not(windows))]
        hook_func!(
            memmem,
            (
                haystack: *const c_void,
                haystacklen: usize,
                needle: *const c_void,
                needlelen: usize
            ),
            *mut c_void
        );
        #[cfg(not(any(target_os = "android", windows)))]
        hook_func!(bzero, (s: *mut c_void, n: usize), usize);
        #[cfg(not(any(target_os = "android", target_vendor = "apple", windows)))]
        hook_func!(explicit_bzero, (s: *mut c_void, n: usize),usize);
        // #[cfg(not(any(target_os = "android", windows)))]
        // hook_func!(
        //     None,
        //     bcmp,
        //     (s1: *const c_void, s2: *const c_void, n: usize),
        //     i32
        // );
        hook_func!(strchr, (s: *mut c_char, c: i32), *mut c_char);
        hook_func!(strrchr, (s: *mut c_char, c: i32), *mut c_char);
        #[cfg(not(windows))]
        hook_func!(
            strcasecmp,
            (s1: *const c_char, s2: *const c_char),
            i32
        );
        #[cfg(not(windows))]
        hook_func!(
            strncasecmp,
            (s1: *const c_char, s2: *const c_char, n: usize),
            i32
        );
        hook_func!(
            strcat,
            (dest: *mut c_char, src: *const c_char),
            *mut c_char
        );
        hook_func!(strcmp, (s1: *const c_char, s2: *const c_char), i32);
        hook_func!(
            strncmp,
            (s1: *const c_char, s2: *const c_char, n: usize),
            i32
        );
        hook_func!(
            strcpy,
            (dest: *mut c_char, src: *const c_char),
            *mut c_char
        );
        hook_func!(
            strncpy,
            (dest: *mut c_char, src: *const c_char, n: usize),
            *mut c_char
        );
        #[cfg(not(windows))]
        hook_func!(
            stpcpy,
            (dest: *mut c_char, src: *const c_char),
            *mut c_char
        );
        #[cfg(not(windows))]
        hook_func!(strdup, (s: *const c_char), *mut c_char);
        #[cfg(windows)]
        hook_func!(_strdup, (s: *const c_char), *mut c_char);
        hook_func!(strlen, (s: *const c_char), usize);
        hook_func!(strnlen, (s: *const c_char, n: usize), usize);
        hook_func!(
            strstr,
            (haystack: *const c_char, needle: *const c_char),
            *mut c_char
        );
        #[cfg(not(windows))]
        hook_func!(
            strcasestr,
            (haystack: *const c_char, needle: *const c_char),
            *mut c_char
        );
        hook_func!(atoi, (nptr: *const c_char), i32);
        hook_func!(atol, (nptr: *const c_char), i32);
        hook_func!(atoll, (nptr: *const c_char), i64);
        hook_func!(wcslen, (s: *const wchar_t), usize);
        hook_func!(
            wcscpy,
            (dest: *mut wchar_t, src: *const wchar_t),
            *mut wchar_t
        );
        hook_func!(wcscmp, (s1: *const wchar_t, s2: *const wchar_t), i32);
        #[cfg(target_vendor = "apple")]
        hook_func!(
            memset_pattern4,
            (s: *mut c_void, c: *const c_void, n: usize),
            ()
        );
        #[cfg(target_vendor = "apple")]
        hook_func!(
            memset_pattern8,
            (s: *mut c_void, c: *const c_void, n: usize),
            ()
        );
        #[cfg(target_vendor = "apple")]
        hook_func!(
            memset_pattern16,
            (s: *mut c_void, c: *const c_void, n: usize),
            ()
        );
    }

    /// Deregister all the hooks
    fn deregister_hooks(&mut self, gum: &Gum) {
        /*This is terrible code and should be replaced as soon as possible.

        This is basically a bandaid solution that happens to work because 2 different Interceptor::obtains will return the same interceptor.

        Ideally the interceptor should be stored in AsanRuntime, but because FridaRuntime has a 'static bound it becomes difficult to introduce that.
        */
        let mut interceptor = Interceptor::obtain(gum);
        for hook in &self.hooks {
            interceptor.revert(*hook);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::too_many_lines)]
    extern "system" fn handle_trap(&mut self) {
        self.disable_hooks();

        self.dump_registers();

        let fault_address = self.regs[17];
        let actual_pc = self.regs[18];

        let decoder = InstDecoder::minimal();

        let instructions: Vec<Instruction> = disas_count(
            &decoder,
            unsafe { std::slice::from_raw_parts(actual_pc as *mut u8, 24) },
            3,
        );

        let insn = instructions[0]; // This is the very instruction that has triggered fault
        log::info!(
            "Fault Instruction: {}",
            insn.display_with(DisplayStyle::Intel).to_string()
        );
        let operand_count = insn.operand_count();

        let mut access_type: Option<AccessType> = None;
        let mut regs: Option<(X86Register, X86Register, i32)> = None;
        for operand_idx in 0..operand_count {
            let operand = insn.operand(operand_idx);
            if operand.is_memory() {
                // The order is like in Intel, not AT&T
                // So a memory read looks like
                //      mov    edx,DWORD PTR [rax+0x14]
                // not  mov    0x14(%rax),%edx
                access_type = if operand_idx == 0 {
                    Some(AccessType::Write)
                } else {
                    Some(AccessType::Read)
                };
                if let Some((basereg, indexreg, _, disp)) = operand_details(&operand) {
                    regs = Some((basereg, indexreg, disp));
                }
            }
        }

        let backtrace = Backtrace::new();
        let (stack_start, stack_end) = Self::current_stack();

        if let Some(r) = regs {
            let base = self.register_idx(r.0); // safe to unwrap
            let index = self.register_idx(r.1);
            let disp = r.2;

            let (base_idx, base_value) = match base {
                Some((idx, size)) => {
                    let value = if size == 64 {
                        Some(self.regs[idx as usize])
                    } else {
                        Some(self.regs[idx as usize] & 0xffffffff)
                    };
                    (Some(idx), value)
                }
                _ => (None, None),
            };

            let index_idx = match index {
                Some((idx, _)) => Some(idx),
                _ => None,
            };

            // log::trace!("{:x}", base_value);
            #[allow(clippy::option_if_let_else)]
            let error = if fault_address >= stack_start && fault_address < stack_end {
                match access_type {
                    Some(typ) => match typ {
                        AccessType::Read => AsanError::StackOobRead((
                            self.regs,
                            actual_pc,
                            (base_idx, index_idx, disp as usize, fault_address),
                            backtrace,
                        )),
                        AccessType::Write => AsanError::StackOobWrite((
                            self.regs,
                            actual_pc,
                            (base_idx, index_idx, disp as usize, fault_address),
                            backtrace,
                        )),
                    },
                    None => AsanError::Unknown((
                        self.regs,
                        actual_pc,
                        (base_idx, index_idx, disp as usize, fault_address),
                        backtrace,
                    )),
                }
            } else if base_value.is_some() {
                if let Some(metadata) = self
                    .allocator
                    .find_metadata(fault_address, base_value.unwrap())
                {
                    match access_type {
                        Some(typ) => {
                            let asan_readwrite_error = AsanReadWriteError {
                                registers: self.regs,
                                pc: actual_pc,
                                fault: (base_idx, index_idx, disp as usize, fault_address),
                                metadata: metadata.clone(),
                                backtrace,
                            };
                            match typ {
                                AccessType::Read => {
                                    if metadata.freed {
                                        AsanError::ReadAfterFree(asan_readwrite_error)
                                    } else {
                                        AsanError::OobRead(asan_readwrite_error)
                                    }
                                }
                                AccessType::Write => {
                                    if metadata.freed {
                                        AsanError::WriteAfterFree(asan_readwrite_error)
                                    } else {
                                        AsanError::OobWrite(asan_readwrite_error)
                                    }
                                }
                            }
                        }
                        None => AsanError::Unknown((
                            self.regs,
                            actual_pc,
                            (base_idx, index_idx, disp as usize, fault_address),
                            backtrace,
                        )),
                    }
                } else {
                    AsanError::Unknown((
                        self.regs,
                        actual_pc,
                        (base_idx, index_idx, disp as usize, fault_address),
                        backtrace,
                    ))
                }
            } else {
                AsanError::Unknown((
                    self.regs,
                    actual_pc,
                    (base_idx, index_idx, disp as usize, fault_address),
                    backtrace,
                ))
            };
            AsanErrors::get_mut_blocking().report_error(error);

            // This is not even a mem instruction??
        } else {
            AsanErrors::get_mut_blocking().report_error(AsanError::Unknown((
                self.regs,
                actual_pc,
                (None, None, 0, fault_address),
                backtrace,
            )));
        }

        // log::info!("ASAN Error, attach the debugger!");
        // // Sleep for 1 minute to give the user time to attach a debugger
        // std::thread::sleep(std::time::Duration::from_secs(60));

        // self.dump_registers();
        self.enable_hooks();
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::cast_sign_loss)] // for displacement
    #[allow(clippy::too_many_lines)]
    extern "system" fn handle_trap(&mut self) {
        self.disable_hooks();
        let mut actual_pc = self.regs[31];
        actual_pc = match self.stalked_addresses.get(&actual_pc) {
            //get the pc associated with the trapped insn
            Some(addr) => *addr,
            None => actual_pc,
        };

        let decoder = <ARMv8 as Arch>::Decoder::default();

        let insn = disas_count(
            &decoder,
            unsafe { std::slice::from_raw_parts(actual_pc as *mut u8, 4) },
            1,
        )[0];

        if insn.opcode == Opcode::MSR && insn.operands[0] == Operand::SystemReg(23056) { //the first operand is nzcv
             //What case is this for??
             /*insn = instructions.get(2).unwrap();
             actual_pc = insn.address() as usize;*/
        }

        let operands_len = insn
            .operands
            .iter()
            .position(|item| *item == Operand::Nothing)
            .unwrap_or(4);

        //the memory operand is always the last operand in aarch64
        let (base_reg, index_reg, displacement) = match insn.operands[operands_len - 1] {
            Operand::RegRegOffset(reg1, reg2, _, _, _) => (reg1, Some(reg2), 0),
            Operand::RegPreIndex(reg, disp, _) => (reg, None, disp),
            Operand::RegPostIndex(reg, _) => {
                //in post index the disp is applied after so it doesn't matter for this memory access
                (reg, None, 0)
            }
            Operand::RegPostIndexReg(reg, _) => (reg, None, 0),
            _ => {
                return;
            }
        };

        #[allow(clippy::cast_possible_wrap)]
        let fault_address =
            (self.regs[base_reg as usize] as isize + displacement as isize) as usize;

        let backtrace = Backtrace::new();

        let (stack_start, stack_end) = Self::current_stack();
        #[allow(clippy::option_if_let_else)]
        let error = if fault_address >= stack_start && fault_address < stack_end {
            if insn.opcode.to_string().starts_with('l') {
                AsanError::StackOobRead((
                    self.regs,
                    actual_pc,
                    (
                        Some(base_reg),
                        Some(index_reg.unwrap_or(0xffff)),
                        displacement as usize,
                        fault_address,
                    ),
                    backtrace,
                ))
            } else {
                AsanError::StackOobWrite((
                    self.regs,
                    actual_pc,
                    (
                        Some(base_reg),
                        Some(index_reg.unwrap_or(0xffff)),
                        displacement as usize,
                        fault_address,
                    ),
                    backtrace,
                ))
            }
        } else if let Some(metadata) = self
            .allocator
            .find_metadata(fault_address, self.regs[base_reg as usize])
        {
            let asan_readwrite_error = AsanReadWriteError {
                registers: self.regs,
                pc: actual_pc,
                fault: (
                    Some(base_reg),
                    Some(index_reg.unwrap_or(0xffff)),
                    displacement as usize,
                    fault_address,
                ),
                metadata: metadata.clone(),
                backtrace,
            };
            if insn.opcode.to_string().starts_with('l') {
                if metadata.freed {
                    AsanError::ReadAfterFree(asan_readwrite_error)
                } else {
                    AsanError::OobRead(asan_readwrite_error)
                }
            } else if metadata.freed {
                AsanError::WriteAfterFree(asan_readwrite_error)
            } else {
                AsanError::OobWrite(asan_readwrite_error)
            }
        } else {
            AsanError::Unknown((
                self.regs,
                actual_pc,
                (
                    Some(base_reg),
                    Some(index_reg.unwrap_or(0xffff)),
                    displacement as usize,
                    fault_address,
                ),
                backtrace,
            ))
        };
        AsanErrors::get_mut_blocking().report_error(error);
        self.enable_hooks();
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::unused_self)]
    fn register_idx(&self, reg: X86Register) -> Option<(u16, u16)> {
        match reg {
            X86Register::Eax => Some((0, 32)),
            X86Register::Ecx => Some((2, 32)),
            X86Register::Edx => Some((3, 32)),
            X86Register::Ebx => Some((1, 32)),
            X86Register::Esp => Some((5, 32)),
            X86Register::Ebp => Some((4, 32)),
            X86Register::Esi => Some((6, 32)),
            X86Register::Edi => Some((7, 32)),
            X86Register::R8d => Some((8, 32)),
            X86Register::R9d => Some((9, 32)),
            X86Register::R10d => Some((10, 32)),
            X86Register::R11d => Some((11, 32)),
            X86Register::R12d => Some((12, 32)),
            X86Register::R13d => Some((13, 32)),
            X86Register::R14d => Some((14, 32)),
            X86Register::R15d => Some((15, 32)),
            X86Register::Eip => Some((18, 32)),
            X86Register::Rax => Some((0, 4)),
            X86Register::Rcx => Some((2, 4)),
            X86Register::Rdx => Some((3, 4)),
            X86Register::Rbx => Some((1, 4)),
            X86Register::Rsp => Some((5, 4)),
            X86Register::Rbp => Some((4, 4)),
            X86Register::Rsi => Some((6, 4)),
            X86Register::Rdi => Some((7, 4)),
            X86Register::R8 => Some((8, 64)),
            X86Register::R9 => Some((9, 64)),
            X86Register::R10 => Some((10, 64)),
            X86Register::R11 => Some((11, 64)),
            X86Register::R12 => Some((12, 64)),
            X86Register::R13 => Some((13, 64)),
            X86Register::R14 => Some((14, 64)),
            X86Register::R15 => Some((15, 64)),
            X86Register::Rip => Some((18, 64)),
            _ => None,
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn dump_registers(&self) {
        log::info!("rax: {:x}", self.regs[0]);
        log::info!("rbx: {:x}", self.regs[1]);
        log::info!("rcx: {:x}", self.regs[2]);
        log::info!("rdx: {:x}", self.regs[3]);
        log::info!("rbp: {:x}", self.regs[4]);
        log::info!("rsp: {:x}", self.regs[5]);
        log::info!("rsi: {:x}", self.regs[6]);
        log::info!("rdi: {:x}", self.regs[7]);
        log::info!("r8: {:x}", self.regs[8]);
        log::info!("r9: {:x}", self.regs[9]);
        log::info!("r10: {:x}", self.regs[10]);
        log::info!("r11: {:x}", self.regs[11]);
        log::info!("r12: {:x}", self.regs[12]);
        log::info!("r13: {:x}", self.regs[13]);
        log::info!("r14: {:x}", self.regs[14]);
        log::info!("r15: {:x}", self.regs[15]);
        log::info!("instrumented rip: {:x}", self.regs[16]);
        log::info!("fault address: {:x}", self.regs[17]);
        log::info!("actual rip: {:x}", self.regs[18]);
        log::info!("stack: ");
        for i in 0..32 {
            log::info!("{:x}", unsafe {
                ((self.regs[5] + i * 8) as *const u64).read()
            });
        }
    }

    // https://godbolt.org/z/ah8vG8sWo
    /*
    #include <stdio.h>
    #include <stdint.h>
    uint8_t shadow_bit = 8;
    uint8_t bit = 3;
    uint64_t result = 0;
    void handle_trap(uint64_t true_rip);
    uint64_t generate_shadow_check_blob(uint64_t start, uint64_t true_rip){
        uint64_t shadow_base = (1ULL << shadow_bit);
        if (shadow_base * 3 > start || start >= shadow_base *4)
            return 0;

        uint64_t addr = 0;
        addr = addr + (start >> 3);
        uint64_t mask = (1ULL << (shadow_bit + 1)) - 1;

        addr = addr & mask;
        addr = addr + (1ULL << shadow_bit);

        uint8_t remainder = start & 0b111;
        uint16_t val = *(uint16_t *)addr;
        val = (val >> remainder);

        uint8_t mask2 = (1 << bit) - 1;
        if((val & mask2) != mask2){
            // failure
            handle_trap(true_rip);
        }
        return 0;

    }
    */

    /*

    FRIDA ASAN IMPLEMENTATION DETAILS

    The format of Frida's ASAN is signficantly different from LLVM ASAN.

    In Frida ASAN, we attempt to find the lowest possible bit such that there is no mapping with that bit. That is to say, for some bit x, there is no mapping greater than
    1 << x. This is our shadow base and is similar to Ultra compact shadow in LLVM ASAN. Unlike ASAN where 0 represents a poisoned byte and 1 represents an unpoisoned byte, in Frida-ASAN

    The reasoning for this is that new pages are zeroed, so, by default, every qword is poisoned and we must explicitly unpoison any byte.

    Much like LLVM ASAN, shadow bytes are qword based. This is to say that each shadow byte maps to one qword. The shadow calculation is as follows:
    (1ULL << shadow_bit) | (address >> 3)

    The format of a shadow bit is a bitmask. Each bit represents if a byte in the qword is valid starting from the first bit. So, something like 0b11100000 indicates that only the first 3 bytes in the associated qword are valid.

    */
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::unused_self)]
    fn generate_shadow_check_blob(&mut self, size: u32) -> Box<[u8]> {
        let shadow_bit = self.allocator.shadow_bit();
        // Rcx, Rax, Rdi, Rdx, Rsi, R8 are used, so we save them in emit_shadow_check
        //at this point RDI contains the
        let mask_shift = 32 - size;
        macro_rules! shadow_check{
            ($ops:ident, $bit:expr) => {dynasm!($ops
                ;   .arch x64
               // ; int3
                ; mov     rdx, 1
                ; shl     rdx, shadow_bit as i8 //rdx = shadow_base
                ; mov rcx, rdi //copy address into rcx
                ; and rcx, 7 //remainder
                ; shr rdi, 3 //start >> 3
                ; add rdi, rdx //shadow_base + (start >> 3)
                ; mov edx, [rdi]  //load 4 shadow bytes. We load 4 just in case of an unaligned access
                ; bswap edx  //bswap to get it into an acceptable form
                ; shl edx, cl //this shifts by the unaligned access offset. why does x86 require cl...
                ; mov edi, -1 //fill edi with all 1s
                ; shl edi, mask_shift as i8 //edi now contains mask. this shl functionally creates a bitmask with the top `size` bits as 1s
                ; and edx, edi //and it to see if the top bits are enabled in edx
                ; cmp edx, edi //if the mask and the and'd value are the same, we're good
                ; je      >done
                ; lea     rsi, [>done] // leap 10 bytes forward
                ; nop // jmp takes 10 bytes at most so we want to allocate 10 bytes buffer (?)
                ; nop
                ; nop
                ; nop
                ; nop
                ; nop
                ; nop
                ; nop
                ; nop
                ; nop
                ;done:
            );};
        }
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        shadow_check!(ops, bit);
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len() - 10].to_vec().into_boxed_slice() //subtract 10 because we don't need the last nop
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::unused_self)]
    fn generate_shadow_check_blob(&mut self, width: u32) -> Box<[u8]> {
        /*x0 contains the shadow address
        x0 and x1 are saved by the asan_check
        The maximum size this supports is up to 25 bytes. This is because we load 4 bytes of the shadow value. And, in the case that we have a misaligned address with an offset of 7 into the word. For example, if we load 25 bytes from 0x1007 - [0x1007,0x101f], then we require the shadow values from 0x1000, 0x1008, 0x1010, and 0x1018 */

        let shadow_bit = self.allocator.shadow_bit();
        macro_rules! shadow_check {
            ($ops:ident, $width:expr) => {dynasm!($ops
                ; .arch aarch64
//              ; brk #0xe
                ; stp x2, x3, [sp, #-0x10]!
                ; mov x1, xzr
                // ; add x1, xzr, x1, lsl #shadow_bit
                ; add x1, x1, x0, lsr #3
                ; ubfx x1, x1, #0, #(shadow_bit + 1)
                ; mov x2, #1
                ; add x1, x1, x2, lsl #shadow_bit
                ; ldr w1, [x1, #0] //w1 contains our shadow check
                ; and x0, x0, #7 //x0 is the offset for unaligned accesses
                ; rev32 x1, x1
                ; rbit w1, w1
                ; lsr w1, w1, w0 //x1 now contains our shadow value
                ; ldp x2, x3, [sp], 0x10
                ; mov w0, #1
                ; add w0, wzr, w0, LSL #$width
                ; sub w0, w0, #1 //x0 now contains our bitmask
                ; and w1, w0, w1 //and the bitmask and the shadow value
                ; cmp w0, w1 //our bitmask and shadow & mask must be the same
                ; b.eq >done
                ; adr x1, >done
                ; nop // will be replaced by b to report
                ; done:
            );};
        }

        let mut ops = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        shadow_check!(ops, width);
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len() - 4].to_vec().into_boxed_slice() //we don't need the last nop so subtract by 4
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::unused_self)]
    fn generate_shadow_check_large_blob(&mut self, width: u32) -> Box<[u8]> {
        //x0 contains the shadow address
        //x0 and x1 are saved by the asan_check
        //large blobs require 16 byte alignment as they are only possible with vector insns, so just abuse that

        //This is used for checking shadow blobs that are larger than 25 bytes

        assert!(width <= 64, "width must be <= 64");
        let shift = 64 - width;
        let shadow_bit = self.allocator.shadow_bit();
        macro_rules! shadow_check_exact {
            ($ops:ident, $shift:expr) => {dynasm!($ops
                ; .arch aarch64

                ; stp x2, x3, [sp, #-0x10]!
                ; mov x1, xzr
                // ; add x1, xzr, x1, lsl #shadow_bit
                ; add x1, x1, x0, lsr #3
                ; ubfx x1, x1, #0, #(shadow_bit + 1)
                ; mov x2, #1
                ; add x1, x1, x2, lsl #shadow_bit
                ; ldr x1, [x1, #0] //x1 contains our shadow check
                ; rev64 x1, x1
                ; rbit x1, x1 //x1 now contains our shadow value
                ; ldp x2, x3, [sp], 0x10
                ; mov x0, xzr
                ; sub x0, x0, #1 //gives us all 1s
                ; lsr x0, x0, #$shift //x0 now contains our bitmask
                ; and x1, x0, x1 //and the bitmask and the shadow value and put it in x1
                ; cmp x0, x1 //our bitmask and shadow & mask must be the same to ensure that the bytes are valid
                ; b.eq >done
                ; adr x1, >done
                ; nop // will be replaced by b to report
                ; done:
            );};
        }

        let mut ops = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        shadow_check_exact!(ops, shift);
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len() - 4].to_vec().into_boxed_slice()
    }

    // Save registers into self_regs_addr
    // Five registers, Rdi, Rsi, Rdx, Rcx, Rax are saved in emit_shadow_check before entering this function
    // So we retrieve them after saving other registers
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::similar_names)]
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::too_many_lines)]
    fn generate_instrumentation_blobs(&mut self) {
        let mut ops_report = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        dynasm!(ops_report
            ; .arch x64
            ; report:
            ; mov rdi, [>self_regs_addr] // load self.regs into rdi
            ; mov [rdi + 0x80], rsi // return address is loaded into rsi in generate_shadow_check_blob. rsi is the address of done
            ; mov [rdi + 0x8], rbx
            ; mov [rdi + 0x20], rbp
            ; mov [rdi + 0x28], rsp
            ; mov [rdi + 0x40], r8
            ; mov [rdi + 0x48], r9
            ; mov [rdi + 0x50], r10
            ; mov [rdi + 0x58], r11
            ; mov [rdi + 0x60], r12
            ; mov [rdi + 0x68], r13
            ; mov [rdi + 0x70], r14
            ; mov [rdi + 0x78], r15
            ; mov rax, [rsp + 0x10]
            ; mov [rdi + 0x0], rax
            ; mov rcx, [rsp + 0x18]
            ; mov [rdi + 0x10], rcx
            ; mov rdx, [rsp + 0x20]
            ; mov [rdi + 0x18], rdx
            ; mov rsi, [rsp + 0x28]
            ; mov [rdi + 0x30], rsi

            ; mov rsi, [rsp + 0x0]  // access_addr
            ; mov [rdi + 0x88], rsi
            ; mov rsi, [rsp + 0x8] // true_rip
            ; mov [rdi + 0x90], rsi

            ; mov rsi, rdi // we want to save rdi, but we have to copy the address of self.regs into another register
            ; mov rdi, [rsp + 0x30]
            ; mov [rsi + 0x38], rdi

            ; mov rdi, [>self_addr]
            ; mov rcx, [>self_addr]
            ; mov rsi, [>trap_func]

            // Align the rsp to 16bytes boundary
            // This adds either -8 or -16 to the currrent rsp.
            // rsp is restored later from self.regs
            ; add rsp, -8
            ; and rsp, -16

            ; call rsi

            ; mov rdi, [>self_regs_addr]
            // restore rbx to r15
            ; mov rbx, [rdi + 0x8]
            ; mov rbp, [rdi + 0x20]
            ; mov rsp, [rdi + 0x28]
            ; mov r8, [rdi + 0x40]
            ; mov r9, [rdi + 0x48]
            ; mov r10, [rdi + 0x50]
            ; mov r11, [rdi + 0x58]
            ; mov r12, [rdi + 0x60]
            ; mov r13, [rdi + 0x68]
            ; mov r14, [rdi + 0x70]
            ; mov r15, [rdi + 0x78]
            ; mov rsi, [rdi + 0x80] // load back >done into rsi
            ; jmp rsi

            // Ignore eh_frame_cie for amd64
            // See discussions https://github.com/AFLplusplus/LibAFL/pull/331
            ;->accessed_address:
            ; .dword 0x0
            ; self_addr:
            ; .qword core::ptr::from_mut(self) as *mut c_void as i64
            ; self_regs_addr:
            ; .qword addr_of_mut!(self.regs) as i64
            ; trap_func:
            ; .qword AsanRuntime::handle_trap as *mut c_void as i64
        );
        self.blob_report = Some(ops_report.finalize().unwrap().into_boxed_slice());

        self.blob_check_mem_byte = Some(self.generate_shadow_check_blob(1));
        self.blob_check_mem_halfword = Some(self.generate_shadow_check_blob(2));
        self.blob_check_mem_dword = Some(self.generate_shadow_check_blob(4));
        self.blob_check_mem_qword = Some(self.generate_shadow_check_blob(8));
        self.blob_check_mem_16bytes = Some(self.generate_shadow_check_blob(16));
    }

    ///
    /// Generate the instrumentation blobs for the current arch.
    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::similar_names)] // We allow things like dword and qword
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::too_many_lines)]
    fn generate_instrumentation_blobs(&mut self) {
        let mut ops_report = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        dynasm!(ops_report
            ; .arch aarch64

            ; report:
            ; stp x29, x30, [sp, #-0x10]!
            ; mov x29, sp
            // save the nvcz and the 'return-address'/address of instrumented instruction
            ; stp x0, x1, [sp, #-0x10]!

            ; ldr x0, >self_regs_addr
            ; stp x2, x3, [x0, #0x10]
            ; stp x4, x5, [x0, #0x20]
            ; stp x6, x7, [x0, #0x30]
            ; stp x8, x9, [x0, #0x40]
            ; stp x10, x11, [x0, #0x50]
            ; stp x12, x13, [x0, #0x60]
            ; stp x14, x15, [x0, #0x70]
            ; stp x16, x17, [x0, #0x80]
            ; stp x18, x19, [x0, #0x90]
            ; stp x20, x21, [x0, #0xa0]
            ; stp x22, x23, [x0, #0xb0]
            ; stp x24, x25, [x0, #0xc0]
            ; stp x26, x27, [x0, #0xd0]
            ; stp x28, x29, [x0, #0xe0]
            ; stp x30, xzr, [x0, #0xf0]
            ; mov x28, x0

            ; mov x25, x1 // address of instrumented instruction.
            ; str x25, [x28, 0xf8]

            ; .dword 0xd53b4218u32 as i32 // mrs x24, nzcv
            ; ldp x0, x1, [sp, 0x20]
            ; stp x0, x1, [x28]

            ; adr x25, <report
            ; adr x15, >eh_frame_cie_addr
            ; ldr x15, [x15]
            ; add x0, x15, ASAN_EH_FRAME_FDE_OFFSET // eh_frame_fde
            ; add x27, x15, ASAN_EH_FRAME_FDE_ADDRESS_OFFSET // fde_address
            ; ldr w26, [x27]
            ; cmp w26, #0x0
            ; b.ne >skip_register
            ; sub x25, x25, x27
            ; str w25, [x27]
            ; ldr x1, >register_frame_func
            //; brk #11
            ; blr x1
            ; skip_register:
            ; ldr x0, >self_addr
            ; ldr x1, >trap_func
            ; blr x1

            ; .dword 0xd51b4218u32 as i32 // msr nzcv, x24
            ; ldr x0, >self_regs_addr
            ; ldp x2, x3, [x0, #0x10]
            ; ldp x4, x5, [x0, #0x20]
            ; ldp x6, x7, [x0, #0x30]
            ; ldp x8, x9, [x0, #0x40]
            ; ldp x10, x11, [x0, #0x50]
            ; ldp x12, x13, [x0, #0x60]
            ; ldp x14, x15, [x0, #0x70]
            ; ldp x16, x17, [x0, #0x80]
            ; ldp x18, x19, [x0, #0x90]
            ; ldp x20, x21, [x0, #0xa0]
            ; ldp x22, x23, [x0, #0xb0]
            ; ldp x24, x25, [x0, #0xc0]
            ; ldp x26, x27, [x0, #0xd0]
            ; ldp x28, x29, [x0, #0xe0]
            ; ldp x30, xzr, [x0, #0xf0]

            // restore nzcv. and 'return address'
            ; ldp x0, x1, [sp], #0x10
            ; ldp x29, x30, [sp], #0x10
            ; br x1 // go back to the 'return address'

            ; self_addr:
            ; .qword core::ptr::from_mut(self) as *mut c_void as i64
            ; self_regs_addr:
            ; .qword addr_of_mut!(self.regs) as i64
            ; trap_func:
            ; .qword AsanRuntime::handle_trap as *mut c_void as i64
            ; register_frame_func:
            ; .qword __register_frame as *mut c_void as i64
            ; eh_frame_cie_addr:
            ; .qword addr_of_mut!(self.eh_frame) as i64
        );
        self.eh_frame = [
            0x14, 0, 0x00527a01, 0x011e7c01, 0x001f0c1b, //
            // eh_frame_fde
            0x14, 0x18, //
            // fde_address
            0, // <-- address offset goes here
            0x104,
            // advance_loc 12
            // def_cfa r29 (x29) at offset 16
            // offset r30 (x30) at cfa-8
            // offset r29 (x29) at cfa-16
            0x1d0c4c00, 0x9d029e10, 0x4, //
            // empty next FDE:
            0, 0,
        ];

        self.blob_report = Some(ops_report.finalize().unwrap().into_boxed_slice());

        self.blob_check_mem_byte = Some(self.generate_shadow_check_blob(1));
        self.blob_check_mem_halfword = Some(self.generate_shadow_check_blob(2));
        self.blob_check_mem_dword = Some(self.generate_shadow_check_blob(4));
        self.blob_check_mem_qword = Some(self.generate_shadow_check_blob(8));
        self.blob_check_mem_16bytes = Some(self.generate_shadow_check_blob(16));

        self.blob_check_mem_3bytes = Some(self.generate_shadow_check_blob(3)); //the below are all possible with vector intrinsics
        self.blob_check_mem_6bytes = Some(self.generate_shadow_check_blob(6));
        self.blob_check_mem_12bytes = Some(self.generate_shadow_check_blob(12));
        self.blob_check_mem_24bytes = Some(self.generate_shadow_check_blob(24));
        self.blob_check_mem_32bytes = Some(self.generate_shadow_check_large_blob(32)); //this is possible with ldp q0, q1, [sp]. This must at least 16 byte aligned
        self.blob_check_mem_48bytes = Some(self.generate_shadow_check_large_blob(48));
        self.blob_check_mem_64bytes = Some(self.generate_shadow_check_large_blob(64));
    }

    /// Get the blob which implements the report funclet
    #[must_use]
    #[inline]
    pub fn blob_report(&self) -> &[u8] {
        self.blob_report.as_ref().unwrap()
    }

    /// Get the blob which checks a byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_byte(&self) -> &[u8] {
        self.blob_check_mem_byte.as_ref().unwrap()
    }

    /// Get the blob which checks a halfword access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_halfword(&self) -> &[u8] {
        self.blob_check_mem_halfword.as_ref().unwrap()
    }

    /// Get the blob which checks a dword access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_dword(&self) -> &[u8] {
        self.blob_check_mem_dword.as_ref().unwrap()
    }

    /// Get the blob which checks a qword access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_qword(&self) -> &[u8] {
        self.blob_check_mem_qword.as_ref().unwrap()
    }

    /// Get the blob which checks a 16 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_16bytes(&self) -> &[u8] {
        self.blob_check_mem_16bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 3 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_3bytes(&self) -> &[u8] {
        self.blob_check_mem_3bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 6 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_6bytes(&self) -> &[u8] {
        self.blob_check_mem_6bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 12 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_12bytes(&self) -> &[u8] {
        self.blob_check_mem_12bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 24 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_24bytes(&self) -> &[u8] {
        self.blob_check_mem_24bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 32 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_32bytes(&self) -> &[u8] {
        self.blob_check_mem_32bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 48 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_48bytes(&self) -> &[u8] {
        self.blob_check_mem_48bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 64 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_64bytes(&self) -> &[u8] {
        self.blob_check_mem_64bytes.as_ref().unwrap()
    }

    /// Determine if the instruction is 'interesting' for the purposes of ASAN
    #[cfg(target_arch = "aarch64")]
    #[must_use]
    #[inline]
    #[allow(clippy::similar_names, clippy::type_complexity)]
    pub fn asan_is_interesting_instruction(
        decoder: InstDecoder,
        _address: u64,
        instr: &Insn,
    ) -> Option<(
        u16,                      //reg1
        Option<(u16, SizeCode)>, //size of reg2. This needs to be an option in the case that we don't have one
        i32,                     //displacement.
        u32,                     //load/store size
        Option<(ShiftStyle, u8)>, //(shift type, shift size)
    )> {
        let instr = disas_count(&decoder, instr.bytes(), 1)[0];
        // We have to ignore these instructions. Simulating them with their side effects is
        // complex, to say the least.
        match instr.opcode {
            Opcode::LDAXR
            | Opcode::STLXR
            | Opcode::LDXR
            | Opcode::LDAR
            | Opcode::STLR
            | Opcode::LDARB
            | Opcode::LDAXP
            | Opcode::LDAXRB
            | Opcode::LDAXRH
            | Opcode::STLRB
            | Opcode::STLRH
            | Opcode::STLXP
            | Opcode::STLXRB
            | Opcode::STLXRH
            | Opcode::LDXRB
            | Opcode::LDXRH
            | Opcode::STXRB
            | Opcode::STXRH => {
                return None;
            }
            _ => (),
        }
        //we need to do this convuluted operation because operands in yaxpeax are in a constant slice of size 4,
        //and any unused operands are Operand::Nothing
        let operands_len = instr
            .operands
            .iter()
            .position(|item| *item == Operand::Nothing)
            .unwrap_or(4);
        if operands_len < 2 {
            return None;
        }

        /*if instr.opcode == Opcode::LDRSW || instr.opcode == Opcode::LDR {
            //this is a special case for pc-relative loads. The only two opcodes capable of this are LDR and LDRSW
            // For more information on this, look up "literal" loads in the ARM docs.
            match instr.operands[1] {
                //this is safe because an ldr is guranteed to have at least 3 operands
                Operand::PCOffset(off) => {
                    return Some((32, None, off, memory_access_size, None));
                }
                _ => (),
            }
        }*/

        // println!("{:?} {}", instr, memory_access_size);
        //abuse the fact that the last operand is always the mem operand
        #[allow(clippy::let_and_return)]
        match instr.operands[operands_len - 1] {
            Operand::RegRegOffset(reg1, reg2, size, shift, shift_size) => {
                let ret = Some((
                    reg1,
                    Some((reg2, size)),
                    0,
                    instruction_width(&instr),
                    Some((shift, shift_size)),
                ));
                // log::trace!("Interesting instruction: {}, {:?}", instr.to_string(), ret);
                ret
            }
            Operand::RegPreIndex(reg, disp, _) => {
                let ret = Some((reg, None, disp, instruction_width(&instr), None));
                // log::trace!("Interesting instruction: {}, {:?}", instr.to_string(), ret);
                ret
            }
            Operand::RegPostIndex(reg, _) => {
                //in post index the disp is applied after so it doesn't matter for this memory access
                let ret = Some((reg, None, 0, instruction_width(&instr), None));
                // log::trace!("Interesting instruction: {}, {:?}", instr.to_string(), ret);
                ret
            }
            Operand::RegPostIndexReg(reg, _) => {
                let ret = Some((reg, None, 0, instruction_width(&instr), None));
                //  log::trace!("Interesting instruction: {}, {:?}", instr.to_string(), ret);
                ret
            }
            _ => None,
        }
    }

    /// Checks if the current instruction is interesting for address sanitization.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[must_use]
    #[allow(clippy::result_unit_err)]
    pub fn asan_is_interesting_instruction(
        decoder: InstDecoder,
        address: u64,
        instr: &Insn,
    ) -> Option<(u8, X86Register, X86Register, u8, i32)> {
        let result = frida_to_cs(decoder, instr);

        if let Err(e) = result {
            log::error!("{}", e);
            return None;
        }

        let cs_instr = result.unwrap();

        let mut operands = vec![];
        for operand_idx in 0..cs_instr.operand_count() {
            operands.push(cs_instr.operand(operand_idx));
        }

        // Ignore lea instruction
        // put nop into the white-list so that instructions like
        // like `nop dword [rax + rax]` does not get caught.
        match cs_instr.opcode() {
            Opcode::LEA | Opcode::NOP => return None,

            _ => (),
        }

        // This is a TODO! In this case, both the src and the dst are mem operand
        // so we would need to return two operadns?
        if cs_instr.prefixes.rep_any() {
            return None;
        }

        log::trace!("{:#x} {:#?} {:#?}", address, cs_instr, cs_instr.to_string());

        for operand in operands {
            if operand.is_memory() {
                // log::trace!("{:#?}", operand);
                // if we reach this point
                // because in x64 there's no mem to mem inst, just return the first memory operand

                if let Some((basereg, indexreg, scale, disp)) = operand_details(&operand) {
                    // if the base register is rip, then it is a pc-relative access
                    // and does not deal with dynamically allocated memory
                    if basereg != X86Register::Rip {
                        let memsz = cs_instr.mem_size().unwrap().bytes_size().unwrap(); // this won't fail if it is mem access inst

                        // println!("{:#?} {:#?} {:#?}", cs_instr, cs_instr.to_string(), operand);
                        // println!("{:#?}", (memsz, basereg, indexreg, scale, disp));
                        log::trace!("ASAN Interesting operand {:#?}", operand);
                        log::trace!("{:#?}", (memsz, basereg, indexreg, scale, disp));
                        return Some((memsz, basereg, indexreg, scale, disp));
                    }
                } // else {} // perhaps avx instructions?
            }
        }

        None
    }

    /// Emits a asan shadow byte check.
    #[inline]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_arguments)]
    #[cfg(target_arch = "x86_64")]
    pub fn emit_shadow_check(
        &mut self,
        address: u64,
        output: &StalkerOutput,
        instruction_size: usize,
        width: u8,
        basereg: X86Register,
        indexreg: X86Register,
        scale: u8,
        disp: i32,
    ) {
        let redzone_size = isize::try_from(frida_gum_sys::GUM_RED_ZONE_SIZE).unwrap();
        let writer = output.writer();
        let true_rip = address;

        let basereg: Option<X86Register> = if basereg == X86Register::None {
            None
        } else {
            Some(basereg)
        };

        let indexreg = if indexreg == X86Register::None {
            None
        } else {
            Some(indexreg)
        };

        let scale = match scale {
            2 => 1,
            4 => 2,
            8 => 3,
            _ => 0,
        };
        if self.current_report_impl == 0
            || !writer.can_branch_directly_to(self.current_report_impl)
            || !writer.can_branch_directly_between(writer.pc() + 128, self.current_report_impl)
        {
            let after_report_impl = writer.code_offset() + 2;

            writer.put_jmp_near_label(after_report_impl);

            self.current_report_impl = writer.pc();
            writer.put_bytes(self.blob_report());

            writer.put_label(after_report_impl);
        }
        // if disp == 0x102 {
        //     log::trace!("BREAKING!");
        //     writer.put_bytes(&[0xcc]);
        // }

        /* Save registers that we'll use later in shadow_check_blob
                                        | addr  | rip   |
                                        | Rcx   | Rax   |
                                        | Rsi   | Rdx   |
            Old Rsp - (redzone_size) -> | flags | Rdi   |
                                        |       |       |
            Old Rsp                  -> |       |       |
        */
        writer.put_lea_reg_reg_offset(X86Register::Rsp, X86Register::Rsp, -(redzone_size));
        writer.put_pushfx();
        writer.put_push_reg(X86Register::Rdi);
        writer.put_push_reg(X86Register::Rsi);
        writer.put_push_reg(X86Register::Rdx);
        writer.put_push_reg(X86Register::Rcx);
        writer.put_push_reg(X86Register::Rax);
        writer.put_push_reg(X86Register::Rbp);
        writer.put_push_reg(X86Register::R8);
        /*
        Things are a bit different when Rip is either base register or index register.
        Suppose we have an instruction like
        `bnd jmp qword ptr [rip + 0x2e4b5]`
        We can't just emit code like
        `mov rdi, rip` to get RIP loaded into RDI,
        because this RIP is NOT the orginal RIP (, which is usually within .text) anymore, rather it is pointing to the memory allocated by the frida stalker.
        Please confer https://frida.re/docs/stalker/ for details.
        */
        // Init Rdi
        match basereg {
            Some(reg) => match reg {
                X86Register::Rip => {
                    writer
                        .put_mov_reg_address(X86Register::Rdi, true_rip + instruction_size as u64);
                }
                X86Register::Rsp => {
                    // In this case rsp clobbered
                    writer.put_lea_reg_reg_offset(
                        X86Register::Rdi,
                        X86Register::Rsp,
                        redzone_size + 0x8 * 7,
                    );
                }
                _ => {
                    writer.put_mov_reg_reg(X86Register::Rdi, basereg.unwrap());
                }
            },
            None => {
                writer.put_xor_reg_reg(X86Register::Rdi, X86Register::Rdi);
            }
        }

        match indexreg {
            Some(reg) => match reg {
                X86Register::Rip => {
                    writer
                        .put_mov_reg_address(X86Register::Rsi, true_rip + instruction_size as u64);
                }
                X86Register::Rdi => {
                    // In this case rdi is already clobbered, so we want it from the stack (we pushed rdi onto stack before!)
                    writer.put_mov_reg_reg_offset_ptr(X86Register::Rsi, X86Register::Rsp, 0x30);
                }
                X86Register::Rsp => {
                    // In this case rsp is also clobbered
                    writer.put_lea_reg_reg_offset(
                        X86Register::Rsi,
                        X86Register::Rsp,
                        redzone_size + 0x8 * 7,
                    );
                }
                _ => {
                    writer.put_mov_reg_reg(X86Register::Rsi, indexreg.unwrap());
                }
            },
            None => {
                writer.put_xor_reg_reg(X86Register::Rsi, X86Register::Rsi);
            }
        }

        // Scale
        if scale > 0 {
            // if scale == 3 {
            //     if let Some(X86Register::R8) = indexreg {
            //         writer.put_bytes(&[0xcc]);
            //     }
            // }kernel
            writer.put_shl_reg_u8(X86Register::Rsi, scale);
        }

        // Finally set Rdi to base + index * scale + disp
        writer.put_add_reg_reg(X86Register::Rdi, X86Register::Rsi);
        writer.put_lea_reg_reg_offset(X86Register::Rdi, X86Register::Rdi, disp as isize);

        writer.put_mov_reg_address(X86Register::Rsi, true_rip); // load true_rip into rsi in case we need them in handle_trap
        writer.put_push_reg(X86Register::Rsi); // save true_rip
        writer.put_push_reg(X86Register::Rdi); // save accessed_address

        let checked: bool = match width {
            1 => writer.put_bytes(self.blob_check_mem_byte()),
            2 => writer.put_bytes(self.blob_check_mem_halfword()),
            4 => writer.put_bytes(self.blob_check_mem_dword()),
            8 => writer.put_bytes(self.blob_check_mem_qword()),
            16 => writer.put_bytes(self.blob_check_mem_16bytes()),
            _ => false,
        };

        if checked {
            writer.put_jmp_address(self.current_report_impl);
            for _ in 0..10 {
                // shadow_check_blob's done will land somewhere in these nops
                // on amd64 jump can takes 10 bytes at most, so that's why I put 10 bytes.
                writer.put_nop();
            }
        }

        writer.put_pop_reg(X86Register::Rdi);
        writer.put_pop_reg(X86Register::Rsi);

        writer.put_pop_reg(X86Register::R8);
        writer.put_pop_reg(X86Register::Rbp);
        writer.put_pop_reg(X86Register::Rax);
        writer.put_pop_reg(X86Register::Rcx);
        writer.put_pop_reg(X86Register::Rdx);
        writer.put_pop_reg(X86Register::Rsi);
        writer.put_pop_reg(X86Register::Rdi);
        writer.put_popfx();
        writer.put_lea_reg_reg_offset(X86Register::Rsp, X86Register::Rsp, redzone_size);
    }

    /// Emit a shadow memory check into the instruction stream
    #[cfg(target_arch = "aarch64")]
    #[inline]
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub fn emit_shadow_check(
        &mut self,
        _address: u64,
        output: &StalkerOutput,
        basereg: u16,
        indexreg: Option<(u16, SizeCode)>,
        displacement: i32,
        width: u32,
        shift: Option<(ShiftStyle, u8)>,
    ) {
        debug_assert!(
            i32::try_from(frida_gum_sys::GUM_RED_ZONE_SIZE).is_ok(),
            "GUM_RED_ZONE_SIZE is bigger than i32::max"
        );
        #[allow(clippy::cast_possible_wrap)]
        let redzone_size = frida_gum_sys::GUM_RED_ZONE_SIZE as i32;
        let writer = output.writer();

        let basereg = writer_register(basereg, SizeCode::X, false); //the writer register can never be zr and is always 64 bit
        let indexreg = if let Some((reg, sizecode)) = indexreg {
            Some(writer_register(reg, sizecode, true)) //the index register can be zr
        } else {
            None
        };

        if self.current_report_impl == 0
            || !writer.can_branch_directly_to(self.current_report_impl)
            || !writer.can_branch_directly_between(writer.pc() + 128, self.current_report_impl)
        {
            let after_report_impl = writer.code_offset() + 2;

            #[cfg(target_arch = "aarch64")]
            writer.put_b_label(after_report_impl);

            self.current_report_impl = writer.pc();

            #[cfg(unix)]
            writer.put_bytes(self.blob_report());

            writer.put_label(after_report_impl);
        }
        //writer.put_brk_imm(1);

        // Preserve x0, x1:
        writer.put_stp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            i64::from(-(16 + redzone_size)),
            IndexMode::PreAdjust,
        );

        // Make sure the base register is copied into x0
        match basereg {
            Aarch64Register::X0 | Aarch64Register::W0 => {}
            Aarch64Register::X1 | Aarch64Register::W1 => {
                writer.put_mov_reg_reg(Aarch64Register::X0, Aarch64Register::X1);
            }
            _ => {
                if !writer.put_mov_reg_reg(Aarch64Register::X0, basereg) {
                    writer.put_mov_reg_reg(Aarch64Register::W0, basereg);
                }
            }
        }

        // Make sure the index register is copied into x1
        if indexreg.is_some() {
            if let Some(indexreg) = indexreg {
                match indexreg {
                    Aarch64Register::X0 | Aarch64Register::W0 => {
                        writer.put_ldr_reg_reg_offset(
                            Aarch64Register::X1,
                            Aarch64Register::Sp,
                            0u64,
                        );
                    }
                    Aarch64Register::X1 | Aarch64Register::W1 => {}
                    _ => {
                        if !writer.put_mov_reg_reg(Aarch64Register::X1, indexreg) {
                            writer.put_mov_reg_reg(Aarch64Register::W1, indexreg);
                        }
                    }
                }
            }

            if let Some((shift_type, amount)) = shift {
                let extender_encoding: i32 = match shift_type {
                    ShiftStyle::UXTB => 0b000,
                    ShiftStyle::UXTH => 0b001,
                    ShiftStyle::UXTW => 0b010,
                    ShiftStyle::UXTX => 0b011,
                    ShiftStyle::SXTB => 0b100,
                    ShiftStyle::SXTH => 0b101,
                    ShiftStyle::SXTW => 0b110,
                    ShiftStyle::SXTX => 0b111,
                    _ => -1,
                };
                let (shift_encoding, shift_amount): (i32, u32) = match shift_type {
                    ShiftStyle::LSL => (0b00, u32::from(amount)),
                    ShiftStyle::LSR => (0b01, u32::from(amount)),
                    ShiftStyle::ASR => (0b10, u32::from(amount)),
                    _ => (-1, 0),
                };

                if extender_encoding != -1 && shift_amount < 0b1000 {
                    // emit add extended register: https://developer.arm.com/documentation/ddi0602/latest/Base-Instructions/ADD--extended-register---Add--extended-register--
                    #[allow(clippy::cast_sign_loss)]
                    writer.put_bytes(
                        &(0x8b210000 | ((extender_encoding as u32) << 13) | (shift_amount << 10))
                            .to_le_bytes(),
                    ); //add x0, x0, w1, [shift] #[amount]
                } else if shift_encoding != -1 {
                    //https://developer.arm.com/documentation/ddi0602/2024-03/Base-Instructions/ADD--shifted-register---Add--shifted-register-- add shifted register
                    #[allow(clippy::cast_sign_loss)]
                    writer.put_bytes(
                        &(0x8b010000 | ((shift_encoding as u32) << 22) | (shift_amount << 10))
                            .to_le_bytes(),
                    ); //add x0, x0, x1, [shift] #[amount]
                } else {
                    panic!("shift_type: {shift_type:?}, shift: {shift:?}");
                }
            } else {
                writer.put_add_reg_reg_reg(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    Aarch64Register::X1,
                );
            };
        }

        let displacement = displacement
            + if basereg == Aarch64Register::Sp {
                16 + redzone_size
            } else {
                0
            };

        #[allow(clippy::comparison_chain)]
        if displacement < 0 {
            if displacement > -4096 {
                #[allow(clippy::cast_sign_loss)]
                let displacement = displacement.unsigned_abs();
                // Subtract the displacement into x0
                writer.put_sub_reg_reg_imm(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    u64::from(displacement),
                );
            } else {
                #[allow(clippy::cast_sign_loss)]
                let displacement = displacement.unsigned_abs();
                let displacement_hi = displacement / 4096;
                let displacement_lo = displacement % 4096;
                writer.put_bytes(&(0xd1400000u32 | (displacement_hi << 10)).to_le_bytes()); //sub x0, x0, #[displacement / 4096] LSL#12
                writer.put_sub_reg_reg_imm(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    u64::from(displacement_lo),
                ); //sub x0, x0, #[displacement 4096]
            }
        } else if displacement > 0 {
            #[allow(clippy::cast_sign_loss)]
            let displacement = displacement as u32;
            if displacement < 4096 {
                // Add the displacement into x0
                writer.put_add_reg_reg_imm(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    u64::from(displacement),
                );
            } else {
                let displacement_hi = displacement / 4096;
                let displacement_lo = displacement % 4096;
                writer.put_bytes(&(0x91400000u32 | (displacement_hi << 10)).to_le_bytes()); //add x0, x0, #[displacement/4096] LSL#12
                writer.put_add_reg_reg_imm(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    u64::from(displacement_lo),
                ); //add x0, x0, #[displacement % 4096]
            }
        }
        // Insert the check_shadow_mem code blob
        #[cfg(unix)]
        match width {
            1 => writer.put_bytes(self.blob_check_mem_byte()),
            2 => writer.put_bytes(self.blob_check_mem_halfword()),
            3 => writer.put_bytes(self.blob_check_mem_3bytes()),
            4 => writer.put_bytes(self.blob_check_mem_dword()),
            6 => writer.put_bytes(self.blob_check_mem_6bytes()),
            8 => writer.put_bytes(self.blob_check_mem_qword()),
            12 => writer.put_bytes(self.blob_check_mem_12bytes()),
            16 => writer.put_bytes(self.blob_check_mem_16bytes()),
            24 => writer.put_bytes(self.blob_check_mem_24bytes()),
            32 => writer.put_bytes(self.blob_check_mem_32bytes()),
            48 => writer.put_bytes(self.blob_check_mem_48bytes()),
            64 => writer.put_bytes(self.blob_check_mem_64bytes()),
            _ => false,
        };
        //Shouldn't there be some manipulation of the code_offset here?
        // Add the branch to report
        //writer.put_brk_imm(0x12);
        writer.put_branch_address(self.current_report_impl);

        match width {
            3 | 6 | 12 | 24 | 32 | 48 | 64 => {
                let msr_nvcz_x0: u32 = 0xd51b4200;
                writer.put_bytes(&msr_nvcz_x0.to_le_bytes());
            }
            _ => (),
        }

        // Restore x0, x1
        assert!(writer.put_ldp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            16 + i64::from(redzone_size),
            IndexMode::PostAdjust,
        ));
    }
}

impl Default for AsanRuntime {
    fn default() -> Self {
        Self {
            check_for_leaks_enabled: false,
            current_report_impl: 0,
            allocator: Allocator::default(),
            regs: [0; ASAN_SAVE_REGISTER_COUNT],
            blob_report: None,
            blob_check_mem_byte: None,
            blob_check_mem_halfword: None,
            blob_check_mem_dword: None,
            blob_check_mem_qword: None,
            blob_check_mem_16bytes: None,
            blob_check_mem_3bytes: None,
            blob_check_mem_6bytes: None,
            blob_check_mem_12bytes: None,
            blob_check_mem_24bytes: None,
            blob_check_mem_32bytes: None,
            blob_check_mem_48bytes: None,
            blob_check_mem_64bytes: None,
            stalked_addresses: HashMap::new(),
            module_map: None,
            suppressed_addresses: Vec::new(),
            skip_ranges: Vec::new(),
            continue_on_error: false,
            #[cfg(target_arch = "aarch64")]
            eh_frame: [0; ASAN_EH_FRAME_DWORD_COUNT],
            pc: None,
            hooks: Vec::new(),
            hooks_enabled: false,
        }
    }
}
