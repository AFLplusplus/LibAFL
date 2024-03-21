use std::{collections::hash_map, fs, hash::Hasher, io::Read, path::Path};

use bindgen::{BindgenError, Bindings};

const WRAPPER_HEADER: &str = r#"

// https://github.com/rust-lang/rust-bindgen/issues/2500
#define __AVX512VLFP16INTRIN_H
#define __AVX512FP16INTRIN_H

// QEMU_BUILD_BUG* cause an infinite recursion in bindgen when target is arm
#include "qemu/compiler.h"

#undef QEMU_BUILD_BUG_MSG
#undef QEMU_BUILD_BUG_ON_STRUCT
#undef QEMU_BUILD_BUG_ON
#undef QEMU_BUILD_BUG_ON_ZERO

#define QEMU_BUILD_BUG_MSG(x, msg) 
#define QEMU_BUILD_BUG_ON_STRUCT(x)
#define QEMU_BUILD_BUG_ON(x) 
#define QEMU_BUILD_BUG_ON_ZERO(x) 

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#endif

#include "qemu/osdep.h"
#include "qapi/error.h"

#include "exec/target_page.h"
#include "exec/cpu-defs.h"
#include "hw/qdev-core.h"
#include "hw/qdev-properties.h"
#include "qemu/error-report.h"

#ifdef CONFIG_USER_ONLY

#include "qemu.h"
#include "user-internals.h"
#include "strace.h"
#include "signal-common.h"
#include "loader.h"
#include "user-mmap.h"
#include "user/safe-syscall.h"
#include "qemu/selfmap.h"
#include "cpu_loop-common.h"

#else

#include "migration/vmstate.h"
#include "migration/savevm.h"
#include "hw/core/sysemu-cpu-ops.h"
#include "exec/address-spaces.h"
#include "sysemu/tcg.h"
#include "sysemu/replay.h"

#include "libafl_extras/syx-snapshot/device-save.h"
#include "libafl_extras/syx-snapshot/syx-snapshot.h"

#endif

#include "exec/cpu-common.h"
#include "exec/cpu-all.h"
#include "exec/exec-all.h"
#include "exec/translate-all.h"
#include "exec/log.h"
#include "trace/trace-root.h"
#include "qemu/accel.h"
#include "hw/core/accel-cpu.h"

#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-internal.h"
#include "exec/helper-head.h"

#include "qemu/plugin-memory.h"

#include "libafl_extras/exit.h"
#include "libafl_extras/hook.h"
#include "libafl_extras/jit.h"

"#;

pub fn generate(
    build_dir: &Path,
    cpu_target: &str,
    clang_args: Vec<String>,
) -> Result<Bindings, BindgenError> {
    let wrapper_h = build_dir.join("wrapper.h");
    let existing_wrapper_h = fs::File::open(&wrapper_h);
    let mut must_rewrite_wrapper = true;

    // Check if equivalent wrapper file already exists without relying on filesystem timestamp.
    if let Ok(mut wrapper_file) = existing_wrapper_h {
        let mut existing_wrapper_content = Vec::with_capacity(WRAPPER_HEADER.len());
        wrapper_file
            .read_to_end(existing_wrapper_content.as_mut())
            .unwrap();

        let mut existing_wrapper_hasher = hash_map::DefaultHasher::new();
        existing_wrapper_hasher.write(existing_wrapper_content.as_ref());

        let mut wrapper_h_hasher = hash_map::DefaultHasher::new();
        wrapper_h_hasher.write(WRAPPER_HEADER.as_bytes());

        // Check if wrappers are the same
        if existing_wrapper_hasher.finish() == wrapper_h_hasher.finish() {
            must_rewrite_wrapper = false;
        }
    }

    if must_rewrite_wrapper {
        fs::write(&wrapper_h, WRAPPER_HEADER).expect("Unable to write wrapper.h");
    }

    let bindings = bindgen::Builder::default()
        .derive_debug(true)
        .derive_default(true)
        .impl_debug(true)
        .generate_comments(true)
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_global: true,
            is_bitfield: true,
        })
        .header(wrapper_h.display().to_string())
        .clang_args(clang_args)
        .allowlist_type("target_ulong")
        .allowlist_type("target_long")
        .allowlist_type("CPUState")
        .allowlist_type("CPUArchState")
        .allowlist_type("RAMBlock")
        .allowlist_type("qemu_plugin_hwaddr")
        .allowlist_type("qemu_plugin_meminfo_t")
        .allowlist_type("qemu_plugin_mem_rw")
        .allowlist_type("MemOpIdx")
        .allowlist_type("MemOp")
        .allowlist_type("DeviceSnapshotKind")
        .allowlist_type("libafl_exit_reason")
        .allowlist_type("libafl_exit_reason_kind")
        .allowlist_type("libafl_exit_reason_sync_backdoor")
        .allowlist_type("libafl_exit_reason_breakpoint")
        .allowlist_type("Syx.*")
        .allowlist_function("qemu_user_init")
        .allowlist_function("target_mmap")
        .allowlist_function("target_mprotect")
        .allowlist_function("target_munmap")
        .allowlist_function("page_check_range")
        .allowlist_function("cpu_memory_rw_debug")
        .allowlist_function("cpu_physical_memory_rw")
        .allowlist_function("cpu_reset")
        .allowlist_function("cpu_synchronize_state")
        .allowlist_function("cpu_get_phys_page_attrs_debug")
        .allowlist_function("tlb_plugin_lookup")
        .allowlist_function("qemu_plugin_hwaddr_phys_addr")
        .allowlist_function("qemu_plugin_get_hwaddr")
        .allowlist_function("qemu_target_page_size")
        .allowlist_function("syx_.*")
        .allowlist_function("device_list_all")
        .allowlist_function("libafl_.*")
        .blocklist_function("main_loop_wait") // bindgen issue #1313
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    // arch specific functions
    let bindings = if cpu_target == "i386" || cpu_target == "x86_64" {
        bindings
            .allowlist_type("CPUX86State")
            .allowlist_type("X86CPU")
    } else if cpu_target == "arssssm" {
        bindings
            .allowlist_type("ARMCPU")
            .allowlist_type("ARMv7MState")
    } else {
        bindings
    };

    // generate + write bindings
    bindings.generate()
}
