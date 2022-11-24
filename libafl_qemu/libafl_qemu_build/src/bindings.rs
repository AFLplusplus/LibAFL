use std::{fs, path::Path};

use bindgen::{BindgenError, Bindings};

use crate::qemu_bindgen_clang_args;

const WRAPPER_HEADER: &str = r#"
// OS includes
#include <qemu/osdep.h>

#if defined(TARGET_ARM)
// CPUARMState, NVIC
#include <hw/arm/armv7m.h>
// qdev_connect_clock_in
#include <hw/qdev-clock.h>
// raise_exception
#include "qemu/target/arm/internals.h"
// arm_register_el_change_hook
#include <target/arm/cpu.h>
#elif defined(TARGET_SPARC)
// qemu_get_cpu
#include <hw/core/cpu.h>
#endif

// MachineClass
#include <hw/boards.h>

// get_system_memory
#include <hw/loader.h>

// qemu_target_page_*
#include <exec/target_page.h>

// TranslationBlock, GETPC_ADJ
#include <exec/exec-all.h>

// cpu_io_recompile
#include <accel/tcg/internal.h>

// qdev_prop_set_string
#include <hw/misc/unimp.h>

// set_basic_block_hook, tcg_prologue_init
#include <tcg/tcg.h>

// qemu_* functions
#include <sysemu/runstate.h>
#include <sysemu/sysemu.h>

// AccelClass
#include <qemu/accel.h>

// tcg_allowed
#include <sysemu/tcg.h>

// tcg_cpu_init_cflags
#include <accel/tcg/tcg-accel-ops.h>

// TCGCPUOps
#include <hw/core/tcg-cpu-ops.h>

// tcg_exec_init
#include <sysemu/tcg.h>

// cpus_register_accel
#include <sysemu/cpus.h>

// cpu_exec_step_atomic
#include <exec/cpu-common.h>

// qemu_guest_random_seed_thread_part2
#include <qemu/guest-random.h>

// current_machine
#include <hw/boards.h>

// GDB stuff
// #include <qapi/qapi-types-run-state.h>

// DirtyBitmapSnapshot
#include "softmmu/physmem.c"
"#;

pub fn generate(build_dir: &Path, cpu_target: &str) -> Result<Bindings, BindgenError> {
    let wrapper_h = build_dir.join("wrapper.h");
    fs::write(&wrapper_h, WRAPPER_HEADER).expect("Unable to write wrapper.h");

    let bindings = bindgen::Builder::default()
        .derive_debug(true)
        .derive_default(true)
        .impl_debug(true)
        .generate_comments(true)
        .default_enum_style(bindgen::EnumVariation::NewType { is_bitfield: false })
        .header(wrapper_h.display().to_string())
        .clang_args(qemu_bindgen_clang_args(build_dir, cpu_target))
        .allowlist_function("cpu_can_run")
        .allowlist_function("cpu_create")
        .allowlist_function("cpu_exec_end")
        .allowlist_function("cpu_exec_start")
        .allowlist_function("cpu_exec_step_atomic")
        .allowlist_function("cpu_exec")
        .allowlist_function("cpu_exit")
        .allowlist_function("cpu_handle_guest_debug")
        .allowlist_function("cpu_io_recompile")
        .allowlist_function("cpu_loop_exit_noexc")
        .allowlist_function("cpu_reset")
        .allowlist_function("cpu_stop_current")
        .allowlist_function("cpu_work_list_empty")
        .allowlist_function("cpus_register_accel")
        .allowlist_function("hoedur_tcg_prologue_init")
        .allowlist_function("get_system_memory")
        .allowlist_function("main_loop_wait")
        .allowlist_function("memory_region_add_subregion_overlap")
        .allowlist_function("memory_region_add_subregion")
        .allowlist_function("memory_region_get_ram_ptr")
        .allowlist_function("memory_region_init_((alias)|(io)|(ram(_ptr)?))")
        .allowlist_function("memory_region_reset_dirty")
        .allowlist_function("memory_region_set_dirty")
        .allowlist_function("memory_region_set_log")
        .allowlist_function("memory_region_set_readonly")
        .allowlist_function("memory_region_snapshot_and_clear_dirty")
        .allowlist_function("object_initialize_child_internal")
        .allowlist_function("object_property_set_link")
        .allowlist_function("page_init")
        .allowlist_function("process_queued_cpu_work")
        .allowlist_function("qdev_new")
        .allowlist_function("qdev_prop_set_string")
        .allowlist_function("qemu_cond_init")
        .allowlist_function("qemu_cpu_is_self")
        .allowlist_function("qemu_get_cpu")
        .allowlist_function("qemu_get_thread_id")
        .allowlist_function("qemu_guest_random_seed_thread_part2")
        .allowlist_function("qemu_init")
        .allowlist_function("qemu_reset_requested_get")
        .allowlist_function("qemu_shutdown_requested_get")
        .allowlist_function("qemu_system_reset_request")
        .allowlist_function("qemu_system_shutdown_request")
        .allowlist_function("qemu_target_page_size")
        .allowlist_function("qemu_thread_get_self")
        .allowlist_function("register_module_init")
        .allowlist_function("runstate_set")
        .allowlist_function("set_basic_block_hook")
        .allowlist_function("set_exit_hook")
        .allowlist_function("sysbus_realize_and_unref")
        .allowlist_function("sysbus_realize")
        .allowlist_function("tb_htable_init")
        .allowlist_function("tcg_cpu_init_cflags")
        .allowlist_function("tcg_init")
        .allowlist_function("tcg_region_init")
        .allowlist_function("tcg_register_thread")
        .allowlist_function("tcg_tb_lookup")
        .allowlist_function("tlb_flush")
        .allowlist_function("type_register_static")
        .allowlist_function("vm_state_notify")
        .allowlist_type("AccelClass")
        .allowlist_type("AccelOpsClass")
        .allowlist_type("CPUClass")
        .allowlist_type("DeviceClass")
        .allowlist_type("DirtyBitmapSnapshot")
        .allowlist_type("MachineClass")
        .allowlist_type("MachineState")
        .allowlist_type("TCGCPUOps")
        .allowlist_var("CF_[A-Z_]+")
        .allowlist_var("current_machine")
        .allowlist_var("DIRTY_MEMORY_VGA")
        .allowlist_var("error_((abort)|(fatal))")
        .allowlist_var("EXCP_[A-Z_]+")
        .allowlist_var("GETPC_ADJ")
        .allowlist_var("is_exit_hook")
        .allowlist_var("NANOSECONDS_PER_SECOND")
        .allowlist_var("rom_write_hook")
        .allowlist_var("TARGET_INSN_START_WORDS")
        .allowlist_var("tcg_allowed")
        .allowlist_var("TYPE_((ACCEL)|(ACCEL_OPS)|(MACHINE)|(SYS_BUS_DEVICE))")
        .blocklist_function("main_loop_wait") // bindgen issue #1313
        .parse_callbacks(Box::new(bindgen::CargoCallbacks));

    // arch specific functions
    let bindings = if cpu_target == "i386" || cpu_target == "x86_64" {
    bindings
            .allowlist_type("CPUX86State")
            .allowlist_type("X86CPU")
    } else if cpu_target == "arm" {
        bindings
            .allowlist_function("arm_register_el_change_hook")
            .allowlist_function("armv7m_nvic_set_pending")
            .allowlist_function("clock_new")
            .allowlist_function("cpsr_read")
            .allowlist_function("nvic_(security_)?post_load")
            .allowlist_function("nvic_security_needed")
            .allowlist_function("qdev_connect_clock_in")
            .allowlist_function("qdev_prop_set_uint32")
            .allowlist_type("arm_features")
            .allowlist_type("ARMCPU")
            .allowlist_type("ARMv7MState")
            .allowlist_type("NVICState")
            .allowlist_var("nvic_abort_hook")
    } else {
        bindings
    };
    
    /*Arch::Sparc => bindings
        .allowlist_function("cpu_sparc_set_id")
        .allowlist_type("CPUSPARCState")
        .allowlist_type("SPARCCPU"),
    Arch::Mipsel => bindings
        .allowlist_type("CPUMIPSState")
        .allowlist_type("MIPSCPU"),*/

    // generate + write bindings
    bindings.generate()
}
