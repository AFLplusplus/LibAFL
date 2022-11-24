use std::{fs, path::Path};

use bindgen::{BindgenError, Bindings};

const WRAPPER_HEADER: &str = r#"
#include "qemu/osdep.h"
#include "qapi/error.h"

#include "exec/target_page.h"
#include "hw/qdev-core.h"
#include "hw/qdev-properties.h"
#include "qemu/error-report.h"
#include "migration/vmstate.h"
#ifdef CONFIG_USER_ONLY
#include "qemu.h"
#else
#include "hw/core/sysemu-cpu-ops.h"
#include "exec/address-spaces.h"
#endif
#include "sysemu/tcg.h"
#include "sysemu/kvm.h"
#include "sysemu/replay.h"
#include "exec/cpu-common.h"
#include "exec/exec-all.h"
#include "exec/translate-all.h"
#include "exec/log.h"
#include "hw/core/accel-cpu.h"
#include "trace/trace-root.h"
#include "qemu/accel.h"

#include "tcg/tcg-op.h"
#include "tcg/tcg-internal.h"
#include "exec/helper-head.h"

"#;

pub fn generate(
    build_dir: &Path,
    cpu_target: &str,
    clang_args: Vec<String>,
) -> Result<Bindings, BindgenError> {
    let wrapper_h = build_dir.join("wrapper.h");
    fs::write(&wrapper_h, WRAPPER_HEADER).expect("Unable to write wrapper.h");

    let bindings = bindgen::Builder::default()
        .derive_debug(true)
        .derive_default(true)
        .impl_debug(true)
        .generate_comments(true)
        //.default_enum_style(bindgen::EnumVariation::NewType { is_bitfield: false })
        .header(wrapper_h.display().to_string())
        .clang_args(clang_args)
        .allowlist_type("CPUState")
        .allowlist_type("CPUArchState")
        .blocklist_function("main_loop_wait") // bindgen issue #1313
        .blocklist_type(".*\\(unnamed_at.*")
        .blocklist_type(".*\\(anonymous_at.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks));

    // arch specific functions
    let bindings = if cpu_target == "i386" || cpu_target == "x86_64" {
        bindings
            .allowlist_type("CPUX86State")
            .allowlist_type("X86CPU")
    } else if cpu_target == "arm" {
        bindings
            .allowlist_type("ARMCPU")
            .allowlist_type("ARMv7MState")
    } else {
        bindings
    };

    // generate + write bindings
    bindings.generate()
}
