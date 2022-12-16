use std::{
    fs::{read_dir, File},
    io::{stderr, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

const ARIANE_PKG: [&'static str; 13] = [
    "include/riscv_pkg.sv",
    "src/riscv-dbg/src/dm_pkg.sv",
    "include/ariane_pkg.sv",
    "include/std_cache_pkg.sv",
    "include/wt_cache_pkg.sv",
    "src/axi/src/axi_pkg.sv",
    "src/register_interface/src/reg_intf.sv",
    "src/register_interface/src/reg_intf_pkg.sv",
    "include/axi_intf.sv",
    "tb/ariane_soc_pkg.sv",
    "include/ariane_axi_pkg.sv",
    "src/fpu/src/fpnew_pkg.sv",
    "src/fpu/src/fpu_div_sqrt_mvp/hdl/defs_div_sqrt_mvp.sv",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cva6");
    println!("cargo:rerun-if-changed=ariane_tb_libafl.cpp");
    println!("cargo:rerun-if-changed=cva6-base.c");
    println!("cargo:rerun-if-changed=harness.h");
    println!("cargo:rerun-if-changed=interop.h");
    println!("cargo:rerun-if-changed=riscv-tests");

    let riscv_path = std::env::var("RISCV").expect("Path to RISCV root must be defined.");

    let mut root_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let patch_file = root_dir.join("syscalls.c.patch");
    root_dir.push("riscv-tests");

    let patch_target = root_dir.join("benchmarks/common/syscalls.c");
    // apply patch if possible
    if patch_target.metadata().unwrap().modified().unwrap()
        < patch_file.metadata().unwrap().modified().unwrap()
        || Command::new("git")
            .arg("diff")
            .arg("--exit-code")
            .arg(&patch_target)
            .current_dir(&root_dir)
            .status()
            .unwrap()
            .success()
    {
        assert!(Command::new("git")
            .arg("checkout")
            .arg(&patch_target)
            .current_dir(&root_dir)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("apply")
            .stdin(Stdio::from(File::open(patch_file).unwrap()))
            .current_dir(&root_dir)
            .status()
            .unwrap()
            .success());
    }

    root_dir.pop();
    root_dir.push("cva6");

    // code derived from the Makefile for cva6 -- this WILL need to be changed if using a different version
    let mut verilator = if let Some(root) = std::env::var_os("VERILATOR_ROOT") {
        let mut path = PathBuf::from(root);
        path.push("bin");
        path.push("verilator");

        Command::new(path)
    } else {
        Command::new("verilator")
    };

    for pkg in ARIANE_PKG {
        verilator.arg(root_dir.join(pkg));
    }
    for file in read_dir(root_dir.join("src")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv")
            && !file.path().ends_with("src/ariane_regfile.sv")
        {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("src/fpu/src")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv")
            && !file.path().ends_with("src/fpu/src/fpnew_pkg.sv")
        {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("src/fpu/src/fpu_div_sqrt_mvp/hdl")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv")
            && !file
                .path()
                .ends_with("src/fpu/src/fpu_div_sqrt_mvp/hdl/defs_div_sqrt_mvp.sv")
        {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("src/frontend")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv") {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("src/cache_subsystem")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv")
            && !file
                .path()
                .ends_with("src/cache_subsystem/std_no_dcache.sv")
        {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("bootrom")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv") {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("src/clint")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv") {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("fpga/src/axi2apb/src")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv") {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("fpga/src/axi_slice/src")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv") {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("src/axi_node/src")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv") {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("src/axi_riscv_atomics/src")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv") {
            verilator.arg(file.path());
        }
    }
    for file in read_dir(root_dir.join("src/axi_mem_if/src")).unwrap() {
        let file = file.unwrap();
        if file.file_name().to_str().unwrap().ends_with(".sv") {
            verilator.arg(file.path());
        }
    }
    for file in [
        "src/rv_plic/rtl/rv_plic_target.sv",
        "src/rv_plic/rtl/rv_plic_gateway.sv",
        "src/rv_plic/rtl/plic_regmap.sv",
        "src/rv_plic/rtl/plic_top.sv",
        "src/riscv-dbg/src/dmi_cdc.sv",
        "src/riscv-dbg/src/dmi_jtag.sv",
        "src/riscv-dbg/src/dmi_jtag_tap.sv",
        "src/riscv-dbg/src/dm_csrs.sv",
        "src/riscv-dbg/src/dm_mem.sv",
        "src/riscv-dbg/src/dm_sba.sv",
        "src/riscv-dbg/src/dm_top.sv",
        "src/riscv-dbg/debug_rom/debug_rom.sv",
        "src/register_interface/src/apb_to_reg.sv",
        "src/axi/src/axi_multicut.sv",
        "src/common_cells/src/deprecated/generic_fifo.sv",
        "src/common_cells/src/deprecated/pulp_sync.sv",
        "src/common_cells/src/deprecated/find_first_one.sv",
        "src/common_cells/src/rstgen_bypass.sv",
        "src/common_cells/src/rstgen.sv",
        "src/common_cells/src/stream_mux.sv",
        "src/common_cells/src/stream_demux.sv",
        "src/util/axi_master_connect.sv",
        "src/util/axi_slave_connect.sv",
        "src/util/axi_master_connect_rev.sv",
        "src/util/axi_slave_connect_rev.sv",
        "src/axi/src/axi_cut.sv",
        "src/axi/src/axi_join.sv",
        "src/axi/src/axi_delayer.sv",
        "src/axi/src/axi_to_axi_lite.sv",
        "src/fpga-support/rtl/SyncSpRamBeNx64.sv",
        "src/common_cells/src/unread.sv",
        "src/common_cells/src/sync.sv",
        "src/common_cells/src/cdc_2phase.sv",
        "src/common_cells/src/spill_register.sv",
        "src/common_cells/src/sync_wedge.sv",
        "src/common_cells/src/edge_detect.sv",
        "src/common_cells/src/stream_arbiter.sv",
        "src/common_cells/src/stream_arbiter_flushable.sv",
        "src/common_cells/src/deprecated/fifo_v1.sv",
        "src/common_cells/src/deprecated/fifo_v2.sv",
        "src/common_cells/src/fifo_v3.sv",
        "src/common_cells/src/lzc.sv",
        "src/common_cells/src/popcount.sv",
        "src/common_cells/src/rr_arb_tree.sv",
        "src/common_cells/src/deprecated/rrarbiter.sv",
        "src/common_cells/src/stream_delay.sv",
        "src/common_cells/src/lfsr_8bit.sv",
        "src/common_cells/src/lfsr_16bit.sv",
        "src/common_cells/src/counter.sv",
        "src/common_cells/src/shift_reg.sv",
        "src/tech_cells_generic/src/pulp_clock_gating.sv",
        "src/tech_cells_generic/src/cluster_clock_inverter.sv",
        "src/tech_cells_generic/src/pulp_clock_mux2.sv",
        "tb/ariane_testharness.sv",
        "tb/ariane_peripherals.sv",
        "tb/common/uart.sv",
        "tb/common/SimDTM.sv",
        "tb/common/SimJTAG.sv",
    ] {
        verilator.arg(root_dir.join(file));
    }
    verilator
        .arg("+define+WT_DCACHE")
        .arg(root_dir.join("src/util/sram.sv"))
        .arg("+incdir+src/axi_node")
        .args(["--threads", "72"]) // ariane requires multiple threads :(
        .args(["--unroll-count", "256"])
        .arg("-Werror-PINMISSING")
        .arg("-Werror-IMPLICIT")
        .arg("-Wno-fatal")
        .arg("-Wno-PINCONNECTEMPTY")
        .arg("-Wno-ASSIGNDLY")
        .arg("-Wno-DECLFILENAME")
        .arg("-Wno-UNUSED")
        .arg("-Wno-UNOPTFLAT")
        .arg("-Wno-ENUMVALUE")
        .arg("-Wno-style")
        .args([
            "-LDFLAGS".to_string(),
            format!("-L{riscv_path}/lib -Wl,-rpath,{riscv_path}/lib -lfesvr -lpthread"),
        ])
        .args([
            "-CFLAGS".to_string(),
            format!(
                "-I{riscv_path}/include -std=c++11 -I{}", // questasim omitted
                root_dir.join("tb/dpi").to_str().unwrap()
            ),
        ])
        .arg("-Wall")
        .arg("--cc")
        .arg("--vpi")
        .arg("--timing") // TODO verify that this is the correct option
        .arg(format!(
            "+incdir+{}/src/common_cells/include",
            root_dir.to_str().unwrap()
        ))
        .args(["--top-module", "ariane_testharness"])
        .args(["--Mdir".to_string(), std::env::var("OUT_DIR").unwrap()])
        .arg("--coverage")
        .args(["--x-assign", "0"])
        .args(["--build", "-j"]);

    let out = verilator.output().unwrap();
    if !out.status.success() {
        stderr().lock().write_all(&out.stderr).unwrap();
        panic!();
    }

    // verilator is mean and forgets to use the c++ deps, so we do so explicitly
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .include(format!("{riscv_path}/include"))
        // .flag("-std=c++11")
        .flag("-fcoroutines")
        .opt_level(3)
        .include(root_dir.join("tb/dpi"));
    if let Some(root) = std::env::var_os("VERILATOR_ROOT") {
        let mut include = PathBuf::from(root);
        include.push("include");
        build
            .include(&include)
            .file(include.join("verilated.cpp"))
            .file(include.join("verilated_vpi.cpp"))
            .file(include.join("verilated_threads.cpp"))
            .file(include.join("verilated_timing.cpp"));
        build.define("VL_THREADED", None);
        include.push("vltstd");
        build.include(&include);
    }
    build.include(std::env::var_os("OUT_DIR").unwrap());
    for file in [
        "tb/dpi/SimDTM.cc",
        "tb/dpi/SimJTAG.cc",
        "tb/dpi/remote_bitbang.cc",
        "tb/dpi/msim_helper.cc",
    ] {
        build.file(root_dir.join(file));
    }
    build.file("ariane_tb_libafl.cpp").compile("cva6");

    let mut cmd = cc::Build::new()
        .no_default_flags(true)
        .compiler(PathBuf::from(&riscv_path).join("bin/riscv64-unknown-elf-gcc"))
        .include("riscv-tests/env")
        .include("riscv-tests/benchmarks/common")
        .include(PathBuf::from(&riscv_path).join("include/riscv"))
        .define("PREALLOCATE", "1")
        .flag("-mcmodel=medany")
        .flag("-std=gnu99")
        .flag("-fno-common")
        .flag("-fno-builtin-printf")
        .flag("-fno-tree-loop-distribute-patterns")
        .flag("-nostdlib")
        .flag("-nostartfiles")
        .flag("-lm")
        .flag("-lgcc")
        .flag("-Triscv-tests/benchmarks/common/test.ld")
        .opt_level(3)
        .static_flag(true)
        .get_compiler()
        .to_command();
    cmd.arg("cva6-base.c").args([
        "riscv-tests/benchmarks/common/syscalls.c",
        "riscv-tests/benchmarks/common/crt.S",
    ]);
    cmd.arg("-o")
        .arg(PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("base-executable"));
    assert!(cmd.status().unwrap().success());

    let bindings = bindgen::builder()
        .header("harness.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .unwrap();

    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // sadly, the ariane team did not emit the lib with a lib prefix, and we cannot set the name
    // without thoroughly breaking other things
    println!(
        "cargo:rustc-link-search={}",
        std::env::var("OUT_DIR").unwrap()
    );
    println!("cargo:rustc-link-arg=-l:Variane_testharness__ALL.a",);
    println!("cargo:rustc-link-lib=cva6");
    println!("cargo:rustc-link-search={riscv_path}/lib");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{riscv_path}/lib");
    println!("cargo:rustc-link-lib=fesvr");
    println!("cargo:rustc-link-lib=dl");
}
