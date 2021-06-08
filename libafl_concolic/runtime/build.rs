fn main() {
    use cmake::Config;
    let runtime_dir = "../libafl_symcc/runtime";
    let dst = Config::new(runtime_dir)
        .define("COMMON_ONLY", "YES")
        .build();
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=static=SymRuntime");
    println!("cargo:rerun-if-changed={}", runtime_dir);
}
