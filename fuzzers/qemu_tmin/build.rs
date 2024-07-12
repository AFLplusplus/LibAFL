use vergen::EmitBuilder;

#[macro_export]
macro_rules! assert_unique_feature {
    () => {};
    ($first:tt $(,$rest:tt)*) => {
        $(
            #[cfg(all(not(any(doc, feature = "clippy")), feature = $first, feature = $rest))]
            compile_error!(concat!("features \"", $first, "\" and \"", $rest, "\" cannot be used together"));
        )*
        assert_unique_feature!($($rest),*);
    }
}

fn main() {
    EmitBuilder::builder()
        .all_build()
        .all_cargo()
        .all_git()
        .all_rustc()
        .all_sysinfo()
        .emit()
        .unwrap();

    assert_unique_feature!("arm", "aarch64", "i386", "x86_64", "mips", "ppc");

    let cpu_target = if cfg!(feature = "x86_64") {
        "x86_64".to_string()
    } else if cfg!(feature = "arm") {
        "arm".to_string()
    } else if cfg!(feature = "aarch64") {
        "aarch64".to_string()
    } else if cfg!(feature = "i386") {
        "i386".to_string()
    } else if cfg!(feature = "mips") {
        "mips".to_string()
    } else if cfg!(feature = "ppc") {
        "ppc".to_string()
    } else {
        println!("cargo:warning=No architecture specified defaulting to x86_64...");
        println!("cargo:rustc-cfg=feature=\"x86_64\"");
        println!("cargo:rustc-cfg=feature=\"64bit\"");
        "x86_64".to_string()
    };

    println!("cargo:rustc-env=CPU_TARGET={cpu_target}");
}
