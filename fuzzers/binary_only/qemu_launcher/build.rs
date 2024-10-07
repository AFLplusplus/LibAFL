use vergen::{BuildBuilder, CargoBuilder, Emitter, RustcBuilder, SysinfoBuilder};
use vergen_git2::Git2Builder;

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
    let build = BuildBuilder::all_build().unwrap();
    let cargo = CargoBuilder::all_cargo().unwrap();
    let git = Git2Builder::all_git().unwrap();
    let rustc = RustcBuilder::all_rustc().unwrap();
    let sysinfo = SysinfoBuilder::all_sysinfo().unwrap();

    Emitter::default()
        .add_instructions(&build)
        .unwrap()
        .add_instructions(&cargo)
        .unwrap()
        .add_instructions(&git)
        .unwrap()
        .add_instructions(&rustc)
        .unwrap()
        .add_instructions(&sysinfo)
        .unwrap()
        .emit()
        .unwrap();

    assert_unique_feature!("arm", "aarch64", "i386", "x86_64", "mips", "ppc", "hexagon");

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
    } else if cfg!(feature = "hexagon") {
        "hexagon".to_string()
    } else {
        println!("cargo:warning=No architecture specified defaulting to x86_64...");
        println!("cargo:rustc-cfg=feature=\"x86_64\"");
        println!("cargo:rustc-cfg=feature=\"64bit\"");
        "x86_64".to_string()
    };

    println!("cargo:rustc-env=CPU_TARGET={cpu_target}");
}
