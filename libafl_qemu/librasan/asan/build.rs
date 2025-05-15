fn main() {
    let single_threaded = std::env::var("CARGO_FEATURE_SINGLE_THREADED").is_ok();
    let multi_threaded = std::env::var("CARGO_FEATURE_MULTI_THREADED").is_ok();

    if single_threaded && multi_threaded {
        panic!("Features `single_threaded` and `multi_threaded` are mutually exclusive.");
    }

    if !single_threaded && !multi_threaded {
        panic!("Either `single_threaded` or `multi_threaded` feature must be enabled.");
    }

    println!("cargo:rerun-if-changed=cc/include/hooks.h");
    println!("cargo:rerun-if-changed=cc/include/trace.h");
    println!("cargo:rerun-if-changed=cc/src/asprintf.c");
    println!("cargo:rerun-if-changed=cc/src/log.c");
    println!("cargo:rerun-if-changed=cc/src/vasprintf.c");

    cc::Build::new()
        .define("_GNU_SOURCE", None)
        .opt_level(3)
        .flag("-Werror")
        .flag("-fno-stack-protector")
        .flag("-U_FORTIFY_SOURCE")
        .flag("-D_FORTIFY_SOURCE=0")
        .flag("-ffunction-sections")
        .include("cc/include/")
        .file("cc/src/asprintf.c")
        .compile("asprintf");

    cc::Build::new()
        .define("_GNU_SOURCE", None)
        .opt_level(3)
        .flag("-Werror")
        .flag("-fno-stack-protector")
        .flag("-U_FORTIFY_SOURCE")
        .flag("-D_FORTIFY_SOURCE=0")
        .flag("-ffunction-sections")
        .include("cc/include/")
        .file("cc/src/log.c")
        .compile("log");

    cc::Build::new()
        .define("_GNU_SOURCE", None)
        .opt_level(3)
        .flag("-Werror")
        .flag("-fno-stack-protector")
        .flag("-U_FORTIFY_SOURCE")
        .flag("-D_FORTIFY_SOURCE=0")
        .flag("-ffunction-sections")
        .include("cc/include/")
        .file("cc/src/vasprintf.c")
        .compile("vasprintf");
}
