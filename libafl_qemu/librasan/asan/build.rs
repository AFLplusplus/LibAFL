use std::env;

fn compile(file: &str, output: &str) {
    cc::Build::new()
        .define("_GNU_SOURCE", None)
        .opt_level(3)
        .flag("-Werror")
        .flag("-fno-stack-protector")
        .flag("-ffunction-sections")
        .flag("-Wa,--noexecstack")
        .include("libc/include/")
        .file(file)
        .compile(output);
}

fn main() {
    println!("cargo:rerun-if-changed=libc");
    let target = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    compile("libc/src/asprintf.c", "asprintf");
    compile("libc/src/log.c", "log");
    compile("libc/src/printf.c", "printf");
    compile("libc/src/vasprintf.c", "vasprintf");

    compile("libc/src/memcmp.c", "memcmp");

    let mut memcpy = "libc/src/memcpy.c";
    let mut memmove = "libc/src/memmove.c";
    let mut memset = "libc/src/memset.c";

    if cfg!(feature = "optimized-assembly") {
        match target.as_str() {
            "aarch64" => {
                memcpy = "libc/src/aarch64/memcpy.S";
                memset = "libc/src/aarch64/memset.S";
            }
            "arm" => {
                memcpy = "libc/src/arm/memcpy.S";
            }
            "x86" => {
                memcpy = "libc/src/i386/memcpy.s";
                memmove = "libc/src/i386/memmove.s";
                memset = "libc/src/i386/memset.s";
            }
            "x86_64" => {
                memcpy = "libc/src/x86_64/memcpy.s";
                memmove = "libc/src/x86_64/memmove.s";
                memset = "libc/src/x86_64/memset.s";
            }
            _ => {}
        }
    }

    compile(memcpy, "memcpy");
    compile(memmove, "memmove");
    compile(memset, "memset");

    compile("libc/src/strlen.c", "strlen");
}
