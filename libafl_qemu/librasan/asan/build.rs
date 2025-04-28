fn compile(file: &str, output: &str) {
    cc::Build::new()
        .define("_GNU_SOURCE", None)
        .opt_level(3)
        .flag("-Werror")
        .flag("-fno-stack-protector")
        .flag("-ffunction-sections")
        .include("libc/include/")
        .file(file)
        .compile(output);
}

fn main() {
    println!("cargo:rerun-if-changed=libc");

    compile("libc/src/asprintf.c", "asprintf");
    compile("libc/src/log.c", "log");
    compile("libc/src/printf.c", "printf");
    compile("libc/src/vasprintf.c", "vasprintf");

    compile("libc/src/memcmp.c", "memcmp");
    compile("libc/src/memcpy.c", "memcpy");
    compile("libc/src/memmove.c", "memmove");
    compile("libc/src/memset.c", "memset");
    compile("libc/src/strlen.c", "strlen");
}
