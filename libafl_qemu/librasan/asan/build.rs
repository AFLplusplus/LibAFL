fn compile(file: &str, output: &str) {
    cc::Build::new()
        .define("_GNU_SOURCE", None)
        .opt_level(3)
        .flag("-Werror")
        .flag("-fno-stack-protector")
        .flag("-ffunction-sections")
        .include("cc/include/")
        .file(file)
        .compile(output);
}

fn main() {
    println!("cargo:rerun-if-changed=cc");

    compile("cc/src/asprintf.c", "asprintf");
    compile("cc/src/log.c", "log");
    compile("cc/src/printf.c", "printf");
    compile("cc/src/vasprintf.c", "vasprintf");

    compile("cc/src/memcmp.c", "memcmp");
    compile("cc/src/memcpy.c", "memcpy");
    compile("cc/src/memmove.c", "memmove");
    compile("cc/src/memset.c", "memset");
    compile("cc/src/strlen.c", "strlen");
}
