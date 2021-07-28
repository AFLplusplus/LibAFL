use regex::{Regex, RegexBuilder};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let function_name_regex = Regex::new(r"pub fn (\w+)").unwrap();
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let exported_function_regex = RegexBuilder::new(r"(pub fn \w+\([^\)]*\)[^;]*);")
        .multi_line(true)
        .build()
        .unwrap();

    let rust_bindings = bindgen::Builder::default()
        .clang_arg("-I../libafl_symcc/runtime")
        .clang_arg("-I../libafl_symcc/runtime/rust_backend")
        .clang_args(["-x", "c++", "-std=c++17"].iter())
        .header("../libafl_symcc/runtime/rust_backend/RustRuntime.h")
        .allowlist_type("RSymExpr")
        .allowlist_function("_rsym_.*")
        .opaque_type("_.*")
        .size_t_is_usize(true)
        .generate()
        .expect("Unable to generate bindings");

    {
        let mut rust_runtime_macro = File::create(out_path.join("rust_exports_macro.rs")).unwrap();

        writeln!(
            &mut rust_runtime_macro,
            "#[doc(hidden)]
#[macro_export]
macro_rules! invoke_macro_with_rust_runtime_exports {{
    ($macro:path; $($extra_ident:path),*) => {{",
        )
        .unwrap();

        exported_function_regex
            .captures_iter(&rust_bindings.to_string())
            .for_each(|captures| {
                writeln!(
                    &mut rust_runtime_macro,
                    "    $macro!({},{}; $($extra_ident),*);",
                    &captures[1].replace("_rsym_", ""),
                    &function_name_regex.captures(&captures[1]).unwrap()[1]
                )
                .unwrap();
            });

        writeln!(
            &mut rust_runtime_macro,
            " }};
        }}",
        )
        .unwrap();
    }

    let function_name_prefix = "_cpp_";
    let cpp_bindings = bindgen::Builder::default()
        .clang_arg("-I../libafl_symcc/runtime")
        .clang_arg("-I../libafl_symcc/runtime/rust_backend")
        .clang_args(["-x", "c++", "-std=c++17"].iter())
        .header("../libafl_symcc/runtime/rust_backend/Runtime.h")
        .header("../libafl_symcc/runtime/LibcWrappers.cpp")
        .allowlist_type("SymExpr")
        .allowlist_function("(_sym_.*)|(.*_symbolized)")
        .opaque_type("_.*")
        .size_t_is_usize(true)
        .generate()
        .expect("Unable to generate bindings");

    {
        let mut bindings_file = File::create(out_path.join("bindings.rs")).unwrap();

        cpp_bindings.to_string().lines().for_each(|l| {
            if let Some(captures) = function_name_regex.captures(l) {
                let function_name = &captures[1];
                writeln!(
                    &mut bindings_file,
                    "#[link_name=\"{}{}\"]",
                    function_name_prefix, function_name
                )
                .unwrap();
            }
            writeln!(&mut bindings_file, "{}", l).unwrap()
        })
    }

    {
        let mut macro_file = File::create(out_path.join("cpp_exports_macro.rs")).unwrap();

        writeln!(
            &mut macro_file,
            "#[doc(hidden)]
#[macro_export]
macro_rules! export_cpp_runtime_functions {{
    () => {{",
        )
        .unwrap();

        exported_function_regex
            .captures_iter(&cpp_bindings.to_string())
            .for_each(|captures| {
                writeln!(
                    &mut macro_file,
                    "    symcc_runtime::export_c_symbol!({});",
                    &captures[1]
                )
                .unwrap();
            });

        writeln!(
            &mut macro_file,
            " }};
        }}",
        )
        .unwrap();
    }

    let rename_header_path = out_path.join("rename.h");
    {
        let mut rename_header_file = File::create(&rename_header_path).unwrap();
        writeln!(
            &mut rename_header_file,
            "#ifndef PREFIX_EXPORTS_H
#define PREFIX_EXPORTS_H",
        )
        .unwrap();

        cpp_bindings
            .to_string()
            .lines()
            .flat_map(|l| function_name_regex.captures(l))
            .map(|captures| captures[1].to_string())
            .for_each(|val| {
                writeln!(
                    &mut rename_header_file,
                    "#define {} {}{}",
                    &val, function_name_prefix, &val
                )
                .unwrap();
            });

        writeln!(&mut rename_header_file, "#endif").unwrap();
    }

    let cpp_lib = cmake::Config::new("../libafl_symcc/runtime")
        .define("RUST_BACKEND", "ON")
        .cxxflag(format!(
            "-include \"{}\"",
            rename_header_path.to_string_lossy()
        ))
        .very_verbose(true)
        .build()
        .join("lib");

    let target = env::var("TARGET").unwrap();
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=dylib:-as-needed=c++");
    } else if target.contains("linux") {
        println!("cargo:rustc-link-lib=dylib:-as-needed=stdc++");
    } else {
        unimplemented!();
    }

    println!("cargo:rustc-link-search=native={}", cpp_lib.display());
    println!("cargo:rustc-link-lib=static=SymRuntime");
}
