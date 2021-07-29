use regex::{Regex, RegexBuilder};
use std::env;
use std::fs::File;
use std::io::{stdout, Write};
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

const SYMCC_REPO_URL: &str = "https://github.com/AFLplusplus/symcc.git";
const SYMCC_REPO_COMMIT: &str = "1a1bf95ac52fa3074acfb095ca91c45cfe6c35d4";

fn checkout_symcc(out_path: &Path) -> PathBuf {
    let repo_dir = out_path.join("libafl_symcc_src");
    if repo_dir.exists() {
        repo_dir
    } else {
        let mut cmd = Command::new("git");
        cmd.arg("clone").arg(SYMCC_REPO_URL).arg(&repo_dir);
        let output = cmd.output().expect("failed to execute git clone");
        if !output.status.success() {
            println!("failed to clone symcc git repository:");
            let mut stdout = stdout();
            stdout
                .write_all(&output.stderr)
                .expect("failed to write git error message to stdout");
            exit(1)
        } else {
            let mut cmd = Command::new("git");
            cmd.arg("checkout")
                .arg(SYMCC_REPO_COMMIT)
                .current_dir(&repo_dir);
            let output = cmd.output().expect("failed to execute git checkout");
            if !output.status.success() {
                println!("failed to checkout symcc git repository commit:");
                let mut stdout = stdout();
                stdout
                    .write_all(&output.stderr)
                    .expect("failed to write git error message to stdout");
                exit(1)
            } else {
                repo_dir
            }
        }
    }
}

fn main() {
    let function_name_regex = Regex::new(r"pub fn (\w+)").unwrap();
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let symcc_src_path = checkout_symcc(&out_path);

    let exported_function_regex = RegexBuilder::new(r"(pub fn \w+\([^\)]*\)[^;]*);")
        .multi_line(true)
        .build()
        .unwrap();

    let rust_bindings = bindgen::Builder::default()
        .clang_arg(format!(
            "-I{}",
            symcc_src_path.join("runtime").to_str().unwrap()
        ))
        .clang_arg(format!(
            "-I{}",
            symcc_src_path
                .join("runtime")
                .join("rust_backend")
                .to_str()
                .unwrap()
        ))
        .clang_args(["-x", "c++", "-std=c++17"].iter())
        .header(
            symcc_src_path
                .join("runtime")
                .join("rust_backend")
                .join("RustRuntime.h")
                .to_str()
                .unwrap(),
        )
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
        .clang_arg(format!(
            "-I{}",
            symcc_src_path.join("runtime").to_str().unwrap()
        ))
        .clang_arg(format!(
            "-I{}",
            symcc_src_path
                .join("runtime")
                .join("rust_backend")
                .to_str()
                .unwrap()
        ))
        .clang_args(["-x", "c++", "-std=c++17"].iter())
        .header(
            symcc_src_path
                .join("runtime")
                .join("rust_backend")
                .join("Runtime.h")
                .to_str()
                .unwrap(),
        )
        .header(
            symcc_src_path
                .join("runtime")
                .join("LibcWrappers.cpp")
                .to_str()
                .unwrap(),
        )
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
    if std::env::var("CARGO_FEATURE_NO_CPP_RUNTIME").is_err() {
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

        let cpp_lib = cmake::Config::new(symcc_src_path.join("runtime"))
            .define("RUST_BACKEND", "ON")
            .cxxflag(format!(
                "-include \"{}\"",
                rename_header_path.to_str().unwrap()
            ))
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
}
