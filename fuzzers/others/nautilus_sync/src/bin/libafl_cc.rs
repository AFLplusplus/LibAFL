use std::{env, process::Command, str};

use libafl_cc::{ClangWrapper, CompilerWrapper, ToolWrapper};

fn find_python3_version() -> Result<String, String> {
    match Command::new("python3").arg("--version").output() {
        Ok(output) => {
            let python_version = str::from_utf8(&output.stdout).unwrap_or_default().trim();
            if python_version.is_empty() {
                return Err("Empty return from python3 --version".to_string());
            }
            let version = python_version.split("Python 3.").nth(1).ok_or_else(|| {
                format!("Could not find Python 3 in version string: {python_version}")
            })?;
            let mut version = version.split('.');
            let version = version.next().ok_or_else(|| {
                format!("Could not split python3 version string {python_version}")
            })?;
            Ok(format!("python3.{version}"))
        }
        Err(err) => Err(format!("Could not execute python3 --version: {err:?}")),
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ wrapper was called. Expected {dir:?} to end with c or cxx"),
        };

        dir.pop();

        let python3_version = find_python3_version().expect("Failed to get python version");

        let mut cc = ClangWrapper::new();
        if let Some(code) = cc
            .cpp(is_cpp)
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            .link_staticlib(&dir, "nautilus_sync")
            .add_arg("-fsanitize-coverage=trace-pc-guard")
            // needed by Nautilus
            .add_link_arg(format!("-l{python3_version}"))
            .add_link_arg("-lutil")
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
