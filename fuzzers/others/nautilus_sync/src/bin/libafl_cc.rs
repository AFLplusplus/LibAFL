use std::{env, process::Command, str};

use libafl_cc::{ClangWrapper, CompilerWrapper, ToolWrapper};

fn find_libpython() -> Result<String, String> {
    match Command::new("python3")
        .args(["-m", "find_libpython"])
        .output()
    {
        Ok(output) => {
            let shared_obj = str::from_utf8(&output.stdout).unwrap_or_default().trim();
            if shared_obj.is_empty() {
                return Err("Empty return from python3 -m find_libpython".to_string());
            }
            Ok(shared_obj.to_owned())
        }
        Err(err) => Err(format!(
            "Could not execute python3 -m find_libpython: {err:?}"
        )),
    }
}

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

        let libpython = find_libpython().expect("Failed to find libpython");

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
            .add_link_arg(libpython)
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
