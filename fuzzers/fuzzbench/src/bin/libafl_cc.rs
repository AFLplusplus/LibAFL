use libafl_cc::{ClangWrapper, CompilerWrapper};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ warpper was called. Expected {:?} to end with c or cxx", dir),
        };

        dir.pop();

        let mut cc = ClangWrapper::new("clang", "clang++");

        cc.is_cpp(is_cpp)
            .silence()
            .from_args(&args)
            .unwrap()
            .link_staticlib(&dir, "fuzzbench".into())
            .unwrap()
            .add_arg("-fsanitize-coverage=trace-pc-guard,trace-cmp".into())
            .unwrap()
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence()
            .run()
            .unwrap();
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
