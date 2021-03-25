use libafl_cc::{ClangWrapper, CompilerWrapper};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        dir.pop();
        ClangWrapper::new("clang", "clang++")
            .from_args(&args)
            .unwrap()
            .add_arg("-fsanitize-coverage=trace-pc-guard".into())
            .unwrap()
            .add_link_arg(dir.join("liblibfuzzer_libpng.a").display().to_string())
            .unwrap()
            .run()
            .unwrap();
    }
}
