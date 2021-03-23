use libafl_cc::{ClangWrapper, CompilerWrapper};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    ClangWrapper::new("clang", "clang++")
            .from_args(&args)
            .unwrap()
            .add_arg("-fsanitize=trace-pc-guard".into())
            .unwrap()
            .run()
            .unwrap();
}
