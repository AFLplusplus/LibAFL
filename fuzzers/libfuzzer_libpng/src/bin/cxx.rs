use libafl_cc::{ClangWrapper, CompilerWrapper, LIB_EXT, LIB_PREFIX};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        dir.pop();
        ClangWrapper::new("clang", "clang++")
            .is_cpp()
            .from_args(&args)
            .unwrap()
            .add_arg("-fsanitize-coverage=trace-pc-guard".into())
            .unwrap()
            .add_link_arg(
                dir.join(format!("{}libfuzzer_libpng.{}", LIB_PREFIX, LIB_EXT))
                    .display()
                    .to_string(),
            )
            .unwrap()
            .run()
            .unwrap();
    }
}
