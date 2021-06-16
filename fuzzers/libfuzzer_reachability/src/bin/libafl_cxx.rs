use libafl_cc::{ClangWrapper, CompilerWrapper};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        dir.pop();

        let mut cc = ClangWrapper::new("clang", "clang++");
        cc.is_cpp(true)
            .from_args(&args)
            .unwrap()
            .link_staticlib(&dir, "libfuzzer_libpng".into())
            .unwrap()
            .add_arg("-fsanitize-coverage=trace-pc-guard,trace-cmp".into())
            .unwrap();
        cc.run().unwrap();
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
