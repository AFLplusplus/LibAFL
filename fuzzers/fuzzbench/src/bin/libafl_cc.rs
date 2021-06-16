use libafl_cc::{ClangWrapper, CompilerWrapper, LIB_EXT, LIB_PREFIX};
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

        let mut cc = if is_cpp {
            let mut cc = ClangWrapper::new("clang", "clang++");
            cc.is_cpp();
            cc
        } else {
            ClangWrapper::new("clang", "clang")
        };

        cc.from_args(&args).unwrap();
        #[cfg(target_os = "linux")]
        cc.add_link_arg("-Wl,--whole-archive".into()).unwrap();
        //#[cfg(any(target_os = "macos", target_os = "ios"))]
        //cc.add_link_arg("-all_load".into()).unwrap();
        cc.add_link_arg(
            dir.join(format!("{}fuzzbench.{}", LIB_PREFIX, LIB_EXT))
                .display()
                .to_string(),
        )
        .unwrap();
        #[cfg(target_os = "linux")]
        cc.add_link_arg("-Wl,-no-whole-archive".into()).unwrap();
        cc.add_arg("-fsanitize-coverage=trace-pc-guard,trace-cmp".into())
            .unwrap();
        // Libraries needed by libafl on Windows
        #[cfg(windows)]
        cc.add_link_arg("-lws2_32".into())
            .unwrap()
            .add_link_arg("-lBcrypt".into())
            .unwrap()
            .add_link_arg("-lAdvapi32".into())
            .unwrap();
        // silence the compiler wrapper output, needed for some configure scripts.
        cc.silence();
        cc.run().unwrap();
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
