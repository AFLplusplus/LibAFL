use libafl_build::find_llvm_config;

fn main() {
    match find_llvm_config() {
        Ok(path) => print!("{}", path),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
