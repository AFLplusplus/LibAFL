use std::env;

fn main() {
    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();
    let mut command = cc::Build::new().get_compiler().to_command();
    command
        .args(["src/test_command.c", "-o"])
        .arg(format!("{}/test_command", &cwd))
        .arg("-fsanitize=address")
        .status()
        .unwrap();
}
