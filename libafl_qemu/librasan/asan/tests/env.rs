#[cfg(test)]
mod tests {
    use asan::{
        env::Env,
        file::{libc::LibcFileReader, linux::LinuxFileReader},
        symbols::dlsym::{DlSymSymbols, LookupTypeNext},
    };
    #[test]
    fn test_linux_env() {
        /* RUST_LOG=debug PROFILE=dev cargo +nightly nextest run test_linux_env --no-capture */
        env_logger::init();
        let mut std_list = std::env::vars().collect::<Vec<(String, String)>>();
        let envs = Env::<LinuxFileReader>::initialize().unwrap();
        let mut linux_list = envs
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<(String, String)>>();

        std_list.sort();
        linux_list.sort();
        assert_eq!(std_list, linux_list);
    }

    #[test]
    fn test_libc_env() {
        /* RUST_LOG=debug PROFILE=dev cargo +nightly nextest run test_libc_env --no-capture */
        env_logger::init();
        let mut std_list = std::env::vars().collect::<Vec<(String, String)>>();
        let envs = Env::<LibcFileReader<DlSymSymbols<LookupTypeNext>>>::initialize().unwrap();
        let mut linux_list = envs
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<(String, String)>>();

        std_list.sort();
        linux_list.sort();
        assert_eq!(std_list, linux_list);
    }
}
