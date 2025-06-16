#[cfg(all(test, feature = "host", feature = "linux", target_os = "linux"))]
mod tests {
    use libafl_asan::host::linux::LinuxHost;

    #[test]
    fn test_sysno() {
        assert_eq!(LinuxHost::sysno() as u32, 0xa2a4);
    }
}
