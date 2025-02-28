#[cfg(test)]
#[cfg(feature = "host")]
mod tests {
    use asan::host::linux::LinuxHost;

    #[test]
    fn test_sysno() {
        assert_eq!(LinuxHost::sysno() as u32, 0xa2a4);
    }
}
