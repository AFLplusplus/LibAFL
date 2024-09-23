use libafl_qemu_build::build_libafl_qemu;

#[macro_export]
macro_rules! assert_unique_feature {
    () => {};
    ($first:tt $(,$rest:tt)*) => {
        $(
            #[cfg(all(not(any(doc, clippy)), feature = $first, feature = $rest))]
            compile_error!(concat!("features \"", $first, "\" and \"", $rest, "\" cannot be used together"));
        )*
        assert_unique_feature!($($rest),*);
    }
}

fn main() {
    assert_unique_feature!("low_level", "breakpoint", "sync_exit");

    build_libafl_qemu();
}
