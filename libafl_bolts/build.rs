/// Taken from <https://internals.rust-lang.org/t/mutually-exclusive-feature-flags/8601/5>
macro_rules! assert_unique_feature {
    () => {};
    ($first:tt $(,$rest:tt)*) => {
        #[allow(unreachable_code)]
        {
            $(
                #[cfg(all(feature = $first, feature = $rest))]
                panic!(concat!("features \"", $first, "\" and \"", $rest, "\" cannot be used together"));
            )*
            assert_unique_feature!($($rest),*);
        }
    }
}

#[rustversion::nightly]
fn nightly() {
    println!("cargo:rustc-cfg=nightly");
}

#[rustversion::not(nightly)]
fn nightly() {}

fn main() {
    if std::env::var("DOCS_RS").is_err() {
        assert_unique_feature!(
            "covmap_naive",
            "covmap_wide128",
            "covmap_wide256",
            "covmap_stdsimd"
        );
        assert_unique_feature!(
            "simplify_map_naive",
            "simplify_map_wide128",
            "simplify_map_wide256"
        );
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(nightly)");
    nightly();
    #[cfg(target_env = "musl")]
    println!("cargo:rustc-link-lib=ucontext");
}
