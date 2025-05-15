fn main() {
    let single_threaded = std::env::var("CARGO_FEATURE_SINGLE_THREADED").is_ok();
    let multi_threaded = std::env::var("CARGO_FEATURE_MULTI_THREADED").is_ok();

    if single_threaded && multi_threaded {
        panic!("Features `single_threaded` and `multi_threaded` are mutually exclusive.");
    }

    if !single_threaded && !multi_threaded {
        panic!("Either `single_threaded` or `multi_threaded` feature must be enabled.");
    }
}
