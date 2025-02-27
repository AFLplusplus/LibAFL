//! A simple wrapper that can be inserted into a program to turn `exit` calls to `abort`, which `LibAFL` will be able to catch.
//! If you are on `MacOS`, use the env variables `DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="path/to/target/release/libdeexit.dylib" tool`
//! On Linux, use `LD_PRELOAD="path/to/target/release/libdeexit.so" tool`.

unsafe extern "C" {
    fn abort();
}

/// Hooked `exit` function
#[unsafe(no_mangle)]
pub extern "C" fn exit(status: i32) {
    println!("DeExit: The target called exit with status code {status}");
    unsafe {
        abort();
    }
}
